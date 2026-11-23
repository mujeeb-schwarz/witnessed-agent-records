"""The checker: rebuilds a run's record from the journal and the witnesses' logs,
and checks each rule of Gate.tla at runtime, per witness. It also checks an
inclusion proof against a witness's chain, and that its signed heads only grow.

Adapted from `apart-sprint-custody`, `tools/check_receipt.py` and
`custody/receipt.py` (`check_receipt`). Every fingerprint and chain link is
re-derived from the plain files. Independently supplied keys establish the
trust root; journal keys establish internal consistency only. The report
includes ok and problems, and bad inputs become problems rather than raised
exceptions. The command-line interface accepts journals and witness logs.
Witness authentication uses Ed25519 signatures. Checks are named after
Gate.tla's properties and apply per witness; inclusion proofs, append-only
signed-head checks and comparisons of witness lists are supported.

What each check name means here (Gate.tla's operator in brackets):
  journal                the record file and decision file chain, fingerprints match
  witness_log            each witness's chain links, signatures verify, no fingerprint twice
  Rule1        [Rule1]   at least one witness holds each started call's fingerprint:
                         the log of the witness whose stamp let it run holds it, with
                         that stamp
  Rule1Step    [Rule1Step] effect timestamp follows the witness entry timestamp
  Rule2        [Rule2]   per witness: every signed head the run holds matches that
                         witness's log at its size, and each extends the one before
  Check3       [Check3]  every fingerprint in every witness's log is a journal record
  RunNeedsHeldStamp [RunNeedsHeldStamp] every approval holds a valid stamp for its
                         record, received before the approval and before the effect
  RefusedNeverRuns [RefusedNeverRuns] no effect for a refused call, no record both
                         refused and run
  JournalBeforeSend [JournalBeforeSend] record timestamp precedes the witness entry timestamp
  CrashRefusesUndecided [CrashRefusesUndecided] each restart refuses exactly the
                         records undecided before it, before any newer record is decided
  StampsComplete         (two witnesses, outside Gate.tla) every second stamp is valid
                         and in its witness's log; with catch_up_done, every started
                         call holds the stamps its mode requires: both witnesses' in
                         "both" mode, the main witness's in "failover" mode
  StampsOnlyFromAsked     each stamp names a permitted witness of its journal;
                         request/channel history is unmeasured (not recorded)
  effects                version 2 schemas, unique exec_id, exact record/action binding
  DecisionHeads          every witnessed decision head (anchor) of a journal, from any
                         witness's log, matches the decision chain at its length; an
                         anchor longer than the chain, or for a chain not given, fails.
                         Lines after a needed witness's longest anchor, and
                         lines it never anchored before a restart, are unmeasured;
                         an anchor counts for a restart only if the witness signed
                         it before the restart line's wall_ns
  arguments              check_run's own arguments: a form it cannot read is a problem
The report also lists every started call still missing a stamp, and every
fingerprint that only some of the witnesses' logs hold.
Effects use the version 2 schema in wire.py, bound by record_fp and exec_id,
with exact function and argument hashes. call_id is display metadata only.
Times are time.time_ns() on one machine: these compare step-start timestamps,
not synchronization completion or drive durability. JournalBeforeSend is a
timestamp-only check: equal clock ticks or a backwards wall-clock adjustment
can fail it despite correct execution order. Scheduling delays alone cannot
reverse the record-write-before-send-before-witness-capture sequence.
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from witnessed_gate.common import (FORMAT, ZERO_HASH, canon, canon_bytes, chain_head, check_stamp, key_for, sha256_hex,
                                   verify_signature, is_hex64, is_uint, signed_message_error)
from witnessed_gate.journal import DECIDING, DECISION_KINDS, decisions_path_for, record_fingerprint
from witnessed_gate.witness import signed_from_line
from witnessed_gate.wire import EFFECT_FIELDS, args_sha256, record_action

CHECK_NAMES = ("journal", "witness_log", "Rule1", "Rule1Step", "Rule2", "Check3",
               "RunNeedsHeldStamp", "RefusedNeverRuns", "JournalBeforeSend",
               "CrashRefusesUndecided", "StampsComplete", "StampsOnlyFromAsked", "DecisionHeads", "effects", "arguments")


def _read_lines(path, bad=None, check="journal") -> Tuple[List[bytes], bool]:
    """The file's non-empty lines, and whether it is missing."""
    if path is None:
        return [], True
    try:
        p = Path(path)
        return [ln for ln in p.read_bytes().splitlines() if ln.strip()], False
    except FileNotFoundError:
        return [], True
    except (OSError, ValueError, TypeError) as exc:
        if bad is not None:
            bad(check, "%s: cannot read evidence (%s: %s)" % (path, type(exc).__name__, exc))
        return [], True


def _parse(raw: bytes) -> Optional[Dict[str, Any]]:
    try:
        x = json.loads(raw)
        # Reject NaN, infinity, lone surrogates and excessive nesting before any
        # later fingerprint computation or diagnostic JSON serialization.
        canon_bytes(x)
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        return None
    return x if isinstance(x, dict) else None


def read_witness_log(path) -> List[Dict[str, Any]]:
    return [x for x in (_parse(r) for r in _read_lines(path)[0]) if x is not None]


# ------------------------------------------------------------ proofs

def inclusion_proof_from_log(entries: List[Dict[str, Any]], fp: str) -> Optional[Dict[str, Any]]:
    """The proof the witness would give for fp, rebuilt from its log."""
    for e in entries:
        if e.get("fp") == fp:
            i = e["index"]
            return {"fp": fp, "index": i, "prev_head": e["prev_head"],
                    "later": [x["fp"] for x in entries[i + 1:]]}
    return None


def verify_inclusion(fp: str, proof: Dict[str, Any], signed_head: Dict[str, Any],
                     keys: Any) -> Optional[str]:
    """None when the proof shows fp in the chain under the signed head; else why
    not. `keys` is one public key or {witness_id: public key}."""
    malformed = signed_message_error(signed_head)
    if malformed:
        return malformed
    if not isinstance(proof, dict) or set(proof) != {"fp", "index", "prev_head", "later"}:
        return "the proof is malformed or incomplete"
    if not (is_hex64(fp) and proof["fp"] == fp and is_uint(proof["index"])
            and is_hex64(proof["prev_head"]) and isinstance(proof["later"], list)
            and all(is_hex64(f) for f in proof["later"])):
        return "the proof has a malformed fingerprint, index or hash"
    if proof["index"] == 0 and proof["prev_head"] != ZERO_HASH:
        return "the first entry must follow the zero hash"
    if not verify_signature(signed_head, key_for(signed_head, keys)):
        return "the signed head does not verify under the witness's key"
    try:
        if proof.get("fp") not in (None, fp):
            return "the proof is for another fingerprint"
        index, later = proof["index"], proof["later"]
        h = chain_head(proof["prev_head"], fp)
        for f in later:
            h = chain_head(h, f)
    except (KeyError, TypeError, ValueError, AttributeError):
        return "the proof is malformed"
    if index + 1 + len(later) != signed_head.get("size"):
        return "the proof does not reach the signed head's size"
    if h != signed_head.get("head"):
        return "the proof does not lead to the signed head"
    return None


def verify_append_only(old: Dict[str, Any], new: Dict[str, Any], fps: Iterable[str],
                       keys: Any) -> Optional[str]:
    """None when the newer signed head extends the older one by exactly fps."""
    try:
        if isinstance(fps, (str, bytes)):
            return "the consistency fingerprints are malformed"
        fps = list(fps)
    except (TypeError, ValueError):
        return "the consistency fingerprints are malformed"
    if not all(is_hex64(f) for f in fps):
        return "the consistency fingerprints are malformed"
    for x in (old, new):
        malformed = signed_message_error(x)
        if malformed:
            return malformed
    for x in (old, new):
        if not verify_signature(x, key_for(x, keys)):
            return "a signed head does not verify under the witness's key"
    if old.get("witness") != new.get("witness"):
        return "the two heads are from different witnesses"
    if not isinstance(old.get("size"), int) or not isinstance(new.get("size"), int):
        return "a signed head has no size"
    if new["size"] < old["size"]:
        return "the newer head is smaller: the list shrank"
    if old["size"] + len(fps) != new["size"]:
        return "the proof does not cover the entries between the two heads"
    h = old.get("head")
    for f in fps:
        h = chain_head(h, f)
    if h != new.get("head"):
        return "the newer head does not extend the older one: the list was rewritten"
    return None


# ------------------------------------------------------------ one journal

def _record_schema(rec):
    return (is_uint(rec.get("seq")) and is_uint(rec.get("wall_ns"))
            and is_hex64(rec.get("fp"))
            and (rec.get("prev_fp") == "" or is_hex64(rec.get("prev_fp")))
            and isinstance(rec.get("salt"), str) and bool(rec["salt"])
            and isinstance(rec.get("action_kind"), str))


def _decision_schema(d):
    if not (is_uint(d.get("seq")) and is_uint(d.get("wall_ns"))
            and is_hex64(d.get("prev")) and isinstance(d.get("kind"), str)
            and d["kind"] in DECISION_KINDS):
        return False
    kind = d["kind"]
    if kind == "open":
        pins = d.get("witnesses")
        if not (d.get("format") == FORMAT and isinstance(pins, list)
                and len(pins) <= 2 and d.get("witness_mode") in ("both", "failover")):
            return False
        for i, p in enumerate(pins):
            if not isinstance(p, dict):
                return False
            wid, key = p.get("witness_id"), p.get("pubkey")
            if not ((wid is None and key is None) or
                    (isinstance(wid, str) and bool(wid) and is_hex64(key))):
                return False
            if p.get("role", "main" if i == 0 else "backup") != ("main" if i == 0 else "backup"):
                return False
        return True
    if kind == "restart":
        todo = d.get("undecided")
        return (is_uint(d.get("records_seen")) and isinstance(todo, list)
                and all(is_hex64(fp) for fp in todo) and len(todo) == len(set(todo)))
    if not (is_hex64(d.get("record_fp")) and is_uint(d.get("record_seq"))):
        return False
    if kind == "refused":
        return isinstance(d.get("reason"), str)
    return is_uint(d.get("stamp_received_ns"))


def _check_journal(path: Path, bad, notes: List[str]) -> Dict[str, Any]:
    name = path.name
    rec_raw, missing = _read_lines(path, bad)
    if missing:
        bad("journal", "%s: the record file is missing" % name)
    records: List[Dict[str, Any]] = []
    by_fp: Dict[str, Dict[str, Any]] = {}
    prev_fp: Optional[str] = ""
    for n, raw in enumerate(rec_raw):
        rec = _parse(raw)
        if rec is None:
            bad("journal", "%s: record line %d is not a JSON object" % (name, n))
            prev_fp = None
            continue
        if not _record_schema(rec):
            bad("journal", "%s: record line %d has a malformed schema or field domain" % (name, n))
            prev_fp = None
            continue
        if rec.get("seq") != n:
            bad("journal", "%s: record line %d: its sequence number does not follow" % (name, n))
        if rec.get("prev_fp") != prev_fp:
            bad("journal", "%s: record line %d does not link to the record before it" % (name, n))
        if not isinstance(rec.get("salt"), str):
            bad("journal", "%s: record line %d has no salt" % (name, n))
        if record_fingerprint(rec) != rec.get("fp"):
            bad("journal", "%s: record line %d: its content does not match its fingerprint" % (name, n))
        prev_fp = rec.get("fp")
        if isinstance(prev_fp, str):
            if prev_fp in by_fp:
                bad("journal", "%s: record line %d repeats a fingerprint" % (name, n))
            by_fp[prev_fp] = rec
        records.append(rec)

    try:
        dpath = decisions_path_for(path)
    except ValueError as exc:  # a path with no file name has no decision file
        bad("journal", "%s: the decision file's path cannot be built (%s)" % (name or str(path), exc))
        dpath = None
    dec_raw, dmissing = _read_lines(dpath, bad)
    if dmissing:
        bad("journal", "%s: the decision file is missing" % name)
    decisions: List[Dict[str, Any]] = []
    prev: Optional[str] = ZERO_HASH
    chain: List[Optional[str]] = [ZERO_HASH]  # the chain head at each length, for every decision anchor
    restart_lines: List[int] = []
    restart_wall_ns: Dict[int, int] = {}  # each restart line's wall_ns, by its index
    for n, raw in enumerate(dec_raw):
        d = _parse(raw)
        if d is None:
            bad("journal", "%s: decision line %d is not a JSON object" % (name, n))
            prev = None
            chain.append(prev)
            continue
        if not _decision_schema(d):
            bad("journal", "%s: decision line %d has a malformed schema or field domain" % (name, n))
            prev = sha256_hex(raw)
            chain.append(prev)
            continue
        if d.get("seq") != n or d.get("prev") != prev:
            bad("journal", "%s: decision line %d does not follow the line before it" % (name, n))
        if d.get("kind") not in DECISION_KINDS:
            bad("journal", "%s: decision line %d has an unknown kind" % (name, n))
        prev = sha256_hex(raw)
        chain.append(prev)
        if d.get("kind") == "restart":
            restart_lines.append(n)
            restart_wall_ns[n] = d["wall_ns"]  # a uint: _decision_schema checked it
        decisions.append(d)
    opened = decisions[0] if decisions and decisions[0].get("kind") == "open" else None
    if opened is None:
        bad("journal", "%s: the decision file does not begin with its open line" % name)
    if any(d.get("kind") == "open" for d in decisions[1:]):
        bad("journal", "%s: the decision file has a second open line" % name)
    pin_list = [p for p in (opened or {}).get("witnesses") or [] if isinstance(p, dict)]
    ids = [p["witness_id"] for p in pin_list if p.get("witness_id") is not None]
    pin_keys = [p["pubkey"] for p in pin_list if p.get("pubkey") is not None]
    if len(ids) != len(set(ids)) or len(pin_keys) != len(set(pin_keys)):
        bad("journal", "%s: pinned witnesses share an id or a public key" % name)
    pins = {p.get("witness_id"): p.get("pubkey") for p in pin_list}
    main = pin_list[0].get("witness_id") if pin_list else None
    mode = (opened or {}).get("witness_mode") or "both"

    decision_of: Dict[str, Dict[str, Any]] = {}
    seconds: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for d in decisions:
        kind = d.get("kind")
        if kind not in DECIDING and kind != "second_stamp":
            continue
        fp = d.get("record_fp")
        rec = by_fp.get(fp)
        if rec is None:
            bad("journal", "%s: decision line %s names no record line" % (name, d.get("seq")))
            continue
        if rec.get("seq") != d.get("record_seq"):
            bad("journal", "%s: decision line %s names the wrong record number" % (name, d.get("seq")))
        if kind == "second_stamp":
            if (decision_of.get(fp) or {}).get("kind") != "approved":
                bad("journal", "%s: decision line %s holds a second stamp for record %s, which had not "
                    "run" % (name, d.get("seq"), rec.get("seq")))
            seconds[fp].append(d)
            continue
        if fp in decision_of:
            kinds = {decision_of[fp].get("kind"), kind}
            check = "RefusedNeverRuns" if kinds == {"approved", "refused"} else "journal"
            bad(check, "%s: record %s has two decisions (%s)" % (name, rec.get("seq"), ", ".join(sorted(kinds))))
            continue
        decision_of[fp] = d

    for i, d in enumerate(decisions):
        if d.get("kind") != "restart":
            continue
        seen = d.get("records_seen")
        if not isinstance(seen, int) or not 0 <= seen <= len(records):
            bad("CrashRefusesUndecided", "%s: restart line %d: records_seen is out of range" % (name, i))
            continue
        decided_before = {x.get("record_fp") for x in decisions[:i] if x.get("kind") in DECIDING}
        want = [r.get("fp") for r in records[:seen] if r.get("fp") not in decided_before]
        if sorted(d.get("undecided") or []) != sorted(want):
            bad("CrashRefusesUndecided", "%s: restart line %d lists %d undecided records, but %d were "
                "undecided" % (name, i, len(d.get("undecided") or []), len(want)))
        first_new = next((x.get("seq") for x in decisions[i + 1:] if x.get("kind") in DECIDING
                          and (by_fp.get(x.get("record_fp")) or {}).get("seq", -1) >= seen), None)
        for fp in want:
            dl = decision_of.get(fp)
            label = "%s: record %s, undecided at restart line %d," % (name, (by_fp.get(fp) or {}).get("seq"), i)
            if dl is None or dl.get("kind") != "refused" or dl.get("seq", -1) < i:
                bad("CrashRefusesUndecided", label + " is not refused after it")
            elif first_new is not None and dl.get("seq") > first_new:
                bad("CrashRefusesUndecided", label + " is refused only after a newer record was decided")

    for rec in records:
        if rec.get("fp") not in decision_of:
            notes.append("%s: record %s is undecided at the end of the journal (the gate stopped while "
                         "it waited; its next start refuses it)" % (name, rec.get("seq")))
    return {"name": name, "records": records, "by_fp": by_fp, "decisions": decisions,
            "journal_id": sha256_hex(canon_bytes(opened)) if opened else None,
            "decision_length": len(dec_raw), "decision_hash": prev,
            "decision_chain": chain, "restart_lines": restart_lines,
            "restart_wall_ns": restart_wall_ns,
            "decision_of": decision_of, "seconds": seconds, "pins": pins, "main": main,
            "mode": "one" if len(pin_list) == 1 else mode,
            "pin_list": pin_list, "pin_ids": [p.get("witness_id") for p in pin_list]}


# ------------------------------------------------------------ the witnesses' logs

def _check_witness_log(path: Path, keys: Dict[str, str], bad) -> Dict[str, Any]:
    """One witness's log: its chain, its signatures, no fingerprint twice."""
    label = "%s/%s" % (path.parent.name, path.name)
    entries: List[Dict[str, Any]] = []
    heads_at: List[Optional[str]] = [ZERO_HASH]
    wfp: Dict[str, Dict[str, Any]] = {}
    decision_heads: List[Dict[str, Any]] = []
    head: Optional[str] = ZERO_HASH
    wid: Optional[str] = None
    lines, missing = _read_lines(path, bad, "witness_log")
    for n, raw in enumerate(lines):
        e = _parse(raw)
        if e is None:
            bad("witness_log", "%s: entry %d is not a JSON object" % (label, n))
            head = None
            heads_at.append(None)
            continue
        if not (is_uint(e.get("index")) and is_hex64(e.get("fp"))
                and is_hex64(e.get("prev_head")) and is_hex64(e.get("head"))
                and is_uint(e.get("t")) and isinstance(e.get("witness"), str)
                and bool(e["witness"]) and isinstance(e.get("sig"), str)):
            bad("witness_log", "%s: entry %d has a malformed schema or field domain" % (label, n))
            head = None
            heads_at.append(None)
            continue
        if e.get("kind") not in (None, "stamp", "decision_head"):
            bad("witness_log", "%s: entry %d has an unknown kind" % (label, n))
        if wid is None:
            wid = e.get("witness")
        elif e.get("witness") != wid:
            bad("witness_log", "%s: entry %d names another witness" % (label, n))
        if e.get("index") != n:
            bad("witness_log", "%s: entry %d: its index is %r" % (label, n, e.get("index")))
        if e.get("prev_head") != head:
            bad("witness_log", "%s: entry %d does not follow the entry before it" % (label, n))
        if e.get("head") != chain_head(str(e.get("prev_head")), str(e.get("fp"))):
            bad("witness_log", "%s: entry %d: its head does not match its content" % (label, n))
        try:
            signed = signed_from_line(e)
            ok_sig = (signed_message_error(signed) is None and signed.get("fp") == e["fp"]
                      and verify_signature(signed, key_for(signed, keys)))
        except (KeyError, TypeError, ValueError):
            ok_sig = False
        if not ok_sig:
            bad("witness_log", "%s: entry %d: its signature does not verify under the witness's "
                "pinned key" % (label, n))
        if e.get("fp") in wfp or any(a.get("fp") == e.get("fp") for a in decision_heads):
            bad("witness_log", "%s: entry %d repeats a fingerprint already in the list" % (label, n))
        elif e.get("kind") == "decision_head":
            decision_heads.append(e)
        else:
            wfp[e.get("fp")] = e
        head = e.get("head")
        heads_at.append(head)
        entries.append(e)
    return {"witness": wid, "label": label, "entries": entries, "heads_at": heads_at, "wfp": wfp,
            "decision_heads": decision_heads,
            "missing": missing}


# ------------------------------------------------------------ a run

ROLES = ("main", "backup")


def _paths(value, what, bad) -> List[Any]:
    """One path, or a list of them; anything else is a reported problem."""
    if value is None:
        return []
    if isinstance(value, (str, Path)):
        return [value]
    if isinstance(value, (bytes, dict)):
        bad("arguments", "%s must be a path or a list of paths" % what)
        return []
    try:
        items = list(value)
    except TypeError:
        bad("arguments", "%s must be a path or a list of paths" % what)
        return []
    out = []
    for i, x in enumerate(items):
        if isinstance(x, (str, Path)):
            out.append(x)
        else:
            bad("arguments", "%s item %d is not a path" % (what, i))
    return out


def _required(value, bad) -> Tuple[Optional[List[Tuple[Optional[str], Optional[str]]]], bool]:
    """required_witnesses as (role, id) pairs, and whether roles were given. Ids
    alone take their role from their place: main first, then backup."""
    if value is None:
        return None, False
    try:
        items = None if isinstance(value, (str, bytes, dict)) else list(value)
    except TypeError:
        items = None
    if items is None or len(items) > 2:
        bad("arguments", "required_witnesses must list at most a main and a backup witness, as ids or "
            "(role, id) pairs")
        return None, False
    pairs, with_roles = [], True
    for i, x in enumerate(items):
        if x is None or isinstance(x, str):
            pairs.append((ROLES[i], x))
            with_roles = False
        elif (isinstance(x, (tuple, list)) and len(x) == 2 and x[0] in ROLES
              and (x[1] is None or isinstance(x[1], str))):
            pairs.append((x[0], x[1]))
        else:
            bad("arguments", "required_witnesses item %d is neither an id nor a (role, id) pair" % i)
            return None, False
    return pairs, with_roles


def _keys(value, what, bad) -> Optional[Dict[str, str]]:
    if value is None:
        return None
    if not (isinstance(value, dict) and all(isinstance(k, str) and k and is_hex64(v) for k, v in value.items())):
        bad("arguments", "%s must map each witness id to its public key in 64 lowercase hex characters" % what)
        return None
    return dict(value)


def _heads(value, bad) -> List[Any]:
    if value is None:
        return []
    try:
        if isinstance(value, (str, bytes, dict)):
            raise TypeError
        return list(value)
    except TypeError:
        bad("arguments", "signed_heads must be a list of signed heads")
        return []


def check_run(journal_paths, witness_logs=None, effects_path=None,
              witness_keys: Optional[Dict[str, str]] = None,
              signed_heads: Iterable[Dict[str, Any]] = (), catch_up_done: bool = False,
              *, trusted_keys: Optional[Dict[str, str]] = None, mode: Optional[str] = None,
              required_witnesses=None, misbehaving=None, exhausted=None) -> Dict[str, Any]:
    """Check a run: one or more journals (gates), the logs of their witnesses
    (one path, or a list with one log per witness in slot order, main first),
    an effects file, and signed heads retained independently at the end of the
    run. trusted_keys is {witness_id: public key hex}; witness_keys is its
    legacy alias. Journal pins never fill gaps in a supplied trust root. mode is
    "one", "both" or "failover"; required_witnesses is a sequence of (role, id)
    pairs (ids alone take their role from their place), None for an empty slot.
    These expected values are compared with each journal.

    Give every journal whose decisions a given witness log anchors. An anchor
    whose journal identity matches no given decision file fails DecisionHeads,
    whether it sits in a given log or is a decision head given in signed_heads;
    so when one witness log holds anchors for two journals, checking only one
    of them fails. A decision head given in signed_heads whose signature
    verifies gets the checks an anchor in a log gets, and counts neither as a
    retained terminal head nor as an anchor.

    status is "pass" only when no check fails and the evidence is complete: the
    effects file was checked, the keys, the mode and the required witnesses
    with their roles came from outside the run, every required witness's log
    was given and its tail is covered by a terminal signed head (an empty log
    by a size-0 head: the witness stamped nothing; only a head of kind "head"
    counts, never a stamp or a decision head rebuilt from the log), each
    required witness has anchored this journal's decisions up to the last line
    and, before each restart line, every line written before it (counting only
    anchors the witness signed before the restart line's wall_ns), every anchor
    from any witness matches the chain at its length, every approval has an effect when
    effects are checked, and either catch-up is done
    or no stamp is missing. Otherwise a run with no failed check is
    "pass_incomplete_evidence", and `unmeasured` names each missing input; a
    required witness's missing or empty log is incomplete evidence unless a
    decision relies on that witness's stamps, when Rule1 and Rule2 fail it. ok
    is True only for "pass". Times compare step-start timestamps, not completed
    synchronization. Never raises: a bad argument or file is a problem.
    misbehaving is the gate's CloseReport.misbehaving (the witnesses whose
    replies were unusable, which no file records); the report shows it under
    misbehaving_witnesses, with a note, and it is not a problem by itself."""
    problems: Dict[str, List[str]] = {c: [] for c in CHECK_NAMES}
    notes: List[str] = []
    notes.append("StampsOnlyFromAsked checks journal-local witness authority only; request/channel "
                 "history and failover send timing are not recorded, so the model's condition that a stamp "
                 "comes only from a witness that was asked is unmeasured.")
    time_checks = ("Wall-clock timestamp ordering only; JournalBeforeSend is a timestamp-only check. "
                   "Equal timestamps or clock adjustments can flag a failure despite correct execution order. "
                   "Completed synchronization and drive durability are not measured.")
    notes.append(time_checks)

    def bad(check: str, text: str) -> None:
        problems[check].append(text)

    journal_list = _paths(journal_paths, "journal_paths", bad)
    log_paths = _paths(witness_logs, "witness_logs", bad)
    if effects_path is not None and not isinstance(effects_path, (str, Path)):
        bad("arguments", "effects_path must be a path")
        effects_path = None
    if not isinstance(catch_up_done, bool):
        bad("arguments", "catch_up_done must be True or False")
        catch_up_done = False
    if mode is not None and mode not in ("one", "both", "failover"):
        bad("arguments", "the expected witness mode is invalid")
    trusted, alias = _keys(trusted_keys, "trusted_keys", bad), _keys(witness_keys, "witness_keys", bad)
    if trusted_keys is not None and witness_keys is not None and trusted != alias:
        bad("journal", "trusted_keys and its witness_keys alias disagree")
    supplied_keys = trusted if trusted_keys is not None else alias
    keys_source = "trusted" if supplied_keys is not None else "journal"
    required_given, with_roles = _required(required_witnesses, bad)
    heads_given = _heads(signed_heads, bad)
    misbehaved: Dict[str, Any] = {}
    if misbehaving is not None:
        if isinstance(misbehaving, dict) and all(isinstance(k, str) for k in misbehaving):
            misbehaved = {k: v for k, v in misbehaving.items()}
            if misbehaved:
                notes.append("The gate recorded unusable replies (a bad signature, another fingerprint or witness, "
                             "a replay, an error) from %s; no such reply counted as a stamp, and those fingerprints "
                             "were not asked of that witness again." % ", ".join(sorted(misbehaved)))
        else:
            bad("arguments", "misbehaving must be the gate's CloseReport.misbehaving, a mapping by witness")
    if keys_source == "journal":
        notes.append("No independently trusted keys were supplied: this checks internal consistency only.")
    named = []
    for p in journal_list:  # a journal path needs a file name
        name = Path(p).name
        if not name or name in (".", ".."):
            bad("arguments", "journal path %r has no file name" % (str(p),))
        else:
            named.append(p)
    journal_list = named
    ex_pairs, ex_given = set(), []
    if exhausted is not None:
        try:
            ex_given = [dict(x) for x in exhausted]
            ex_pairs = {(x["record_fp"], x.get("witness")) for x in ex_given}
            if not all(is_hex64(fp) for fp, _ in ex_pairs):
                raise ValueError
        except (TypeError, ValueError, KeyError):
            bad("arguments", "exhausted must be the gate's CloseReport.exhausted")
            ex_pairs, ex_given = set(), []
    if not journal_list:
        bad("journal", "no journal was given, so there is no evidence to check")
    jstates = [_check_journal(Path(p), bad, notes) for p in journal_list]
    for st in jstates:
        if mode in ("one", "both", "failover") and st["mode"] != mode:
            bad("journal", "%s: its witness mode differs from the expected mode" % st["name"])
        pins = st["pin_list"] if st["mode"] == "both" else st["pin_list"][:1]
        actual = [(p.get("role", ROLES[i] if i < 2 else None), p.get("witness_id")) for i, p in enumerate(pins)]
        st["required"] = actual
        if required_given is not None and required_given != actual:
            bad("journal", "%s: its required witness identities or roles differ from those given" % st["name"])
    all_records: Dict[str, Tuple[Dict[str, Any], Dict[str, Any]]] = {}
    for st in jstates:
        for fp, rec in st["by_fp"].items():
            if fp in all_records:
                bad("journal", "%s: record %s shares its fingerprint with another journal's record"
                    % (st["name"], rec.get("seq")))
            all_records[fp] = (st, rec)
    keys: Dict[str, str] = {}
    for st in jstates:
        for wid, k in st["pins"].items():
            if wid is None:
                continue
            if wid in keys and keys[wid] != k:
                bad("journal", "the journals pin different keys for witness %s" % wid)
            keys.setdefault(wid, k)
    if supplied_keys is not None:
        for wid, k in keys.items():
            if wid is not None and supplied_keys.get(wid) != k:
                bad("journal", "the trusted key for witness %s is missing or differs from the journal pin" % wid)
        # Journal pins never fill gaps in an independently supplied trust root.
        keys = dict(supplied_keys)
    for st in jstates:
        st["keys"] = {wid: keys[wid] for wid in st["pins"] if wid in keys}

    # The logs. A log whose entries name its witness is that witness's; an empty
    # or missing log is bound by its place in the list to the journals' fixed
    # slot at that place, so that a witness that stamped nothing still has a log.
    slot_ids: Dict[int, str] = {}
    for i in range(2):
        ids = {st["pin_list"][i].get("witness_id") for st in jstates if i < len(st["pin_list"])}
        if len(ids) == 1 and None not in ids:
            slot_ids[i] = ids.pop()
    states = [(i, _check_witness_log(Path(p), keys, bad)) for i, p in enumerate(log_paths)]
    logs: Dict[str, Dict[str, Any]] = {}
    for i, ws in states:
        if ws["witness"] is None:
            continue
        if ws["witness"] in logs:
            bad("witness_log", "two logs were given for witness %s" % ws["witness"])
            continue
        logs[ws["witness"]] = ws
    for i, ws in states:
        if ws["witness"] is not None or ws["entries"]:
            continue
        wid = slot_ids.get(i)
        if wid is None:
            notes.append("%s: the empty or missing log at place %d binds to no witness: no journal's fixed slot %d "
                         "names one" % (ws["label"], i, i))
            continue
        if wid in logs:
            bad("witness_log", "%s: the empty or missing log at place %d belongs to slot %d's witness %s, which "
                "another log already holds: give the logs in slot order, main first" % (ws["label"], i, i, wid))
            continue
        ws["witness"] = wid
        logs[wid] = ws

    def log_entry(stamp: Any, fp: str) -> Optional[Dict[str, Any]]:
        wid = stamp.get("witness") if isinstance(stamp, dict) else None
        ws = logs.get(wid) if isinstance(wid, str) else None
        return ws["wfp"].get(fp) if ws else None

    def same_as_log(stamp: Dict[str, Any], e: Dict[str, Any]) -> bool:
        return (e.get("index"), e.get("head"), e.get("sig")) == (stamp.get("index"), stamp.get("head"),
                                                                 stamp.get("sig"))

    # Rule2, per witness: each signed head the run holds matches that witness's log, and they only grow
    heads: List[Tuple[str, Any]] = []
    for st in jstates:
        for d in st["decisions"]:
            if d.get("kind") in ("approved", "second_stamp") and isinstance(d.get("stamp"), dict):
                heads.append(("%s decision line %s" % (st["name"], d.get("seq")), d["stamp"]))
    for i, h in enumerate(heads_given):
        heads.append(("signed head %d given" % i, h))
        if isinstance(h, dict) and h.get("kind") in ("stamp", "decision_head"):
            # Anyone holding the logs can rebuild a stamp or an anchor
            # from them, so only a signed head of kind "head" counts as kept outside
            # the run. The item is still checked against the log, as a checkpoint.
            notes.append("signed head %d given (witness %s) is refused as a head kept outside the run: its kind is "
                         "%r, and only a signed head of kind \"head\" counts; a stamp or a decision head can be "
                         "rebuilt from the witness's log, so it leaves that log with no kept head"
                         % (i, h.get("witness"), h.get("kind")))
    good: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    anchored = set()
    for where, h in heads:
        if not isinstance(h, dict) or signed_message_error(h) or not verify_signature(h, key_for(h, keys)):
            bad("Rule2", "%s: the signed head does not verify under the witness's pinned key" % where)
            continue
        ws = logs.get(h.get("witness"))
        size = h.get("size")
        if ws is None:
            bad("Rule2", "%s: no log was given for witness %s, which signed it" % (where, h.get("witness")))
        elif not isinstance(size, int) or size < 0:
            bad("Rule2", "%s: the signed head has no size" % where)
        elif size >= len(ws["heads_at"]):
            bad("Rule2", "%s: the witness signed a head at size %d, but its log holds %d entries: "
                "entries were removed" % (where, size, len(ws["entries"])))
        elif ws["heads_at"][size] != h.get("head"):
            bad("Rule2", "%s: the log's head at size %d differs from the head the witness signed: "
                "the log was rewritten" % (where, size))
        else:
            good[h["witness"]].append(h)
            if (where.startswith("signed head ") and h.get("kind") == "head"
                    and size == len(ws["heads_at"]) - 1):
                anchored.add(h["witness"])
    for wid, hs in good.items():
        hs.sort(key=lambda x: x["size"])
        entries = logs[wid]["entries"]
        for a, b in zip(hs, hs[1:]):
            why = verify_append_only(a, b, [e.get("fp") for e in entries[a["size"]:b["size"]]], keys)
            if why:
                bad("Rule2", "witness %s, signed heads at sizes %d and %d: %s" % (wid, a["size"], b["size"], why))

    # Check3 and JournalBeforeSend: each witness's list against the journals
    for wid, ws in logs.items():
        for fp, e in ws["wfp"].items():
            hit = all_records.get(fp)
            if hit is None:
                bad("Check3", "%s: entry %s holds a fingerprint that no journal record has"
                    % (ws["label"], e.get("index")))
                continue
            st, rec = hit
            if not (isinstance(rec.get("wall_ns"), int) and isinstance(e.get("t"), int)
                    and rec["wall_ns"] < e["t"]):
                bad("JournalBeforeSend", "%s: record %s timestamp does not precede witness %s's "
                    "entry timestamp" % (st["name"], rec.get("seq"), wid))

    # Rule1 (state form) and RunNeedsHeldStamp for every approval; the second stamps; StampsComplete
    missing_stamps: List[Dict[str, Any]] = []
    for st in jstates:
        required = st["required"]
        for fp, d in st["decision_of"].items():
            if d.get("kind") != "approved":
                continue
            rec = st["by_fp"][fp]
            label = "%s: record %s" % (st["name"], rec.get("seq"))
            why = check_stamp(d.get("stamp"), fp, st["keys"])
            approval_stamp = d.get("stamp")
            if isinstance(approval_stamp, dict) and key_for(approval_stamp, st["keys"]) is None:
                bad("StampsOnlyFromAsked", "%s: its stamp names no permitted witness of this journal" % label)
            if why:
                bad("RunNeedsHeldStamp", "%s was approved without a valid stamp: %s" % (label, why))
            recv, wrote = d.get("stamp_received_ns"), d.get("wall_ns")
            if not (isinstance(recv, int) and isinstance(wrote, int) and recv <= wrote):
                bad("RunNeedsHeldStamp", "%s: the approval timestamp precedes its stamp-received timestamp" % label)
            stamp = d.get("stamp") if isinstance(d.get("stamp"), dict) else {}
            e = log_entry(stamp, fp)
            if e is None:
                bad("Rule1", "%s was approved, but no witness's log holds its fingerprint with its stamp"
                    % label)
            elif not same_as_log(stamp, e):
                bad("Rule1", "%s: its stamp differs from the witness's log entry" % label)
            holders = {stamp.get("witness")} if why is None else set()
            for s in st["seconds"].get(fp, []):
                s_stamp = s.get("stamp") if isinstance(s.get("stamp"), dict) else {}
                s_why = check_stamp(s_stamp, fp, st["keys"])
                if key_for(s_stamp, st["keys"]) is None:
                    bad("StampsOnlyFromAsked", "%s: its second stamp names no permitted witness of this journal"
                        % label)
                s_entry = log_entry(s_stamp, fp)
                if s_why:
                    bad("StampsComplete", "%s: its second stamp is not valid: %s" % (label, s_why))
                elif s_entry is None or not same_as_log(s_stamp, s_entry):
                    bad("StampsComplete", "%s: its second stamp is not in witness %s's log"
                        % (label, s_stamp.get("witness")))
                elif s_stamp.get("witness") in holders:
                    bad("journal", "%s holds two stamps from witness %s" % (label, s_stamp.get("witness")))
                else:
                    holders.add(s_stamp.get("witness"))
            # An empty fixed slot is still required; its role names the missing
            # stamp rather than silently dropping the slot from a set of ids.
            lacking = [wid if wid is not None else role for role, wid in required
                       if wid is None or wid not in holders]
            if lacking:
                missing_stamps.append({"journal": st["name"], "record_seq": rec.get("seq"), "record_fp": fp,
                                       "call_id": rec.get("call_id"), "has": sorted(h for h in holders if h),
                                       "missing": lacking})
                counted = [w for w in lacking if (fp, w) not in ex_pairs]  # exhausted: incomplete, not a fail
                if catch_up_done and counted:
                    bad("StampsComplete", "%s ran, and after the catch-up still lacks the stamp of %s"
                        % (label, ", ".join(counted)))

    # Version 2 effects: fingerprint selects exactly one approval. call_id is
    # display metadata and cannot transfer authority between records.
    effects: List[Tuple[int, Dict[str, Any]]] = []
    used_approvals = set()
    execution_ids = set()
    if effects_path is not None:
        effect_raw, missing = _read_lines(effects_path, bad, "effects")
        if missing and any(d["kind"] == "approved" for st in jstates for d in st["decision_of"].values()):
            bad("effects", "the effects file is missing or unreadable")
        for n, raw in enumerate(effect_raw):
            x = _parse(raw)
            if x is None:
                bad("effects", "effects line %d is not a canonicalizable JSON object" % n)
                continue
            effects.append((n, x))
            eid = x.get("exec_id")
            if not (set(x) == set(EFFECT_FIELDS) and isinstance(x.get("call_id"), str)
                    and isinstance(eid, str) and len(eid) == 32
                    and all(c in "0123456789abcdef" for c in eid)
                    and isinstance(x.get("function"), str) and is_hex64(x.get("args_sha256"))
                    and is_uint(x.get("wall_ns"))):
                bad("effects", "effects line %d has a malformed version 2 schema or field domain" % n)
                fp = x.get("record_fp")
                if fp is None:
                    bad("Rule1", "effects line %d has no record_fp: it did not pass the gate" % n)
                elif is_hex64(fp) and fp in all_records:
                    st, _ = all_records[fp]
                    if (st["decision_of"].get(fp) or {}).get("kind") == "refused":
                        bad("RefusedNeverRuns", "effects line %d ran the exact record the gate refused" % n)
                continue
            if eid in execution_ids:
                bad("effects", "effects line %d repeats an exec_id" % n)
            execution_ids.add(eid)
            fp = x.get("record_fp")
            if not is_hex64(fp):
                bad("effects", "effects line %d has no valid record_fp" % n)
                bad("Rule1", "effects line %d has no bound journal record: it did not pass the gate" % n)
                continue
            hit = all_records.get(fp)
            if hit is None:
                bad("Rule1", "effects line %d has no journal record: it did not pass the gate" % n)
                continue
            st, rec = hit
            d = st["decision_of"].get(fp)
            if d is None:
                bad("Rule1", "effects line %d ran a call the gate never decided" % n)
                continue
            if d["kind"] == "refused":
                bad("RefusedNeverRuns", "effects line %d ran the exact record the gate refused" % n)
                continue
            if fp in used_approvals:
                bad("Rule1", "effects line %d is a second effect for one approval" % n)
            used_approvals.add(fp)
            function, arguments = record_action(rec)
            if x["function"] != function or x["args_sha256"] != args_sha256(arguments):
                bad("effects", "effects line %d function or args_sha256 differs from its approved record" % n)
            if d["wall_ns"] > x["wall_ns"]:
                bad("RunNeedsHeldStamp", "effects line %d timestamp precedes its approval timestamp" % n)
            e = log_entry(d.get("stamp"), fp)
            if e is None:
                bad("Rule1", "effects line %d: no witness's log holds its fingerprint" % n)
            elif not e["t"] < x["wall_ns"]:
                bad("Rule1Step", "effects line %d timestamp does not follow its witness entry timestamp" % n)
            if d["stamp_received_ns"] > x["wall_ns"]:
                bad("RunNeedsHeldStamp", "effects line %d timestamp precedes the stamp-received timestamp" % n)
    approvals_without_effect = []
    if effects_path is not None:
        for st in jstates:
            for fp, d in st["decision_of"].items():
                if d["kind"] == "approved" and fp not in used_approvals:
                    approvals_without_effect.append(fp)
                    notes.append("%s: record %s was approved, and no effects line shows it ran"
                                 % (st["name"], st["by_fp"][fp]["seq"]))

    # the witnesses' lists compared: every fingerprint that only some of them hold
    only_some: List[Dict[str, Any]] = []
    if len(logs) > 1:
        held: Dict[str, List[str]] = defaultdict(list)
        for wid, ws in logs.items():
            for fp in ws["wfp"]:
                held[fp].append(wid)
        for fp, wids in held.items():
            if len(wids) < len(logs):
                hit = all_records.get(fp)
                only_some.append({"fp": fp, "held_by": sorted(wids),
                                  "missing_from": sorted(set(logs) - set(wids)),
                                  "journal": hit[0]["name"] if hit else None,
                                  "record_seq": hit[1].get("seq") if hit else None})

    # Evidence: the required witnesses, and every pinned witness a decision relies on
    pinned_role: Dict[str, str] = {}
    for st in jstates:
        for i, p in enumerate(st["pin_list"][:2]):
            if p.get("witness_id") is not None:
                pinned_role.setdefault(p["witness_id"], ROLES[i])
    needed: List[Tuple[Optional[str], Optional[str]]] = []
    for st in jstates:
        for pair in st["required"]:
            if pair not in needed:
                needed.append(pair)
    for st in jstates:
        for d in st["decisions"]:
            w = d.get("stamp").get("witness") if (d.get("kind") in ("approved", "second_stamp")
                                                   and isinstance(d.get("stamp"), dict)) else None
            if isinstance(w, str) and w in pinned_role and all(w != wid for _, wid in needed):
                needed.append((pinned_role[w], w))
    missing_logs: List[Dict[str, Any]] = []
    unanchored: List[str] = []
    for role, wid in needed:
        ws = logs.get(wid) if wid is not None else None
        if wid is None:
            why = "the %s slot has no pinned witness" % role
        elif ws is None:
            why = "no log was given for this witness"
        elif ws["missing"]:
            why = "its log file is missing"
        elif not ws["entries"] and wid not in anchored:
            why = "its log is empty, and no size-0 terminal head shows that it stamped nothing"
        else:
            why = None
            if wid not in anchored:
                unanchored.append(wid)
        if why is not None:
            missing_logs.append({"role": role, "witness": wid, "why": why})
    unmeasured: List[Dict[str, Any]] = []
    if approvals_without_effect:
        unmeasured.append({"input": "approvals without effect",
                           "reason": "the effects checked do not account for every approval",
                           "fingerprints": sorted(approvals_without_effect)})
    # DecisionHeads: an anchor in a given log for a chain that was not
    # given fails: a rewritten opening line changes the journal identity, which
    # would otherwise leave every anchor unmatched and the run merely incomplete.
    # A decision head given in signed_heads whose signature
    # verifies under the witness's key gets the same checks as one in a log. It
    # is still no retained terminal head and never counts as anchoring: only an
    # entry in a given log does. Each anchor: (witness, anchor, where, source, in a log).
    anchors = [(wid, e, "log entry %s" % e.get("index"), "%s: entry %s" % (ws["label"], e.get("index")), True)
               for wid, ws in logs.items() for e in ws["decision_heads"]]
    for i, h in enumerate(heads_given):
        if (isinstance(h, dict) and h.get("kind") == "decision_head" and signed_message_error(h) is None
                and verify_signature(h, key_for(h, keys))):
            anchors.append((h.get("witness"), h, "signed head %d given" % i, "signed head %d given" % i, False))
    given_ids = {st["journal_id"] for st in jstates if st["journal_id"] is not None}
    for wid, e, _, source, in_log in anchors:
        if e.get("journal") not in given_ids:
            bad("DecisionHeads", "%s: witness %s anchored a decision chain that was not given "
                "(journal %s, length %s); give every journal whose decisions a given %s anchors"
                % (source, wid, str(e.get("journal"))[:16], e.get("length"), "log" if in_log else "signed head"))
    for st in jstates:
        # Every anchor of this journal, from every witness's log, required or not,
        # must match the decision chain at its own length; so must every
        # authenticated decision head given in signed_heads.
        chain, length = st["decision_chain"], st["decision_length"]
        matched: Dict[str, List[Tuple[int, int]]] = defaultdict(list)  # (length, signed t) per witness
        for wid, e, where, _, in_log in anchors:
            if st["journal_id"] is None or e.get("journal") != st["journal_id"]:
                continue
            tag = "" if in_log else " (%s)" % where
            n = e.get("length")
            if not is_uint(n) or n == 0:
                bad("DecisionHeads", "%s: witness %s's decision head at %s has no valid length"
                    % (st["name"], wid, where))
            elif n > length:
                bad("DecisionHeads", "%s: witness %s anchored the decision chain at length %d, but the decision "
                    "file holds %d lines: lines were removed%s" % (st["name"], wid, n, length, tag))
            elif chain[n] != e.get("decision_hash"):
                bad("DecisionHeads", "%s: witness %s's decision head at length %d differs from the decision "
                    "chain at that length: the decision file was rewritten%s" % (st["name"], wid, n, tag))
            elif in_log:
                matched[wid].append((n, e["t"]))  # t is a uint: the log's schema check holds it
        anchor_witnesses = list(st["required"])
        # A failover backup that supplied an approval also contributes evidence.
        for d in st["decisions"]:
            stamp = d.get("stamp")
            wid = stamp.get("witness") if isinstance(stamp, dict) else None
            if isinstance(wid, str) and wid in st["pins"] and all(wid != w for _, w in anchor_witnesses):
                anchor_witnesses.append((pinned_role.get(wid), wid))
        for role, wid in anchor_witnesses:
            wid_anchors = matched.get(wid, []) if wid is not None else []
            lengths = [n for n, _ in wid_anchors]
            gap = {"input": "decision heads", "journal": st["name"], "witness": wid}
            if not lengths:
                unmeasured.append(dict(gap, count=length, reason="no witnessed decision head from the %s witness "
                                       "matches this journal's decision chain" % role))
            elif max(lengths) < length:  # the lines after its longest anchor
                longest = max(lengths)
                unmeasured.append(dict(gap, lines=[longest, length - 1], count=length - longest,
                                       reason="%d decision line(s) after the %s witness's longest decision head "
                                       "(length %d) are not anchored" % (length - longest, role, longest)))
            for r in st["restart_lines"]:  # lines never anchored before a restart
                # An anchor counts for this restart only if the witness signed it
                # before the restart line's wall_ns. Anchor requests carry no authentication,
                # so an anchor of these lines made at or after the restart shows nothing about
                # them before it; it still counts for the lines after the longest anchor.
                wall = st["restart_wall_ns"][r]
                a = max([n for n, t in wid_anchors if n <= r and t < wall], default=0)
                if a < r:
                    unmeasured.append(dict(gap, restart_line=r, lines=[a, r - 1], count=r - a,
                                           reason="decision lines %d to %d were written before the restart at line "
                                           "%d, and the %s witness anchored none of them before it: a rewrite while "
                                           "the gate was down would go unseen" % (a, r - 1, r, role)))
    if effects_path is None:
        unmeasured.append({"input": "effects", "reason": "no effects file was given, so no effect was checked "
                           "against the approvals"})
    if keys_source != "trusted":
        unmeasured.append({"input": "trusted_keys", "reason": "no keys kept outside the run were given; the "
                           "journal's own pins were used"})
    if mode is None:
        unmeasured.append({"input": "mode", "reason": "no expected witness mode was given; the journal's own "
                           "was used"})
    if required_given is None:
        unmeasured.append({"input": "required_witnesses", "reason": "no expected witnesses with roles were "
                           "given; the journal's own slots were used"})
    elif not with_roles:
        unmeasured.append({"input": "required_witnesses", "reason": "the expected witnesses were given as ids, "
                           "without their roles"})
    if missing_stamps and not catch_up_done:
        unmeasured.append({"input": "catch_up_done", "reason": "%d started call(s) lack a required stamp, and the "
                           "catch-up was not declared done" % len(missing_stamps)})
    if missing_logs:
        unmeasured.append({"input": "witness_logs", "reason": "a required witness's log is missing or empty",
                           "witnesses": [m["witness"] or m["role"] for m in missing_logs]})
    if unanchored:
        unmeasured.append({"input": "signed_heads", "reason": "no terminal signed head kept outside the run "
                           "covers the tail of these logs, so a removed tail could go unseen",
                           "witnesses": unanchored})

    if not needed:  # no configured or required witness means the evidence is incomplete
        unmeasured.append({"input": "no witnesses", "reason": "no witness is configured or required, so no stamp "
                           "could be checked"})
    if ex_given:
        unmeasured.append({"input": "exhausted", "reason": "the gate stopped asking a witness for these "
                           "fingerprints after its attempts ran out or its answers were unusable",
                           "fingerprints": sorted({x["record_fp"] for x in ex_given})})
    flat = ["%s: %s" % (c, p) for c in CHECK_NAMES for p in problems[c]]
    evidence_complete = not unmeasured and not flat
    if not evidence_complete:
        notes.append("Evidence is incomplete: unmeasured %s. Every required witness needs a valid log and an "
                     "independently retained terminal signed head at its tail; an unanchored removed tail can "
                     "remain undetected." % (", ".join(u["input"] for u in unmeasured) or "nothing beyond the "
                                             "failed checks"))
    status = "fail" if flat else "pass" if evidence_complete else "pass_incomplete_evidence"
    kinds: Dict[str, int] = defaultdict(int)
    for st in jstates:
        for d in st["decisions"]:
            kinds[d.get("kind")] += 1
    return {"ok": status == "pass", "problems": flat, "by_check": problems, "notes": notes,
            "keys_source": keys_source,
            "evidence_complete": evidence_complete, "status": status, "unmeasured": unmeasured,
            "missing_required_logs": missing_logs, "misbehaving_witnesses": misbehaved,
            "exhausted_fingerprints": ex_given,
            "time_checks": time_checks,
            "calls_missing_stamps": missing_stamps, "only_one_witness_holds": only_some,
            "counts": {"records": sum(len(st["records"]) for st in jstates),
                       "decisions": dict(kinds),
                       "witness_entries": {wid: len(ws["entries"]) for wid, ws in logs.items()},
                       "effects_lines": len(effects), "witness_keys": keys,
                       "witness_modes": sorted({st["mode"] for st in jstates})}}


class _Parser(argparse.ArgumentParser):
    """A usage error exits with 3, apart from the verdicts' 0, 1 and 2."""

    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("%s: error: %s\n" % (self.prog, message))
        sys.exit(3)


def main(argv=None) -> int:
    """Exit 0 on "pass", 2 on a pass with incomplete evidence, 1 on a fail and 3
    on a usage error."""
    p = _Parser(description="Check a witnessed-gate run against Gate.tla's rules.")
    p.add_argument("journal", nargs="+", help="record file(s); each decision file sits beside its record file. "
                   "Give every journal whose decisions a given witness log anchors: an anchor naming a journal "
                   "that was not given fails DecisionHeads, so a log shared by two journals needs both")
    p.add_argument("--witness-log", action="append", default=[],
                   help="a witness's log; repeat for each witness, main first")
    p.add_argument("--effects")
    p.add_argument("--key", action="append", default=[], metavar="WITNESS_ID=HEX",
                   help="a witness's public key, kept outside the run (trusted_keys)")
    p.add_argument("--signed-heads", metavar="FILE", help="terminal signed heads kept outside the run, JSON lines")
    p.add_argument("--mode", choices=("one", "both", "failover"), help="the expected witness mode")
    p.add_argument("--required-witness", action="append", default=[], metavar="ROLE=ID",
                   help="an expected required witness, main or backup; repeat, main first")
    p.add_argument("--catch-up-done", action="store_true",
                   help="the catch-up has run: a started call missing a required stamp fails")
    args = p.parse_args(argv)
    keys: Dict[str, str] = {}
    for item in args.key:
        wid, sep, hexkey = item.partition("=")
        if not sep or not wid:
            p.error("--key takes WITNESS_ID=HEX, not %r" % item)
        keys[wid] = hexkey
    required = None
    if args.required_witness:
        required = []
        for item in args.required_witness:
            role, sep, wid = item.partition("=")
            if not sep or role not in ROLES:
                p.error("--required-witness takes main=ID or backup=ID, not %r" % item)
            required.append((role, wid or None))
    heads: List[Any] = []
    if args.signed_heads:
        lines, missing = _read_lines(args.signed_heads)
        if missing:
            p.error("--signed-heads: %s cannot be read" % args.signed_heads)
        for n, raw in enumerate(lines):
            h = _parse(raw)
            if h is None:
                p.error("--signed-heads: line %d is not a JSON object" % n)
            heads.append(h)
    report = check_run(args.journal, args.witness_log, args.effects, signed_heads=heads,
                       catch_up_done=args.catch_up_done, trusted_keys=keys or None, mode=args.mode,
                       required_witnesses=required)
    print(canon(report))
    return {"pass": 0, "fail": 1}.get(report["status"], 2)


if __name__ == "__main__":
    sys.exit(main())
