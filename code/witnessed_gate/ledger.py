"""A ledger adapter on the witnessed gate for a courier that writes before
delivery and reads records to build a receipt.

Adapted from `apart-sprint-custody`, `custody/journal.py` (`Ledger`), with
the record-first courier interface from `custody/gate.py` (`GateCourier`)
and the record shape from `custody/core.py` (`Record`). The interface is:

  write(record)       runs the gate's steps for one record (a custody.core.Record
                      or a dict) and returns the record line as written, a dict,
                      with `receipt` holding the first valid stamp. On refusal it
                      raises `refusal_error` (pass the bench's
                      custody.core.LedgerError) with the gate's reason; if
                      storage fails before durable approval it raises GateCrashed.
                      Post-approval catch-up failure is exposed on the returned
                      WrittenRecord as .catch_up_error and .gate_decision.
                      Nothing runs without a stamp, deletions included.
  effect_line(rec)    the effects line, version 2, for one delivery of a record
                      that write() returned (witnessed_gate.wire).
  records()           every record line in the journal, in order, each with
                      `receipt` set to its first stamp (None if refused), read
                      from the journal itself, so it holds after a reopen.
  outcomes()          the gate's decision for each record: ran or refused, and
                      which witness stamped it, also from the journal.
  public_keys()       {witness id: public key}, main first, as the witness
                      processes announced them: keep it outside the run's files
                      and pass it to checker.check_run as trusted_keys.
  mode, degraded      "one", "both" or "failover", for check_run's mode; True when
                      a witness asked for did not start or has stopped.
  close()             waits up to close_grace_seconds for second stamps still due
                      and catches up a witness that missed fingerprints, closes
                      the journal, stops the witness processes, and returns the
                      gate's CloseReport (catch_up_done and signed_heads go to
                      check_run); signed_heads is also available on the ledger.

One witness by default; backup=True adds a backup witness, each its own process
with its own key, in witness_mode "both" (the default: every fingerprint to
both at once) or "failover" (the backup only after the main witness's wait).
A ledger asked for two witnesses keeps both slots even if one fails to start:
it is then degraded, and the backup never stands in as the main witness.

Files, as the bench reads them:
  run_dir/journal/<run_id>.jsonl            the record lines: the compatible record fields
                                             (seq, run_id, t, handover, labels,
                                             verdicts, decision, prev_fp, fp,
                                             receipt null) plus salt, wall_ns and
                                             action_kind. One line per record, so
                                             position-based planted edits apply
                                             unchanged.
  run_dir/journal/<run_id>.decisions.jsonl  the gate's decisions, with the stamps
  run_dir/journal/<run_id>.jsonl.lock       the record file's owner lock
  run_dir/journal/<run_id>.decisions.jsonl.lock  the decision file's owner lock
  run_dir/witness/<run_id>/log.jsonl        the main witness's log: a folder of
                                             its own per ledger, unless witness_dir
                                             is given (a folder has one owner at a
                                             time)
  run_dir/witness_backup/<run_id>/log.jsonl the backup's log, when there is one
The action's kind is its handover's "action" ("send", "delete", "close").
"""
import copy
import dataclasses
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from witnessed_gate import wire
from witnessed_gate.gate import CloseReport, Decision, Gate, GateRefused, WitnessClient, WitnessGone

BENCH_ROUTES = ["every handover the courier writes through this ledger before it delivers"]


class WrittenRecord(dict):
    """The journal record and receipt, with framework metadata as attributes.

    Metadata stays outside the mapping so record_fingerprint() and the bench's
    record format remain unchanged. The fingerprint itself is the ledger's
    unique call identity; no supplied field can choose it.
    """

    def __init__(self, decision: Decision):
        super().__init__(decision.record)
        self["receipt"] = decision.stamp
        self.gate_decision = decision

    @property
    def call_id(self) -> str:
        return self.gate_decision.fp

    @property
    def catch_up_error(self) -> Optional[str]:
        return self.gate_decision.catch_up_error


class BenchLedger:
    def __init__(self, run_dir, run_id: str, wait_seconds: float = 2.0,
                 witness_faults: Optional[Dict[str, Any]] = None, refusal_error: type = GateRefused,
                 witness_dir=None, start_witness: bool = True,
                 operator: str = "the bench's runner; each witness is a separate process on the same machine",
                 close_grace_seconds: float = 0.0, full_fsync: bool = False, backup: bool = False,
                 backup_witness_dir=None, backup_faults: Optional[Dict[str, Any]] = None,
                 witness_mode: Optional[str] = None, backup_wait_seconds: Optional[float] = None):
        run_dir = Path(run_dir)
        self.run_id = run_id
        self.journal_path = run_dir / "journal" / ("%s.jsonl" % run_id)
        self.witness_dir = Path(witness_dir) if witness_dir else run_dir / "witness" / run_id
        self.witness_log_path = self.witness_dir / "log.jsonl"
        backup = backup or backup_witness_dir is not None
        self.backup_dir = ((Path(backup_witness_dir) if backup_witness_dir else run_dir / "witness_backup" / run_id)
                           if backup else None)
        self.refusal_error = refusal_error
        self.close_grace_seconds = close_grace_seconds
        self.full_fsync = full_fsync
        self.signed_heads: List[Dict[str, Any]] = []
        self.start_errors: Dict[str, str] = {}
        self.witness = self._launch("main", self.witness_dir, witness_faults) if start_witness else None
        self.backup = self._launch("backup", self.backup_dir, backup_faults) if (start_witness and backup) else None
        slots = ([self.witness] + ([self.backup] if backup else [])) if start_witness else []
        try:
            self.gate = Gate(self.journal_path, witnesses=slots, wait_seconds=wait_seconds,
                             operator=operator, routes=BENCH_ROUTES, full_fsync=full_fsync,
                             witness_mode=witness_mode, backup_wait_seconds=backup_wait_seconds)
        except BaseException:
            self._stop_witnesses()
            raise
        self.decisions_path = self.gate.journal.decisions_path

    def _launch(self, name: str, state_dir: Path, faults: Optional[Dict[str, Any]]) -> Optional[WitnessClient]:
        try:
            return WitnessClient.launch(state_dir, faults=faults, full_fsync=self.full_fsync)
        except (WitnessGone, OSError) as exc:  # a witness that cannot start is a witness that is down
            self.start_errors[name] = str(exc)
            return None

    @property
    def witness_pubkey(self) -> Optional[str]:
        return self.gate.pubkey

    @property
    def witness_keys(self) -> Dict[str, str]:
        """The keys the journal pins (for reading; for checking, use public_keys())."""
        return dict(self.gate.keys)

    def public_keys(self) -> Dict[str, str]:
        """{witness id: public key hex}, main first, from the witness processes'
        own hello lines, not from the journal: the trust root to keep outside
        the run's files and give checker.check_run as trusted_keys. A witness
        that did not start is missing from it."""
        return {c.witness_id: c.pubkey for c in (self.witness, self.backup) if c is not None}

    @property
    def mode(self) -> str:
        """"one" with one witness slot, else the gate's mode ("both" or "failover")."""
        return "one" if len(self.gate.pins) <= 1 else self.gate.mode

    @property
    def degraded(self) -> bool:
        """True when a witness asked for did not start, has stopped, or has no
        pinned key. Read it during the run, or after close(): from close() on
        it keeps the value it had when close() began, before the witnesses were
        stopped."""
        frozen = getattr(self, "_degraded_at_close", None)
        if frozen is not None:
            return frozen
        return bool(self.start_errors) or self.gate.degraded

    def required_witnesses(self) -> List[Tuple[str, Optional[str]]]:
        """(role, id) of each witness whose stamp every record that ran must end
        with, from this ledger's configuration and its witness processes' hello
        lines, never from the journal: checker.check_run's required_witnesses.
        A witness that did not start has id None."""
        if not self.gate.pins:
            return []
        main = ("main", self.witness.witness_id if self.witness is not None else None)
        if self.backup_dir is None or self.mode == "failover":
            return [main]
        return [main, ("backup", self.backup.witness_id if self.backup is not None else None)]

    @property
    def witness_logs(self) -> List[Path]:
        """Every witness's log, main first: the list checker.check_run takes."""
        return [self.witness_log_path] + ([self.backup_dir / "log.jsonl"] if self.backup_dir else [])

    def write(self, record: Any) -> Dict[str, Any]:
        rec = dataclasses.asdict(record) if dataclasses.is_dataclass(record) else dict(record)
        content = {k: v for k, v in rec.items() if k not in ("seq", "prev_fp", "fp", "receipt")}
        handover = rec.get("handover")
        kind = handover.get("action") if isinstance(handover, dict) and handover.get("action") else "call"
        d = self.gate.decide(content, kind=kind)  # GateCrashed reaches the caller
        if not d.approved:
            raise self.refusal_error("the witnessed gate refused the record: %s" % d.reason)
        filled = WrittenRecord(d)
        self.gate.approved_calls.add(dict(filled, call_id=filled.call_id))
        return filled

    def effect_line(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """The effects line for one delivery of a record write() returned:
        bound to it by its fingerprint, with a new execution id."""
        function, arguments = wire.record_action(record)
        return wire.effect_for_call(function, arguments, self.gate.approved_calls,
                                    execution_id=record.call_id if isinstance(record, WrittenRecord) else record.get("call_id"))

    def _history(self):
        records, decisions = self.gate.history()
        decided = {d["record_fp"]: d for d in decisions if d.get("kind") in ("approved", "refused")}
        return records, decided

    def records(self) -> List[Dict[str, Any]]:
        records, decided = self._history()
        out = []
        for r in records:
            d = decided.get(r["fp"])
            r["receipt"] = d.get("stamp") if d is not None and d["kind"] == "approved" else None
            out.append(r)
        return out

    def outcomes(self) -> List[Dict[str, Any]]:
        """One entry per record line: outcome "ran", "refused", or None while
        undecided (a crashed gate's last call, until a new gate refuses it)."""
        records, decided = self._history()
        out = []
        for r in records:
            d = decided.get(r["fp"])
            ran = d is not None and d["kind"] == "approved"
            witness = (d.get("stamp") or {}).get("witness") if ran else None
            if ran:
                reason = "stamped by the %s witness" % ("main" if witness == self.gate.main_id else "backup")
            else:
                reason = d.get("reason") if d is not None else None
            out.append({"seq": r["seq"], "fp": r["fp"], "kind": r.get("action_kind"),
                        "outcome": None if d is None else ("ran" if ran else "refused"),
                        "witness": witness, "reason": reason})
        return out

    def _stop_witnesses(self) -> None:
        for client in (self.witness, self.backup):
            if client is not None:
                client.stop()

    def close(self) -> CloseReport:
        if getattr(self, "_degraded_at_close", None) is None:
            self._degraded_at_close = bool(self.start_errors) or self.gate.degraded
        try:
            report = self.gate.close(self.close_grace_seconds)
            self.signed_heads = copy.deepcopy(report.signed_heads)
            return report
        finally:
            self._stop_witnesses()


def make_ledger(run_dir, run_id: str, choices: Any = None, **options: Any) -> BenchLedger:
    """Construct a ledger with make_ledger(run_dir, run_id, choices).
    choices is unused; settings come as keyword options."""
    return BenchLedger(run_dir, run_id, **options)
