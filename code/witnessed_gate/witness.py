"""The witness, run as its own process. The gate starts it through subprocess
and talks to it in JSON lines over stdin and stdout, so it needs no network
port. Run it as:  python -m witnessed_gate.witness --state-dir DIR

It keeps an append-only hash chain of fingerprints in DIR/log.jsonl and saves
each new entry with fsync before it sends the stamp (Gate.tla's WitnessStamps:
add, save, stamp, as one step seen from outside). Every stamp and every chain
head it hands out is signed with Ed25519 (PyNaCl, nacl.signing). The signing
key is made here on first start, kept in DIR/signing.key, and never leaves
this process: the gate only ever sees the public key. A fingerprint it already
holds gets the same stamp again. After a crash it reloads the saved list, so
the list survives (Gate.tla's WitnessCrash).

Adapted from `apart-sprint-custody`, `custody/witness.py`. The chain
formula is head = sha256(prev_head + fp), starting from 64 zeros, with one
saved line per fingerprint and reload on start. Authentication uses Ed25519
in place of the source's HMAC test key. The witness is a separate process,
fsyncs before sending a stamp, avoids duplicate fingerprints and serves
inclusion and consistency proofs.

An exclusive lock on DIR/lock is held from before key and log reads until
shutdown, so a second process on the same folder refuses to start. Reloaded
lines must be signed by this witness's key, name this witness and hold unique
fingerprints. The hello reports full_fsync. A witness that cannot start
writes {"op": "refused", "error": ...} and exits.

Requests, one JSON object per line; every reply carries the request's "id":
  {"op": "stamp", "id": .., "fp": HEX}   -> {"ok": true, "stamp": {...}}
  {"op": "head", "id": ..}               -> {"ok": true, "head": {...signed...}}
  {"op": "decision_head", "id": .., "journal": HEX, "length": N, "decision_hash": HEX}
                                         -> {"ok": true, "decision_head": {...signed...}}
  {"op": "proof", "id": .., "fp": HEX}   -> {"ok": true, "proof": {...}, "head": {...}}
  {"op": "consistency", "id": .., "old_size": N}
                                         -> {"ok": true, "fps": [...], "head": {...}}
  {"op": "bye"}                          -> the witness exits
On start it writes {"op": "hello", "witness": ID, "pubkey": HEX, "size": N, "head": HEX,
"full_fsync": BOOL}, or, if it cannot start, {"op": "refused", "error": TEXT}.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from nacl.signing import SigningKey

from witnessed_gate.common import (ZERO_HASH, canon, canon_bytes, chain_head, head_body,
                                   is_hex64, is_uint, stamp_body, verify_signature,
                                   decision_head_body, decision_head_fp, signed_message_error)
from witnessed_gate.journal import (OwnedElsewhere, cut_torn_tail, durable_sync, release_lock,
                                    sync_dir, take_lock)


class WitnessError(Exception):
    pass


def stamp_from_line(line: Dict[str, Any]) -> Dict[str, Any]:
    """The signed stamp that a log line stands for."""
    stamp = stamp_body(line["witness"], line["fp"], line["index"], line["head"], line["t"])
    stamp["sig"] = line["sig"]
    return stamp


def signed_from_line(line: Dict[str, Any]) -> Dict[str, Any]:
    """Old stamp lines have no kind; decision heads have a distinct signed body."""
    if line.get("kind") == "decision_head":
        body = decision_head_body(line["witness"], line["journal"], line["length"],
                                  line["decision_hash"], line["index"], line["head"], line["t"])
        body["sig"] = line["sig"]
        return body
    return stamp_from_line(line)


class WitnessStore:
    """The witness's saved list and its key. Decision-head leaves have an explicit
    kind and a content-derived fingerprint; legacy stamp lines keep their shape.
    Both kinds use the same chain and survive reload."""

    def __init__(self, state_dir, witness_id: Optional[str] = None, full_fsync: bool = False):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.full_fsync = full_fsync
        self.failed: Optional[str] = None
        self._fd = None
        try:
            self._lock_fd = take_lock(self.dir / "lock", "the witness state folder %s" % self.dir)
        except OwnedElsewhere as exc:
            raise WitnessError("another witness process owns this state folder: %s" % exc)
        try:
            self._open(witness_id)
        except BaseException:
            self.close()
            raise

    def _open(self, witness_id: Optional[str]) -> None:
        self._key = self._load_or_make_key(self.dir / "signing.key")
        self.pubkey = self._key.verify_key.encode().hex()
        info_path = self.dir / "witness.json"
        if info_path.exists():
            try:
                info = json.loads(info_path.read_text(encoding="utf-8"))
                self.witness_id = info["witness"]
            except (ValueError, KeyError, TypeError) as exc:
                raise WitnessError("witness.json cannot be read: %s" % exc)
            if info.get("pubkey") != self.pubkey:
                raise WitnessError("witness.json names another key than signing.key holds")
        else:
            self.witness_id = witness_id or "witness-" + self.pubkey[:12]
            info_path.write_text(canon({"witness": self.witness_id, "pubkey": self.pubkey}) + "\n",
                                 encoding="utf-8")
        self.log_path = self.dir / "log.jsonl"
        self.entries: List[Dict[str, Any]] = []
        self._by_fp: Dict[str, Dict[str, Any]] = {}
        self._decision_heads: Dict[str, Dict[str, Any]] = {}
        self._load()
        existed = self.log_path.exists()
        self._fd = os.open(str(self.log_path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        # Complete lines can survive a failed sync. Re-establish the requested
        # durability before any recovered stamp or signed head can leave us.
        durable_sync(self._fd, self.full_fsync)
        if not existed:
            sync_dir(self.dir)

    @staticmethod
    def _load_or_make_key(path: Path) -> SigningKey:
        if path.exists():
            return SigningKey(bytes.fromhex(path.read_text(encoding="ascii").strip()))
        key = SigningKey.generate()
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key.encode().hex().encode("ascii") + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        sync_dir(path.parent)
        return key

    def _load(self) -> None:
        """Reload the saved list. Every line must follow the chain, name this
        witness, hold a fingerprint not seen before and carry a valid signature
        under this witness's key; otherwise the witness refuses to start, since
        it would sign new heads over a list it cannot vouch for."""
        if not self.log_path.exists():
            return
        cut_torn_tail(self.log_path)  # a torn last line was never stamped
        head = ZERO_HASH
        for n, raw in enumerate(self.log_path.read_bytes().splitlines()):
            try:
                line = json.loads(raw)
            except ValueError:
                raise WitnessError("log line %d is not JSON" % n)
            if not isinstance(line, dict):
                raise WitnessError("log line %d is not an object" % n)
            fp, t = line.get("fp"), line.get("t")
            if (type(line.get("index")) is not int or line["index"] != n or line.get("prev_head") != head
                    or not is_hex64(fp) or line.get("head") != chain_head(head, fp)):
                raise WitnessError("log line %d does not follow the chain" % n)
            if line.get("witness") != self.witness_id:
                raise WitnessError("log line %d names another witness" % n)
            if line.get("kind") not in (None, "stamp", "decision_head"):
                raise WitnessError("log line %d has an unknown kind" % n)
            if fp in self._by_fp or fp in self._decision_heads:
                raise WitnessError("log line %d repeats a fingerprint" % n)
            try:
                signed = signed_from_line(line)
            except (KeyError, TypeError, ValueError):
                raise WitnessError("log line %d has a malformed signed body" % n)
            if (signed_message_error(signed) or signed.get("fp") != fp
                    or not verify_signature(signed, self.pubkey)):
                raise WitnessError("log line %d is not signed by this witness's key" % n)
            head = line["head"]
            self.entries.append(line)
            (self._decision_heads if line.get("kind") == "decision_head" else self._by_fp)[fp] = line

    @property
    def size(self) -> int:
        return len(self.entries)

    @property
    def head(self) -> str:
        return self.entries[-1]["head"] if self.entries else ZERO_HASH

    def sign_body(self, body: Dict[str, Any], key: Optional[SigningKey] = None) -> Dict[str, Any]:
        signed = dict(body)
        signed["sig"] = (key or self._key).sign(canon_bytes(body)).signature.hex()
        return signed

    def save_line(self, line: Dict[str, Any]) -> None:
        """Append one log line and fsync it. Returns only once it is saved. Any
        error in the write or the sync stops the log: the line may be on disk
        in part or in full, so every later stamp is refused,
        and a restart reloads and checks the log."""
        if self.failed is not None:
            raise WitnessError("the witness's log stopped after a failed write: %s" % self.failed)
        try:
            view = memoryview(canon_bytes(line) + b"\n")
            while view:
                view = view[os.write(self._fd, view):]
            durable_sync(self._fd, self.full_fsync)
        except BaseException as exc:
            self.failed = "%s: %s" % (exc.__class__.__name__, exc)
            raise

    def stamp(self, fp: str) -> Dict[str, Any]:
        """Gate.tla's WitnessStamps(f): add fp to the list, save the list, and
        only then return the signed stamp naming fp. A fingerprint already in the
        list is not added again; it gets the stamp it got the first time."""
        if not is_hex64(fp):
            raise WitnessError("a fingerprint is 64 lowercase hex characters")
        if self.failed is not None:
            raise WitnessError("the witness's log stopped after a failed write: %s" % self.failed)
        held = self._by_fp.get(fp)
        if held is not None:
            return stamp_from_line(held)
        if fp in self._decision_heads:
            raise WitnessError("this fingerprint already belongs to a decision head")
        index, prev_head, t = self.size, self.head, time.time_ns()
        head = chain_head(prev_head, fp)
        stamp = self.sign_body(stamp_body(self.witness_id, fp, index, head, t))
        line = {"index": index, "fp": fp, "prev_head": prev_head, "head": head, "t": t,
                "witness": self.witness_id, "sig": stamp["sig"]}
        self.save_line(line)  # saved before the stamp leaves this process
        self.entries.append(line)
        self._by_fp[fp] = line
        return stamp

    def signed_head(self) -> Dict[str, Any]:
        return self.sign_body(head_body(self.witness_id, self.size, self.head))

    def decision_head(self, journal: str, length: int, decision_hash: str) -> Dict[str, Any]:
        """Save a signed decision-chain anchor before acknowledging it."""
        if not (is_hex64(journal) and is_uint(length) and length > 0 and is_hex64(decision_hash)):
            raise WitnessError("a decision head needs a journal hash, positive length and decision hash")
        if self.failed is not None:
            raise WitnessError("the witness's log stopped after a failed write: %s" % self.failed)
        fp = decision_head_fp(journal, length, decision_hash)
        if fp in self._by_fp:
            raise WitnessError("this decision head's fingerprint already belongs to a stamp")
        if fp in self._decision_heads:
            return signed_from_line(self._decision_heads[fp])
        index, prev_head, t = self.size, self.head, time.time_ns()
        head = chain_head(prev_head, fp)
        signed = self.sign_body(decision_head_body(self.witness_id, journal, length, decision_hash,
                                                   index, head, t))
        line = {k: v for k, v in signed.items() if k != "size"}
        line["prev_head"] = prev_head
        self.save_line(line)
        self.entries.append(line)
        self._decision_heads[fp] = line
        return signed

    def inclusion_proof(self, fp: str) -> Dict[str, Any]:
        """The entry's place, the head before it and every fingerprint after it:
        enough to recompute the signed head from fp."""
        held = self._by_fp.get(fp) or self._decision_heads.get(fp)
        if held is None:
            raise WitnessError("the witness does not hold this fingerprint")
        i = held["index"]
        return {"fp": fp, "index": i, "prev_head": held["prev_head"],
                "later": [e["fp"] for e in self.entries[i + 1:]]}

    def consistency_fps(self, old_size: int) -> List[str]:
        """The fingerprints added since the list had old_size entries."""
        if not isinstance(old_size, int) or old_size < 0 or old_size > self.size:
            raise WitnessError("old_size is out of range")
        return [e["fp"] for e in self.entries[old_size:]]

    def close(self) -> None:
        """Close the log, then let the folder's lock go. Safe to call twice."""
        fd, self._fd = self._fd, None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        lock, self._lock_fd = getattr(self, "_lock_fd", None), None
        release_lock(lock)


def hello(store: WitnessStore) -> Dict[str, Any]:
    return {"op": "hello", "witness": store.witness_id, "pubkey": store.pubkey,
            "size": store.size, "head": store.head, "full_fsync": bool(store.full_fsync)}


def refuse_start(exc: BaseException, outfile=None) -> int:
    """Tell the gate why this witness cannot start, then exit with 2."""
    write_reply(outfile or sys.stdout.buffer, {"op": "refused", "error": str(exc)})
    return 2


def handle(store: WitnessStore, req: Dict[str, Any]) -> Dict[str, Any]:
    """The reply to one request."""
    rid = req.get("id")
    op = req.get("op")
    try:
        if op == "stamp":
            return {"id": rid, "ok": True, "stamp": store.stamp(req.get("fp"))}
        if op == "head":
            return {"id": rid, "ok": True, "head": store.signed_head()}
        if op == "decision_head":
            return {"id": rid, "ok": True, "decision_head": store.decision_head(
                req.get("journal"), req.get("length"), req.get("decision_hash"))}
        if op == "proof":
            return {"id": rid, "ok": True, "proof": store.inclusion_proof(req.get("fp")),
                    "head": store.signed_head()}
        if op == "consistency":
            return {"id": rid, "ok": True, "old_size": req.get("old_size"),
                    "fps": store.consistency_fps(req.get("old_size")), "head": store.signed_head()}
        return {"id": rid, "ok": False, "error": "unknown op %r" % (op,)}
    except (WitnessError, OSError) as exc:
        return {"id": rid, "ok": False, "error": str(exc)}


def write_reply(outfile, reply: Any) -> None:
    if isinstance(reply, bytes):
        data = reply
    elif isinstance(reply, str):
        data = reply.encode("utf-8")
    else:
        data = canon_bytes(reply)
    outfile.write(data + b"\n")
    outfile.flush()


def serve(store: WitnessStore, infile=None, outfile=None,
          respond: Optional[Callable[[Dict[str, Any]], Any]] = None) -> None:
    """Answer requests until stdin closes or a "bye" arrives. `respond` replaces
    the normal reply (the fault hooks in faulty_witness use it); it may return
    None for no reply, or bytes for a raw line."""
    infile = infile or sys.stdin.buffer
    outfile = outfile or sys.stdout.buffer
    respond = respond or (lambda req: handle(store, req))
    write_reply(outfile, hello(store))
    while True:
        raw = infile.readline()
        if not raw:
            break
        raw = raw.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
            if not isinstance(req, dict):
                raise ValueError("not an object")
        except ValueError:
            write_reply(outfile, {"id": None, "ok": False, "error": "the request is not a JSON object"})
            continue
        if req.get("op") == "bye":
            break
        reply = respond(req)
        if reply is not None:
            write_reply(outfile, reply)


def arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="The witness: JSON lines on stdin and stdout.")
    p.add_argument("--state-dir", required=True)
    p.add_argument("--witness-id", default=None)
    p.add_argument("--full-fsync", action="store_true")
    return p


def main(argv=None) -> int:
    args = arg_parser().parse_args(argv)
    try:
        store = WitnessStore(args.state_dir, args.witness_id, args.full_fsync)
    except (WitnessError, OSError, ValueError) as exc:
        return refuse_start(exc)
    try:
        serve(store)
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
