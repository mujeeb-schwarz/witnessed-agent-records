"""The journal: the gate's own record, in two append-only files of canonical
JSON lines. Each line is written and fsynced before the gate does anything
that depends on it.

Adapted from `apart-sprint-custody`, `custody/journal.py`. Each record is
one canonical JSON line written before its fingerprint is sent, with receipt
null. seq orders records; prev_fp is the preceding record's fp, or "" for
the first. fp is sha256 of the canonical line without fp and receipt. A random
salt and wall_ns are included in that hash. Every line is fsynced before the
call returns. The gate sends fingerprints separately (SendFingerprint), and
decisions occupy a second file.

The journal takes exclusive, nonblocking flock locks on both resolved
evidence paths with .lock appended, in sorted order before reading or
repairing either file. It holds them until close(), so a second owner of
either stream fails immediately. A write or sync error poisons the journal;
every later append raises JournalFailed.

The two files:
  <name>.jsonl            the record file: one line per action, Gate.tla's
                          Entry(a, "intent"). The caller's fields are kept as
                          they are, so bench records (run_id, t,
                          handover, labels, verdicts, decision) keep their
                          shape and position, and the bench's planted edits
                          apply to this file unchanged.
  <name>.decisions.jsonl  the decision file: "open" (always the first line;
                          pins the witnesses' keys and the witness mode),
                          "approved" (Entry(a, "approved"), with the first
                          valid stamp), "refused" (Entry(a, "refused")),
                          "restart" (each restart, with the undecided records
                          its recovery refuses), and "second_stamp" (another
                          witness's stamp for a record that ran, late or
                          from catch-up; outside Gate.tla, which has one
                          witness). Each line holds seq, prev (sha256 of the
                          previous line's bytes, 64 zeros first), kind and
                          wall_ns.
"""
import fcntl
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from witnessed_gate.common import ZERO_HASH, canon_bytes, sha256_hex

# fields the journal fills in a record line; a caller's values for them are replaced
FILLED_FIELDS = ("seq", "prev_fp", "fp", "salt", "wall_ns", "receipt")
DECISION_KINDS = ("open", "approved", "refused", "restart", "second_stamp")
DECIDING = ("approved", "refused")


class JournalError(Exception):
    """The journal cannot be read, or refused a write."""


class JournalFailed(JournalError):
    """A write or a sync failed, so the file may or may not hold the line: the
    journal stops, as after a crash, and every later append raises this too.
    Reopening it (a new gate) is the only way on, through recovery."""


class OwnedElsewhere(Exception):
    """Another owner (a gate, or a witness process) holds the lock."""


def take_lock(path: Path, what: str) -> int:
    """An exclusive, non-blocking flock on the file at path, made if missing.
    Returns its file descriptor, which holds the lock until it is closed; a
    second owner, in this process or another, gets OwnedElsewhere at once."""
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        raise OwnedElsewhere("%s is in use by another owner (the lock %s is held): %s"
                             % (what, path, exc.strerror or exc))
    return fd


def release_lock(fd) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def record_fingerprint(line: Dict[str, Any]) -> str:
    """Record fingerprint adapted from `apart-sprint-custody`,
    `custody/journal.py`: sha256 of canonical JSON without fp and receipt. The line holds its own random salt, so the
    fingerprint is sha256 over the canonical bytes with a per-entry salt in them."""
    body = {k: v for k, v in line.items() if k not in ("fp", "receipt")}
    return sha256_hex(canon_bytes(body))


def decisions_path_for(path) -> Path:
    path = Path(path)
    name = path.name[:-len(".jsonl")] if path.name.endswith(".jsonl") else path.name
    return path.with_name(name + ".decisions.jsonl")


def durable_sync(fd: int, full: bool = False) -> None:
    """fsync the file. On macOS, fsync does not empty the drive's own cache;
    full=True asks for F_FULLFSYNC, which does, at a cost in time."""
    if full and hasattr(fcntl, "F_FULLFSYNC"):
        fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
    else:
        os.fsync(fd)


def sync_dir(path: Path) -> None:
    """fsync a directory, so a newly created file's name is saved too."""
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def cut_torn_tail(path: Path) -> bool:
    """If the file's last line has no newline, its write never finished, so
    nothing that depends on it happened: cut it. True if it cut."""
    data = path.read_bytes()
    if not data or data.endswith(b"\n"):
        return False
    with open(str(path), "r+b") as fh:
        fh.truncate(data.rfind(b"\n") + 1)
        fh.flush()
        os.fsync(fh.fileno())
    return True


class AppendFile:
    """One append-only file of lines, each fsynced before append returns. Any
    error while a line is written or synced poisons the file: the line may be
    on disk in part or in full, so every later append raises."""

    def __init__(self, path, full_fsync: bool = False):
        self.path = Path(path)
        self.full_fsync = full_fsync
        self.failed: Optional[str] = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists()
        self.torn_tail_cut = cut_torn_tail(self.path) if existed else False
        self.raw_lines: List[bytes] = self.path.read_bytes().splitlines() if existed else []
        self._fd = os.open(str(self.path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        if not existed:
            sync_dir(self.path.parent)

    def append(self, raw: bytes) -> None:
        if self.failed is not None:
            raise OSError("%s stopped after a failed write: %s" % (self.path.name, self.failed))
        if self._fd is None:
            raise OSError("%s is closed" % self.path.name)
        try:
            view = memoryview(raw + b"\n")
            while view:
                view = view[os.write(self._fd, view):]
            durable_sync(self._fd, self.full_fsync)
        except BaseException as exc:
            self.failed = "%s: %s" % (exc.__class__.__name__, exc)
            raise

    def close(self) -> None:
        """Close once: a second close must not hit a file descriptor number
        that the system has since given to another file."""
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            os.close(fd)
        except OSError:
            pass


def _parse(raw: bytes, what: str, n: int) -> Dict[str, Any]:
    try:
        line = json.loads(raw)
    except ValueError as exc:
        raise JournalError("%s line %d is not JSON: %s" % (what, n, exc))
    if not isinstance(line, dict):
        raise JournalError("%s line %d is not an object" % (what, n))
    return line


class Journal:
    """The gate's journal. Reopening an existing journal reads both files back
    and checks their chains: that is how a restarted gate finds the records it
    journaled but never decided. A broken chain stops the gate from starting."""

    def __init__(self, path, full_fsync: bool = False):
        self.path = Path(path)
        self.decisions_path = decisions_path_for(self.path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.full_fsync = full_fsync
        self.failed: Optional[str] = None
        self._lock_fds = []
        self._rec_file = self._dec_file = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Lock each evidence pathname, including the shared decision stream.
            # Resolve symlinks and acquire in one order before reading either file.
            evidence = sorted({self.path.resolve(), self.decisions_path.resolve()})
            for path in evidence:
                lock = path.with_name(path.name + ".lock")
                self._lock_fds.append(take_lock(lock, "the journal %s" % self.path.name))
            self._rec_file = AppendFile(self.path, full_fsync)
            self._dec_file = AppendFile(self.decisions_path, full_fsync)
        except OwnedElsewhere as exc:
            self.close()
            raise JournalError("another gate owns this journal: %s" % exc)
        except OSError as exc:
            self.close()
            raise JournalError("the journal cannot be opened: %s" % exc)
        try:
            self._read_back()
        except BaseException:
            self.close()
            raise

    def _read_back(self) -> None:
        self._records: List[Dict[str, Any]] = []
        self._decisions: List[Dict[str, Any]] = []
        self._fps: Set[str] = set()
        self._last_fp = ""
        self._last_hash = ZERO_HASH
        for n, raw in enumerate(self._rec_file.raw_lines):
            rec = _parse(raw, "record", n)
            if rec.get("seq") != n or rec.get("prev_fp") != self._last_fp:
                raise JournalError("record line %d does not follow the line before it" % n)
            if record_fingerprint(rec) != rec.get("fp"):
                raise JournalError("record line %d does not match its fingerprint" % n)
            self._records.append(rec)
            self._fps.add(rec["fp"])
            self._last_fp = rec["fp"]
        for n, raw in enumerate(self._dec_file.raw_lines):
            dec = _parse(raw, "decision", n)
            if dec.get("seq") != n or dec.get("prev") != self._last_hash:
                raise JournalError("decision line %d does not follow the line before it" % n)
            self._decisions.append(dec)
            self._last_hash = sha256_hex(raw)

    def write_record(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Gate.tla's WriteInJournal: one record line, fsynced. Returns it."""
        line = {k: v for k, v in content.items() if k not in FILLED_FIELDS}
        line.update(seq=len(self._records), prev_fp=self._last_fp,
                    salt=os.urandom(16).hex(), wall_ns=time.time_ns(), receipt=None)
        try:  # canonical JSON first, so content that is not JSON is a JournalError
            canon_bytes(line)
        except (TypeError, ValueError, RecursionError, OverflowError) as exc:
            raise JournalError("the entry cannot be written as JSON: %s" % exc)
        line["fp"] = record_fingerprint(line)
        self._append(self._rec_file, line)
        self._records.append(line)
        self._fps.add(line["fp"])
        self._last_fp = line["fp"]
        return dict(line)

    def write_decision(self, kind: str, fields: Dict[str, Any]) -> Dict[str, Any]:
        """One decision line, fsynced. Returns it."""
        if kind not in DECISION_KINDS:
            raise JournalError("unknown decision kind %r" % (kind,))
        line = dict(fields)
        line.update(seq=len(self._decisions), prev=self._last_hash, kind=kind, wall_ns=time.time_ns())
        raw = self._append(self._dec_file, line)
        self._decisions.append(line)
        self._last_hash = sha256_hex(raw)
        return dict(line)

    def _append(self, f: AppendFile, line: Dict[str, Any]) -> bytes:
        """Write one line. An entry that is not JSON is refused before anything
        is written (JournalError). Any error in the write or the sync poisons
        the whole journal (JournalFailed), now and for every later append."""
        if self.failed is not None:
            raise JournalFailed("the journal stopped after a failed write, and takes no more lines: %s"
                                % self.failed)
        try:
            raw = canon_bytes(line)
        except (TypeError, ValueError) as exc:
            raise JournalError("the entry cannot be written as JSON: %s" % exc)
        try:
            f.append(raw)
        except BaseException as exc:
            self.failed = "%s: %s: %s" % (f.path.name, exc.__class__.__name__, exc)
            if isinstance(exc, OSError):
                raise JournalFailed("the journal refused the entry, so it stops: %s" % exc)
            raise
        return raw

    def holds_record(self, fp: str) -> bool:
        return fp in self._fps

    def records(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._records]

    def decisions(self) -> List[Dict[str, Any]]:
        return [dict(d) for d in self._decisions]

    def decision_head(self) -> Dict[str, Any]:
        """The opening line identifies the journal across moves and restarts."""
        return {"journal": sha256_hex(canon_bytes(self._decisions[0])),
                "length": len(self._decisions), "decision_hash": self._last_hash}

    def close(self) -> None:
        """Close both files, then let the lock go. Safe to call twice."""
        for f in (self._rec_file, self._dec_file):
            if f is not None:
                f.close()
        fds, self._lock_fds = self._lock_fds, []
        for fd in reversed(fds):
            release_lock(fd)
