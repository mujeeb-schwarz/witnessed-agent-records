"""The gate: the state machine of Gate.tla, with one witness or two (a main
witness and a backup).

Before a call starts, the gate writes it in the journal (WriteInJournal), sends
its fingerprint to the witness (SendFingerprint) and waits for a signed stamp
naming that fingerprint (StampArrives). Only when it holds a valid stamp does
it write "approved" and let the call start (Run). If no valid stamp comes in
time, it refuses the call and writes the refusal (GiveUp). After a crash and
restart, it refuses every call it had journaled but not decided, and writes
those refusals (GateCrash). Each function that implements a step names the
Gate.tla operator in its docstring.

Two witnesses, each its own process with its own Ed25519 key; the open line
pins each witness's id and key in its slot (main, then backup), and the mode:
  "both"      (the default) every fingerprint goes to both witnesses at once,
              and the call runs on the first valid stamp (GateBothWitnesses.tla).
  "failover"  the fingerprint goes to the main witness; only if no valid stamp
              comes within the wait does it go to the backup (GateTwoWitnesses.tla).
A valid stamp from either counts, and nothing runs without one. A call is
refused, and the refusal journaled, when no witness gives a valid stamp
in time or a gate-side policy rejects it. Every later valid stamp for a call
that ran is journaled as "second_stamp". Catch-up: a witness that missed
fingerprints (it was down,
or failed to answer) is sent every approved fingerprint it has not stamped
once it answers again; in failover mode only the main witness is caught up.

Every public step and lifecycle method takes the gate's lock and checks the
call's state inside it. Recovery runs only while a gate opens; a later
recover() raises. A failed or uncertain journal write stops the gate with
GateCrashed. Witness clients, ids and keys must be distinct, and slots stay
fixed even when a witness is missing. Replies count only from their request's
channel and pinned witness; request ids carry a connection generation.
Requests left unanswered past their wait can be retried when the witness
answers again. Reopened approvals must name the journal's own records and
hold valid stamps. Sends never block. With two witnesses the gate gives up
only while it holds no stamp. close() reports any required stamps still missing.

The record-first ordering is adapted from `apart-sprint-custody`,
`custody/gate.py`: write the record before delivery. No implementation code
is copied from that module.
"""
import copy
import itertools
import json
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from witnessed_gate.wire import ApprovedCalls
from witnessed_gate.common import (FORMAT, ZERO_HASH, canon_bytes, check_stamp, sha256_hex, signed_message_error,
                                   verify_signature)
from witnessed_gate.journal import DECIDING, Journal, JournalError, JournalFailed

CODE_DIR = Path(__file__).resolve().parents[1]

# where a call stands, as in Gate.tla's Statuses ("idle" and "lost" leave no object)
PROPOSED, JOURNALED, WAITING, RAN, REFUSED = "proposed", "journaled", "waiting", "ran", "refused"
HELD = "held"
ROLES = ("main", "backup")
OUTBOUND_LIMIT = 64  # queued messages per witness, plus at most one pipe write
SETTLE_BATCH = 64    # maximum queued replies processed before checking settlement's deadline
RECOVERY_REASON = ("refused at restart: the gate had journaled this call but not decided it, "
                   "and cannot tell whether a witness got its fingerprint")
DEFAULT_ROUTES = ["every action handed to this gate before it starts; in Inspect, every tool "
                  "call matched by the approval policy '*'"]


class GateError(Exception):
    """A step was taken out of order, or the gate cannot start."""


class GateCrashed(GateError):
    """A journal write failed or may have failed, so the gate stops as if it
    had crashed: before durable approval the call does not run; after approval
    the returned Decision exposes catch_up_error. Nothing more is written, and
    every later step raises this. A new gate on the journal recovers it,
    refusing every record left undecided."""


class GateRefused(Exception):
    """Raised by adapters (the ledger) when the gate refuses an action."""


class WitnessGone(Exception):
    """The witness process has stopped, or could not start."""


_EOF = object()
_STOP = object()


class WitnessClient:
    """The gate's end of the channel to one witness process: JSON lines over
    the process's stdin and stdout. A reader thread puts each message, with
    this client, in a queue: the client's own until a gate attaches it, then
    the gate's inbox, which every witness of that gate shares. A writer thread
    sends each line, so send() only queues it and a witness that stops reading
    cannot block the gate; a line that is never read is a lost message."""

    def __init__(self, argv: List[str], env: Optional[Dict[str, str]] = None,
                 start_timeout: float = 15.0, stderr_path: Optional[Path] = None):
        self.argv = list(argv)
        self.id_prefix = ""  # the gate sets one per slot and connection, so request ids never repeat
        self.answered = False  # True once this channel has given a verified response
        self.last_answer = float("-inf")  # time.monotonic() of its last verified response
        self._stderr = open(str(stderr_path), "ab") if stderr_path else subprocess.DEVNULL
        self._proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=self._stderr, env=env, close_fds=True)
        self._queue: "queue.Queue[Any]" = queue.Queue()
        self._sink: "queue.Queue[Any]" = self._queue
        self._sink_lock = threading.Lock()
        self._gone = False
        self._ids = itertools.count(1)
        self._out: "queue.Queue[Any]" = queue.Queue(maxsize=OUTBOUND_LIMIT)
        self._writer_stop = threading.Event()
        self._write_error: Optional[str] = None
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        self._writer = threading.Thread(target=self._write, daemon=True)
        self._writer.start()
        try:
            msg = self.next_message(start_timeout)
        except WitnessGone:
            msg = None
        if isinstance(msg, dict) and msg.get("op") == "refused":
            self.kill()
            raise WitnessGone("the witness did not start: %s" % msg.get("error"))
        if not isinstance(msg, dict) or msg.get("op") != "hello":
            self.kill()
            raise WitnessGone("the witness did not start (no hello within %.1f s)" % start_timeout)
        self.hello = msg
        self.pubkey: str = msg.get("pubkey")
        self.witness_id: str = msg.get("witness")

    @classmethod
    def launch(cls, state_dir, faults: Optional[Dict[str, Any]] = None,
               python: Optional[str] = None, witness_id: Optional[str] = None,
               start_timeout: float = 15.0, full_fsync: bool = False) -> "WitnessClient":
        """Start a witness process on state_dir (its log is state_dir/log.jsonl).
        `faults` picks the faulty witness: {"mode": ..., "delay": ..., "after": ...,
        "journal": ...}; see faulty_witness.py. full_fsync=True makes the
        witness sync its log with F_FULLFSYNC (its hello reports it)."""
        state_dir = Path(state_dir)
        state_dir.mkdir(parents=True, exist_ok=True)
        module = "witnessed_gate.faulty_witness" if faults else "witnessed_gate.witness"
        argv = [python or sys.executable, "-m", module, "--state-dir", str(state_dir)]
        if witness_id:
            argv += ["--witness-id", witness_id]
        if full_fsync:
            argv.append("--full-fsync")
        for k, v in (faults or {}).items():
            argv += ["--" + k.replace("_", "-"), str(v)]
        env = dict(os.environ)
        env["PYTHONPATH"] = str(CODE_DIR) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        return cls(argv, env=env, start_timeout=start_timeout,
                   stderr_path=state_dir / "witness.stderr.txt")

    def _put(self, msg: Any) -> None:
        with self._sink_lock:
            self._sink.put((self, msg))

    def _read(self) -> None:
        try:
            for raw in iter(self._proc.stdout.readline, b""):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    msg = json.loads(raw)
                except ValueError:
                    msg = None
                if not isinstance(msg, dict):
                    msg = {"op": "garbled", "raw": raw[:200].decode("utf-8", "replace")}
                self._put(msg)
        except (OSError, ValueError):
            pass
        finally:
            self._put(_EOF)

    def _write(self) -> None:
        while not self._writer_stop.is_set():
            try:
                data = self._out.get(timeout=0.1)
            except queue.Empty:
                continue
            if data is _STOP:
                return
            try:
                self._proc.stdin.write(data)
                self._proc.stdin.flush()
            except (OSError, ValueError) as exc:
                self._write_error = "%s: %s" % (exc.__class__.__name__, exc)
                return

    def attach(self, sink: "queue.Queue[Any]") -> None:
        """Send this client's messages to `sink` from now on (a gate's inbox)."""
        with self._sink_lock:
            if self._sink is sink:
                return
            while True:
                try:
                    sink.put(self._queue.get_nowait())
                except queue.Empty:
                    break
            self._sink = sink

    def new_request_id(self) -> str:
        return "%sr%d" % (self.id_prefix, next(self._ids))

    def send(self, msg: Dict[str, Any]) -> bool:
        """Queue one message and return at once. False when it cannot be sent,
        with the reason in last_send_error: the process has stopped, an earlier
        write failed, the message is not JSON, or the bounded queue is full. In
        Gate.tla's terms, it is lost."""
        if self._gone or self._proc.poll() is not None:
            self.last_send_error = "the witness is not running"
            return False
        if self._write_error is not None:
            self.last_send_error = "an earlier write to the witness failed (%s)" % self._write_error
            return False
        try:
            data = canon_bytes(msg) + b"\n"
        except (TypeError, ValueError):
            self.last_send_error = "the message is not JSON"
            return False
        try:
            self._out.put_nowait(data)
        except queue.Full:
            self.last_send_error = "the witness's send queue is full"
            return False
        self.last_send_error = None
        return True

    def next_message(self, timeout: float) -> Optional[Dict[str, Any]]:
        """For a client no gate has attached: the next message, or None after
        timeout seconds; WitnessGone once the process has stopped."""
        if self._gone:
            raise WitnessGone("the witness process has stopped")
        try:
            _, msg = self._queue.get(timeout=timeout) if timeout > 0 else self._queue.get_nowait()
        except queue.Empty:
            return None
        if msg is _EOF:
            self._gone = True
            raise WitnessGone("the witness process has stopped")
        return msg

    @property
    def alive(self) -> bool:
        return not self._gone and self._proc.poll() is None

    def stop(self, timeout: float = 5.0) -> None:
        """Ask the witness to exit, then make sure it has."""
        if self._proc.poll() is None:
            self.send({"op": "bye"})
            try:
                self._out.put_nowait(_STOP)
            except queue.Full:
                self.kill()
                return
            self._writer.join(timeout=timeout)
            if self._writer.is_alive():  # the witness is not reading: switch it off
                self.kill()
                return
            try:
                self._proc.stdin.close()
            except (OSError, ValueError):
                pass
            try:
                self._proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.kill()
                return
        self._close_files()

    def kill(self) -> None:
        """Switch the witness off at once: Gate.tla's WitnessCrash, or an outage."""
        if self._proc.poll() is None:
            self._proc.kill()
            self._proc.wait()
        self._close_files()

    def _close_files(self) -> None:
        """Once the process has exited: end the writer, close the pipes (after
        the reader thread has read to the end) and the stderr file."""
        self._writer_stop.set()
        try:
            self._out.put_nowait(_STOP)
        except queue.Full:
            pass
        self._writer.join(timeout=2.0)
        if not self._writer.is_alive():
            try:
                self._proc.stdin.close()
            except (OSError, ValueError):
                pass
        self._reader.join(timeout=2.0)
        if not self._reader.is_alive():
            try:
                self._proc.stdout.close()
            except (OSError, ValueError):
                pass
        if self._stderr is not subprocess.DEVNULL:
            try:
                self._stderr.close()
            except OSError:
                pass


MODES = ("both", "failover")


@dataclass
class Call:
    """One action as the gate holds it in memory."""
    content: Dict[str, Any]
    kind: str
    status: str = PROPOSED
    record: Optional[Dict[str, Any]] = None
    fp: Optional[str] = None
    asking: set = field(default_factory=set)              # witness clients that may still answer
    asked: set = field(default_factory=set)               # slots sent this fingerprint (never twice)
    failures: Dict[str, str] = field(default_factory=dict)  # witness label -> why it gave no stamp
    stamp: Optional[Dict[str, Any]] = None
    times: Dict[str, int] = field(default_factory=dict)


@dataclass
class Decision:
    """The gate's answer for one action."""
    approved: bool                 # may the action start?
    outcome: str                   # "ran" or "refused"
    fp: Optional[str]
    reason: str
    record: Optional[Dict[str, Any]]
    stamp: Optional[Dict[str, Any]] = None   # the first valid stamp
    times: Dict[str, int] = field(default_factory=dict)

    catch_up_error: Optional[str] = None  # durable approval stands; the gate is now poisoned
    misbehaving: List[Dict[str, Any]] = field(default_factory=list)  # unusable replies while it was decided

    @property
    def call_id(self) -> Optional[str]:
        return (self.record or {}).get("call_id")

    @property
    def witness(self) -> Optional[str]:
        """The id of the witness whose stamp let the call run."""
        return (self.stamp or {}).get("witness")


@dataclass
class CloseReport:
    """What close() found. catch_up_done: every call that ran holds the stamps
    its mode needs (one witness: its own; "both": both witnesses'; "failover":
    the main witness's), the value to pass to checker.check_run's
    catch_up_done. missing: each call that does not, with the ids it lacks.
    signed_heads: terminal heads captured by close after catch-up, before the
    witnesses stop; retain them independently for check_run(signed_heads=...).
    head_errors: witnesses whose final heads could not be captured or verified.
    decision_heads: signed final decision-chain anchors saved before those heads.
    decision_head_errors: witnesses that did not acknowledge a valid anchor.
    catch_up_done alone says nothing about terminal evidence completeness."""
    catch_up_done: bool
    missing: List[Dict[str, Any]] = field(default_factory=list)
    signed_heads: List[Dict[str, Any]] = field(default_factory=list)
    head_errors: Dict[str, str] = field(default_factory=dict)
    misbehaving: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # witness -> its unusable replies
    exhausted: List[Dict[str, Any]] = field(default_factory=list)  # fingerprints the gate stopped asking for
    decision_heads: List[Dict[str, Any]] = field(default_factory=list)  # signed decision anchors in witness logs
    decision_head_errors: Dict[str, str] = field(default_factory=dict)


@dataclass
class _Request:
    """One request bound to a channel and slot; maintenance uses an empty fp."""
    client: "WitnessClient"
    slot: int
    fp: str
    call: Optional[Call]       # None for a catch-up request
    seq: Optional[int]         # the record's seq, for a catch-up request
    expires: float             # time.monotonic() at which its wait ends
    order: int = 0             # this gate's send order, so that in-order answers show a lost reply
    sent_at: float = 0.0       # time.monotonic() when it was sent
    generation: int = 0        # this client's channel generation when it was sent


MAX_ATTEMPTS = 3          # stamp requests per call per witness channel before it must prove healthy
MAX_TOTAL_REQUESTS = 9    # all stamp requests per call per witness channel, the first one included
MAX_BAD_ANSWERS = 2       # unusable answers for one call after which that channel is not asked again
MAX_REQUESTS = MAX_TOTAL_REQUESTS  # compatibility alias for the total stamp-request limit


def _safe_repr(value: Any) -> str:
    """A repr that is always canonical JSON text: ASCII, at most 500 characters."""
    try:
        text = repr(value)
    except Exception:  # noqa: BLE001 - a repr that fails is shown by its type
        text = "<a %s that cannot be shown>" % type(value).__name__
    return text.encode("ascii", "backslashreplace").decode("ascii")[:500]


def _not_json(content: Any) -> Optional[str]:
    """None when the content is canonical JSON; else why it is not."""
    try:
        canon_bytes(dict(content))
        return None
    except (TypeError, ValueError, RecursionError, OverflowError) as exc:
        return "%s: %s" % (exc.__class__.__name__, exc)


def _json_stand_in(content: Any) -> Dict[str, Any]:
    """The content with each field that is not JSON replaced by its repr, so
    that the attempted call can still be journaled and refused."""
    fallback = {"not_json": _safe_repr(content)}  # can always be written
    try:
        items = list(dict(content).items())
    except Exception:  # noqa: BLE001
        return fallback
    out: Dict[str, Any] = {}
    for k, v in items:
        try:
            if not isinstance(k, str):
                return fallback
            canon_bytes(k)  # keys too: a lone surrogate in a key is not JSON
        except (TypeError, ValueError, RecursionError, OverflowError):
            return fallback
        try:
            canon_bytes(v)
            out[k] = v
        except (TypeError, ValueError, RecursionError, OverflowError):
            out[k] = {"not_json": _safe_repr(v)}
    try:
        canon_bytes(out)
    except (TypeError, ValueError, RecursionError, OverflowError):
        return fallback
    return out


def _id_keys(pins: List[Dict[str, Any]]) -> List[Tuple[Any, Any]]:
    return [(p.get("witness_id"), p.get("pubkey")) for p in pins]


class Gate:
    """Gate.tla's gate. Every public step and lifecycle method takes one lock
    and checks the call's state inside it, so two threads cannot both decide a
    call and the journal keeps one order.

    witness / witnesses: one client, or [main, backup]. None in a slot leaves it
    empty (a witness that is down); a role never moves to another slot.
    witness_pubkey: pin this key for the main witness instead of its hello key.
    witness_keys: pin these keys, {witness_id: pubkey hex}, main first, instead.
    witness_mode: "both" (default) or "failover"; see the module's docstring.
    wait_seconds: how long to wait for a stamp; backup_wait_seconds: in failover
    mode, how long to wait for the backup after the main witness's wait.
    A reopened journal keeps the keys, slots and mode it pinned when opened;
    the gate holds the journal's lock until close()."""

    def __init__(self, journal_path, witness: Optional[WitnessClient] = None,
                 witness_pubkey: Optional[str] = None, wait_seconds: float = 2.0,
                 operator: str = "not stated", routes: Optional[List[str]] = None,
                 full_fsync: bool = False, witnesses: Optional[List[Optional[WitnessClient]]] = None,
                 witness_keys: Optional[Dict[str, str]] = None,
                 backup_wait_seconds: Optional[float] = None, witness_mode: Optional[str] = None):
        if witness is not None and witnesses is not None:
            raise GateError("give witness or witnesses, not both")
        if witness_mode is not None and witness_mode not in MODES:
            raise GateError("witness_mode must be one of %s" % (MODES,))
        clients = list(witnesses) if witnesses is not None else ([witness] if witness is not None else [])
        if len(clients) > 2:
            raise GateError("the gate takes a main witness and at most one backup")
        self._check_clients(clients)
        self._lock = threading.RLock()
        self.approved_calls = ApprovedCalls()
        self.approved_calls.bind(self)
        self._inbox: "queue.Queue[Any]" = queue.Queue()
        self._generation = 0
        self._channel_generations: Dict[WitnessClient, int] = {}
        self.slots: List[Optional[WitnessClient]] = []
        self.pins: List[Dict[str, Any]] = []
        self.keys: Dict[str, str] = {}
        self.crashed: Optional[str] = None
        self.closed = False
        self._close_report: Optional[CloseReport] = None
        self._decisions_sealed = False
        self.wait_seconds = float(wait_seconds)
        self.backup_wait_seconds = (self.wait_seconds if backup_wait_seconds is None
                                    else float(backup_wait_seconds))
        self.calls: List[Call] = []
        self._requests: Dict[str, _Request] = {}
        self._maintenance: Dict[str, _Request] = {}
        self._order = 0                                    # requests sent, in order
        self._sent: Dict[Tuple[Any, str], Dict[str, Any]] = {}  # (client, fp) -> its attempts
        self._answered: Dict[Tuple[Any, int], int] = {}        # (client, generation) -> latest order answered
        self._valid_answered: Dict[Tuple[Any, int], int] = {}  # the same, for valid answers only
        self._last_reply: Dict[Tuple[Any, int], float] = {}    # (client, generation) -> time of its last reply
        self.misbehaving: Dict[str, Dict[str, Any]] = {}   # witness -> its unusable replies
        self.stamps_held: Dict[str, Dict[str, Any]] = {}  # memory only: a crash loses it
        self.ignored: List[Dict[str, Any]] = []           # messages that changed nothing
        self.recovered: List[str] = []
        self.second_stamps = 0
        self._approved: List[Tuple[int, str]] = []
        self._stamped_by: Dict[str, set] = {}
        self.journal = Journal(journal_path, full_fsync)  # takes the journal's lock first
        try:
            self._open(clients, witness_pubkey, witness_keys, witness_mode, operator, routes, full_fsync)
        except BaseException:
            self.journal.close()
            raise

    def _open(self, clients, witness_pubkey, witness_keys, witness_mode, operator, routes, full_fsync) -> None:
        decisions = self.journal.decisions()
        explicit = self._explicit_pins(witness_pubkey, witness_keys, clients)
        if not decisions:
            pins = explicit if explicit is not None else self._hello_pins(clients)
            pins = [dict(p, role=ROLES[i]) for i, p in enumerate(pins[:2])] + pins[2:]
            self._check_pins(pins, clients)
            self.mode = witness_mode or "both"
            self.pins = pins
            self._journal(self.journal.write_decision, "open", {
                "format": FORMAT, "witnesses": pins, "witness_mode": self.mode,
                "witness_operator": operator, "routes": list(routes or DEFAULT_ROUTES),
                "wait_seconds": self.wait_seconds, "backup_wait_seconds": self.backup_wait_seconds,
                "full_fsync": bool(full_fsync)})
        else:
            opened = decisions[0]
            if opened.get("kind") != "open":
                raise GateError("the journal's first decision line is not its open line")
            pins = [dict(p) for p in (opened.get("witnesses") or []) if isinstance(p, dict)]
            self._check_pins(pins, clients)
            if explicit is not None and _id_keys(explicit) != _id_keys(pins):
                raise GateError("the witness keys given differ from the keys the journal pins")
            self.mode = opened.get("witness_mode") or "both"
            if witness_mode is not None and witness_mode != self.mode:
                raise GateError("the witness mode given differs from the one the journal pins")
            self.pins = pins
        self.keys = {p["witness_id"]: p["pubkey"] for p in self.pins
                     if p.get("witness_id") and p.get("pubkey")}
        if decisions:
            self._load_history(decisions)
        self.connect(clients)
        if decisions:
            self.recovered = self._recover()

    @staticmethod
    def _check_clients(clients: List[Optional[WitnessClient]]) -> None:
        """Two slots must hold two distinct witnesses: no client, id or key twice."""
        given = [c for c in clients if c is not None]
        if len({id(c) for c in given}) != len(given):
            raise GateError("the same witness client is given for two slots")
        ids = [c.witness_id for c in given]
        if len(set(ids)) != len(ids):
            raise GateError("two witness clients share the witness id %r" % (ids[0],))
        keys = [c.pubkey for c in given]
        if len(set(keys)) != len(keys):
            raise GateError("two witness clients share one public key")

    @staticmethod
    def _check_pins(pins: List[Dict[str, Any]], clients: List[Optional[WitnessClient]]) -> None:
        if len(pins) > 2:
            raise GateError("a journal pins a main witness and at most one backup")
        ids = [p["witness_id"] for p in pins if p.get("witness_id")]
        keys = [p["pubkey"] for p in pins if p.get("pubkey")]
        if len(set(ids)) != len(ids) or len(set(keys)) != len(keys):
            raise GateError("the pinned witnesses share an id or a key")
        if len(clients) > len(pins):
            raise GateError("%d witness clients given for %d pinned witnesses" % (len(clients), len(pins)))

    @staticmethod
    def _hello_pins(clients: List[Optional[WitnessClient]]) -> List[Dict[str, Any]]:
        pins = []
        for c in clients:
            if c is None:
                pins.append({"witness_id": None, "pubkey": None,
                             "missing": "no witness was running in this slot when the journal was opened"})
            else:
                pins.append({"witness_id": c.witness_id, "pubkey": c.pubkey,
                             "full_fsync": (getattr(c, "hello", None) or {}).get("full_fsync")})
        return pins

    def _explicit_pins(self, witness_pubkey, witness_keys, clients) -> Optional[List[Dict[str, Any]]]:
        if witness_keys:
            return [{"witness_id": k, "pubkey": v} for k, v in witness_keys.items()]
        if witness_pubkey and clients and clients[0] is not None:
            pins = self._hello_pins(clients)
            pins[0]["pubkey"] = witness_pubkey
            return pins
        return None

    def _load_history(self, decisions: List[Dict[str, Any]]) -> None:
        """A reopened journal's decisions must name its own records and hold
        valid stamps under its pinned keys before the gate builds catch-up work
        from them; otherwise the gate does not start."""
        by_fp = {r["fp"]: r for r in self.journal.records()}
        decided: Dict[str, str] = {}
        for d in decisions[1:]:
            kind, fp, n = d.get("kind"), d.get("record_fp"), d.get("seq")
            if kind == "open":
                raise GateError("decision line %s is a second open line" % n)
            if kind not in ("approved", "refused", "second_stamp"):
                continue
            rec = by_fp.get(fp) if isinstance(fp, str) else None
            if rec is None or rec.get("seq") != d.get("record_seq"):
                raise GateError("decision line %s names no record of this journal, so the gate does not start" % n)
            if kind in DECIDING:
                if fp in decided:
                    raise GateError("decision line %s decides record %s a second time" % (n, rec["seq"]))
                decided[fp] = kind
                if kind == "refused":
                    continue
            elif decided.get(fp) != "approved":
                raise GateError("decision line %s is a second stamp for a record that did not run" % n)
            why = check_stamp(d.get("stamp"), fp, self.keys)
            if why:
                raise GateError("decision line %s holds a stamp that fails its check (%s), so the gate "
                                "does not start" % (n, why))
            if kind == "approved":
                self._approved.append((rec["seq"], fp))
            self._stamped_by.setdefault(fp, set()).add(d["stamp"].get("witness"))

    # ------------------------------------------------------------ properties

    @property
    def witnesses(self) -> List[WitnessClient]:
        """The connected witness clients, main first (an empty slot is left out; see slots)."""
        return [c for c in self.slots if c is not None]

    @property
    def main(self) -> Optional[WitnessClient]:
        return self.slots[0] if self.slots else None

    @property
    def backup(self) -> Optional[WitnessClient]:
        return self.slots[1] if len(self.slots) > 1 else None

    @property
    def witness(self) -> Optional[WitnessClient]:
        """The main witness (the one-witness name)."""
        return self.main

    @property
    def main_id(self) -> Optional[str]:
        return self.pins[0].get("witness_id") if self.pins else None

    @property
    def pubkey(self) -> Optional[str]:
        """The main witness's pinned key."""
        return self.pins[0].get("pubkey") if self.pins else None

    @property
    def degraded(self) -> bool:
        """True when a pinned slot has no key, no client, or a client that has stopped."""
        with self._lock:
            if any(not p.get("witness_id") or not p.get("pubkey") for p in self.pins):
                return True
            return any(c is None or not c.alive for c in self.slots)

    def required_witnesses(self) -> List[Tuple[str, Optional[str]]]:
        """(role, witness id) of each witness whose stamp every call that ran
        must end with: the one witness, both in "both" mode, the main witness
        in "failover" mode. The id is None for a slot pinned with no witness."""
        with self._lock:
            if self.crashed is not None:
                self._check_open()
            return self._required_witnesses()

    def _required_witnesses(self):
        if len(self.pins) <= 1 or self.mode == "failover":
            return [(ROLES[0], self.pins[0].get("witness_id"))] if self.pins else []
        return [(ROLES[i], p.get("witness_id")) for i, p in enumerate(self.pins)]

    def _slot_of(self, client: Any) -> Optional[int]:
        for i, c in enumerate(self.slots):
            if c is client:
                return i
        return None

    @staticmethod
    def _label_slot(slot: Optional[int]) -> str:
        return "main witness" if slot == 0 else ("backup witness" if slot == 1 else "a disconnected witness")

    def _check_open(self) -> None:
        if self.crashed is not None:
            raise GateCrashed("the gate stopped after a failed journal write; open a new gate on the "
                              "journal: %s" % self.crashed)
        if self.closed:
            raise GateError("the gate is closed")

    def _journal(self, fn, *args):
        """Every journal write goes through here: a failed or uncertain write
        stops the gate, as a crash would."""
        try:
            return fn(*args)
        except JournalFailed as exc:
            self.crashed = str(exc)
            raise GateCrashed("the journal write failed, so the gate stops as after a crash: %s" % exc) from exc

    # ------------------------------------------------------------ the steps

    def propose(self, content: Dict[str, Any], kind: str = "call") -> Call:
        """Gate.tla: Propose(a). The call exists only in the gate's memory."""
        with self._lock:
            self._check_open()
            return Call(content=copy.deepcopy(dict(content)), kind=str(kind),
                        times={"proposed_ns": time.time_ns()})

    def write_in_journal(self, call: Call) -> None:
        """Gate.tla: WriteInJournal(a). The record line is fsynced before this returns."""
        with self._lock:
            self._check_open()
            if call.status != PROPOSED:
                raise GateError("only a proposed call is written in the journal")
            content = dict(call.content)
            content["action_kind"] = call.kind
            call.record = self._journal(self.journal.write_record, content)
            call.fp = call.record["fp"]
            call.status = JOURNALED
            call.times["journaled_ns"] = time.time_ns()
            self.calls.append(call)

    def send_fingerprint(self, call: Call) -> bool:
        """Gate.tla: SendFingerprint(a). Only for a call already in the journal,
        and never twice to one witness: in "both" mode to every witness at once,
        in "failover" mode to the main witness (await_stamp may then send it to
        the backup). A send that fails is a lost message."""
        with self._lock:
            self._check_open()
            if call.status != JOURNALED or not self.journal.holds_record(call.fp):
                raise GateError("a fingerprint is sent only for a call written in the journal")
            call.status = WAITING
            if not self.slots:
                call.failures["gate"] = "no witness is connected"
                return False
            call.times["sent_ns"] = time.time_ns()
            for slot in (range(len(self.slots)) if self.mode == "both" else [0]):
                self._ask(call, slot)
            return bool(call.asking)

    def _ask(self, call: Call, slot: int) -> bool:
        """Send call's fingerprint to the witness in `slot`, once per call."""
        if slot in call.asked:
            return False
        call.asked.add(slot)
        label = self._label_slot(slot)
        client = self.slots[slot] if slot < len(self.slots) else None
        if client is None:
            call.failures[label] = "no witness is connected in this slot"
            return False
        if not self.pins[slot].get("pubkey"):
            call.failures[label] = "this slot has no pinned key, so no stamp from it can be checked"
            return False
        rid = client.new_request_id()
        self._requests[rid] = _Request(client, slot, call.fp, call, None, time.monotonic() + self.wait_seconds)
        client.last_send_error = None
        if client.send({"op": "stamp", "id": rid, "fp": call.fp}):
            call.asking.add(client)
            self._note_sent(self._requests[rid])
            return True
        del self._requests[rid]
        call.failures[label] = "the fingerprint could not be sent: %s" % (
            getattr(client, "last_send_error", None) or "the witness is not running")
        return False

    def _why_bad(self, msg: Dict[str, Any], req: _Request) -> Optional[str]:
        """None when msg holds a good stamp, from the witness pinned in the slot
        the request went to, for the request's fingerprint."""
        if not msg.get("ok"):
            return "the witness answered with an error: %s" % msg.get("error")
        pin = self.pins[req.slot] if req.slot < len(self.pins) else {}
        wid, key = pin.get("witness_id"), pin.get("pubkey")
        if not wid or not key:
            return "the %s has no pinned key" % self._label_slot(req.slot)
        stamp = msg.get("stamp")
        if isinstance(stamp, dict) and stamp.get("kind") == "stamp" and stamp.get("witness") != wid:
            return "the stamp names witness %r, not the %s that was asked" % (stamp.get("witness"),
                                                                             self._label_slot(req.slot))
        return check_stamp(stamp, req.fp, {wid: key})

    def stamp_arrives(self, msg: Dict[str, Any], source: Optional[WitnessClient] = None) -> Optional[str]:
        """Gate.tla: StampArrives(f). Takes a reply only for a request this gate
        sent, on the channel it was sent on (source; None means unknown), and a
        stamp only from the witness pinned in the slot it was sent to. Returns
        HELD when the gate now holds a valid stamp for the waiting call, and a
        reason when that witness's reply is unusable (a bad signature, another
        fingerprint or witness, an error). A valid stamp for a call that already
        ran, or a catch-up reply, is journaled as "second_stamp". Anything else
        changes nothing and returns None."""
        with self._lock:
            self._check_open()
            now = time.time_ns()
            rid = msg.get("id") if isinstance(msg, dict) else None
            req = self._requests.get(rid) if isinstance(rid, str) else None
            if req is None or source is not req.client:
                self.ignored.append({"wall_ns": now, "msg": str(msg)[:200],
                                     "why": "no request of this gate went with this id to the witness that sent it"})
                return None
            del self._requests[rid]
            why = self._why_bad(msg, req)
            self._note_answer(req, why is None)
            if why is not None:
                self._note_misbehaving(req, why)
            if req.call is None:
                if why is None:
                    self._second_stamp(req.seq, req.fp, msg["stamp"], now)
                else:
                    self.ignored.append({"wall_ns": now, "record_fp": req.fp, "why": "catch-up reply unusable: " + why})
                return None
            call = req.call
            if call.status == WAITING and call.fp not in self.stamps_held:
                if why:
                    call.failures[self._label_slot(req.slot)] = why
                    call.asking.discard(req.client)
                    return why
                call.stamp = msg["stamp"]
                self.stamps_held[call.fp] = call.stamp
                call.times["stamp_received_ns"] = now
                return HELD
            if call.status == RAN and why is None:
                self._second_stamp(call.record["seq"], call.fp, msg["stamp"], now)
                return None
            self.ignored.append({"wall_ns": now, "record_fp": call.fp,
                                 "why": ("late: the call was already %s" % call.status) if why is None
                                 else "unusable: " + why})
            return None

    def _second_stamp(self, seq: int, fp: str, stamp: Dict[str, Any], now: int) -> None:
        if self._decisions_sealed:
            return  # close has frozen the exact decision chain being witnessed
        have = self._stamped_by.setdefault(fp, set())
        if stamp.get("witness") in have:
            return  # that witness's stamp is journaled already
        self._journal(self.journal.write_decision, "second_stamp", {
            "record_seq": seq, "record_fp": fp, "stamp": stamp, "stamp_received_ns": now})
        have.add(stamp.get("witness"))
        self.second_stamps += 1

    def _next(self, timeout: float) -> Optional[Tuple[WitnessClient, Any]]:
        try:
            return self._inbox.get(timeout=timeout) if timeout > 0 else self._inbox.get_nowait()
        except queue.Empty:
            return None

    def _take(self, item: Tuple[WitnessClient, Any]) -> None:
        with self._lock:
            source, msg = item
            if msg is _EOF:
                source._gone = True
                label = self._label_slot(self._slot_of(source))
                for call in self.calls:
                    if source in call.asking:
                        call.asking.discard(source)
                        call.failures[label] = "the witness stopped before it stamped the call"
                return
            if self._maintenance_reply(source, msg):
                return
            self.stamp_arrives(msg, source)

    def _wait_any(self, call: Call, seconds: float, slots=None) -> Optional[str]:
        """Wait up to `seconds` until the gate holds a valid stamp for call, or
        no witness asked can still answer. None once held; else the reason."""
        deadline = time.monotonic() + seconds
        for req in self._requests.values():
            if req.call is call and (slots is None or req.slot in slots):
                req.expires = deadline
        while call.fp not in self.stamps_held:
            if not call.asking:
                return "no witness gave a valid stamp (%s)" % self._failures(call)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failed = self._failures(call)
                return "gave up waiting for a stamp after %.3f s%s" % (seconds, " (%s)" % failed if failed else "")
            item = self._next(remaining)
            if item is not None:
                self._take(item)
        return None

    @staticmethod
    def _failures(call: Call) -> str:
        return "; ".join("%s: %s" % kv for kv in call.failures.items())

    def await_stamp(self, call: Call, wait_seconds: Optional[float] = None) -> Optional[str]:
        """Wait for StampArrives for this call. In "both" mode, from either
        witness. In "failover" mode, from the main witness; if no valid stamp
        came within the wait, the same fingerprint goes to the backup, once per
        call however often this is called, and a valid stamp from either
        counts. None once the gate holds a valid stamp; otherwise the reason
        to give up."""
        with self._lock:
            self._check_open()
            if call.status != WAITING:
                raise GateError("only a waiting call waits for a stamp")
            wait = self.wait_seconds if wait_seconds is None else float(wait_seconds)
            why = self._wait_any(call, wait, slots=[0] if self.mode == "failover" and 1 not in call.asked else None)
            if why is None or self.mode == "both" or len(self.slots) < 2 or 1 in call.asked:
                return why
            call.times["backup_sent_ns"] = time.time_ns()
            self._ask(call, 1)
            why_backup = self._wait_any(call, self.backup_wait_seconds, slots=[1])
            return None if why_backup is None else "main witness: %s; then %s" % (why, why_backup)

    def run(self, call: Call) -> Decision:
        """Gate.tla: Run(a). Only with a held stamp naming this call's
        fingerprint. The "approved" line is fsynced before the call may start;
        the start itself is the caller's (in Inspect, the tool runs after the
        approver returns), so this is two steps where Gate.tla has one. If the
        approval cannot be written for certain, the gate stops (GateCrashed):
        no refusal follows, and recovery decides the call at the next start."""
        with self._lock:
            self._check_open()
            if call.status != WAITING or call.fp not in self.stamps_held:
                raise GateError("Run needs a waiting call and a held stamp naming it")
            self._journal(self.journal.write_decision, "approved", {
                "record_seq": call.record["seq"], "record_fp": call.fp, "stamp": call.stamp,
                "stamp_received_ns": call.times["stamp_received_ns"]})
            call.status = RAN
            call.times["decided_ns"] = time.time_ns()
            self._approved.append((call.record["seq"], call.fp))
            self._stamped_by.setdefault(call.fp, set()).add(call.stamp.get("witness"))
            who = "the main witness" if call.stamp.get("witness") == self.main_id else "the backup witness"
            return Decision(True, RAN, call.fp, "stamped by " + who, call.record, call.stamp,
                            dict(call.times))

    def give_up(self, call: Call, reason: str) -> Decision:
        """Gate.tla: GiveUp(a). Refuse the call and journal the refusal. With
        two witnesses, only while the gate holds no stamp for the call, as
        GateBothWitnesses.tla and GateTwoWitnesses.tla say; with one witness,
        Gate.tla lets it give up at any moment while the call waits."""
        with self._lock:
            self._check_open()
            if call.status != WAITING:
                raise GateError("only a waiting call is given up")
            if len(self.pins) == 2 and call.fp in self.stamps_held:
                raise GateError("with two witnesses the gate gives up only while it holds no stamp for the call")
            self._journal(self.journal.write_decision, "refused", {
                "record_seq": call.record["seq"], "record_fp": call.fp, "reason": reason})
            call.status = REFUSED
            call.times["decided_ns"] = time.time_ns()
            return Decision(False, REFUSED, call.fp, reason, call.record, None, dict(call.times))

    def recover(self) -> List[str]:
        """Gate.tla: GateCrash, its restart half. It runs only while a gate opens
        a journal that already has lines, before the gate takes any call; called
        later it raises, since this gate's live calls, held stamps and requests
        would outlive it. Open a new Gate on the journal instead."""
        with self._lock:
            self._check_open()
        raise GateError("recovery runs only when a gate opens its journal, before it takes a call; "
                        "open a new Gate on the journal instead")

    def _recover(self) -> List[str]:
        """Every record with no decision is refused, and the refusals are
        journaled after a "restart" line that lists them. The stamps the old
        gate held in memory are gone; calls proposed but never journaled left
        no record ("lost")."""
        records = self.journal.records()
        decided = {d["record_fp"] for d in self.journal.decisions() if d.get("kind") in DECIDING}
        undecided = [r for r in records if r["fp"] not in decided]
        self._journal(self.journal.write_decision, "restart", {
            "records_seen": len(records), "undecided": [r["fp"] for r in undecided]})
        for r in undecided:
            self._journal(self.journal.write_decision, "refused", {
                "record_seq": r["seq"], "record_fp": r["fp"], "reason": RECOVERY_REASON})
        return [r["fp"] for r in undecided]

    # ------------------------------------------------------------ one call

    def decide(self, content: Dict[str, Any], kind: str = "call",
               wait_seconds: Optional[float] = None, policy_refusal: Optional[str] = None) -> Decision:
        """Every step for one action, in Gate.tla's order, one call at a time.
        After an approval, any witness that has answered again and still
        misses fingerprints is caught up before decide returns; that time is in
        times["catch_up_ns"], apart from the decision's own steps. Raises
        GateCrashed if storage fails before durable approval. After approval, a
        catch-up storage failure is returned in catch_up_error and poisons the gate."""
        with self._lock:
            self._check_open()
            not_json = _not_json(content)
            if not_json is not None:  # journal a stand-in and refuse it; never raise
                content = _json_stand_in(content)
                reason = ("the call's content is not JSON (%s), so a stand-in was journaled in its place "
                          "and the call is refused" % not_json)
                policy_refusal = reason if policy_refusal is None else "%s; %s" % (reason, policy_refusal)
            if _not_json({"action_kind": str(kind)}) is not None:  # the kind is journaled too
                kind = _safe_repr(kind)
                reason = "the call's kind is not JSON, so a stand-in was journaled in its place and the call is refused"
                policy_refusal = reason if policy_refusal is None else "%s; %s" % (reason, policy_refusal)
            call = self.propose(content, kind)
            try:
                self.write_in_journal(call)
            except GateCrashed:
                raise
            except JournalError as exc:
                # the entry is not JSON: nothing was written or sent, and the call never runs
                return Decision(False, REFUSED, None,
                                "the journal could not record the call, so it does not run: %s" % exc,
                                None, None, dict(call.times))
            if policy_refusal is not None:
                call.status = WAITING
                return self.give_up(call, policy_refusal)
            self.send_fingerprint(call)
            why = self.await_stamp(call, wait_seconds)
            if why is not None:
                refused = self.give_up(call, why)
                refused.misbehaving = list(getattr(call, "misbehaving", []))
                return refused
            decision = self.run(call)
            decision.misbehaving = list(getattr(call, "misbehaving", []))
            started = time.time_ns()
            try:
                self.catch_up(only_answering=True)
            except GateCrashed as exc:  # permission is durable; expose the failure to the caller
                decision.catch_up_error = str(exc)
                decision.reason += "; then the journal failed during catch-up, so the gate has stopped: %s" % exc
            decision.times["catch_up_ns"] = time.time_ns() - started
            return decision

    # ------------------------------------------------------------ catch-up

    def missed(self, client: WitnessClient) -> List[Tuple[int, str]]:
        """The approved records the witness in client's slot has not stamped,
        leaving out those with a request still due: one inside its wait, or one
        past its wait that this channel has not answered anything since (a
        channel that went quiet is not flooded with repeats). In failover mode
        the backup misses nothing by design."""
        with self._lock:
            self._check_open()
            return list(self._iter_missed(client))

    def _iter_missed(self, client: WitnessClient, deadline=None):
        """Prepare catch-up lazily, checking its budget even before any send."""
        slot = self._slot_of(client)
        if slot is None or slot >= len(self.pins) or (self.mode == "failover" and slot != 0):
            return
        wid = self.pins[slot].get("witness_id")
        if not wid or not self.pins[slot].get("pubkey"):
            return
        now = time.monotonic()
        flying = set()
        for req in self._requests.values():
            if deadline is not None and time.monotonic() >= deadline:
                return
            # A request stays on its way until its wait ends, and after that until a
            # later request in its channel generation has been answered: a witness
            # answers in order, so only then was this reply lost.
            if req.client is client and not self._proven_lost(req, now):
                flying.add(req.fp)
        for seq, fp in self._approved:
            if deadline is not None and time.monotonic() >= deadline:
                return
            if wid in self._stamped_by.get(fp, ()) or fp in flying:
                continue
            if self._blocked(client, fp, now, rearm=True) is None:
                yield seq, fp

    def catch_up(self, wait_seconds: Optional[float] = None, only_answering: bool = False) -> int:
        """Send each witness every fingerprint it missed, and journal each stamp
        that comes back as "second_stamp". With only_answering, only witnesses
        that have answered on their current channel. The wait starts before the
        sends. Returns how many second stamps it journaled."""
        with self._lock:
            self._check_open()
            before = self.second_stamps
            self._prune_requests()
            deadline = time.monotonic() + (self.wait_seconds if wait_seconds is None else wait_seconds)
            waiting = set()
            for slot, client in enumerate(self.slots):
                if time.monotonic() >= deadline:
                    break
                if client is None or not client.alive or (only_answering and not client.answered):
                    continue
                for seq, fp in self._iter_missed(client, deadline):
                    if time.monotonic() >= deadline:
                        break
                    if not self.journal.holds_record(fp):  # never send a fingerprint that is no record
                        self.ignored.append({"wall_ns": time.time_ns(), "record_fp": fp,
                                             "why": "catch-up skipped: the journal holds no such record"})
                        continue
                    if time.monotonic() >= deadline:
                        break
                    rid = client.new_request_id()
                    self._requests[rid] = _Request(client, slot, fp, None, seq, deadline)
                    if not client.send({"op": "stamp", "id": rid, "fp": fp}):
                        del self._requests[rid]
                        break
                    waiting.add(rid)
                    self._note_sent(self._requests[rid])
            while any(rid in self._requests for rid in waiting):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                item = self._next(remaining)
                if item is not None:
                    self._take(item)
            return self.second_stamps - before

    def _note_sent(self, req: _Request) -> None:
        """Count a request that went out, per channel and fingerprint."""
        self._order_request(req)
        entry = self._sent.setdefault((req.client, req.fp), {"window": 0, "total": 0, "last": None, "bad": 0,
                                                              "bad_order": None})
        entry["window"] += 1
        entry["total"] += 1
        entry["last"] = req

    def _order_request(self, req: _Request) -> None:
        """Stamp and maintenance requests share the channel's send order."""
        self._order += 1
        req.order, req.sent_at, req.generation = (self._order, time.monotonic(),
                                                self._channel_generations[req.client])

    def _note_answer(self, req: _Request, valid: bool) -> None:
        chan = (req.client, req.generation)
        self._answered[chan] = max(self._answered.get(chan, 0), req.order)
        self._last_reply[chan] = time.monotonic()
        if valid:
            req.client.answered = True
            req.client.last_answer = self._last_reply[chan]
            self._valid_answered[chan] = max(self._valid_answered.get(chan, 0), req.order)

    def _proven_lost(self, req: _Request, now: float) -> bool:
        """Past its wait, and a later request in its channel generation answered."""
        return req.expires <= now and req.order < self._answered.get((req.client, req.generation), 0)

    def _blocked(self, client: WitnessClient, fp: str, now: float, rearm: bool = False) -> Optional[str]:
        """None when catch-up may ask this channel for fp now; else why not.
        Attempts come in windows of MAX_ATTEMPTS; a window that ran out, or an
        unusable answer, is re-armed only once the channel has answered a later
        request validly, and never past MAX_TOTAL_REQUESTS requests or
        MAX_BAD_ANSWERS unusable answers for that fingerprint."""
        st = self._sent.get((client, fp))
        if st is None or st["last"] is None:
            return None
        last = st["last"]
        valid = self._valid_answered.get((client, last.generation), 0)
        if st["bad"] >= MAX_BAD_ANSWERS:
            return "its answers for this fingerprint were unusable %d times" % st["bad"]
        if st["total"] >= MAX_TOTAL_REQUESTS:
            return "its %d requests for this fingerprint ran out" % st["total"]
        if st["bad_order"] is not None:
            if valid <= st["bad_order"]:
                return "its last answer for this fingerprint was unusable, and it has answered nothing validly since"
            if rearm:
                st["bad_order"], st["window"] = None, 0
        if st["window"] >= MAX_ATTEMPTS:
            if valid <= last.order:
                return "its %d attempts ran out, and it has answered nothing validly since" % st["window"]
            if rearm:
                st["window"] = 0
        if st["window"] and now < last.expires + (2 ** (st["window"] - 1) - 1) * max(0.0, last.expires - last.sent_at):
            return "backoff"
        return None

    def _note_misbehaving(self, req: _Request, why: str) -> None:
        """Record an unusable reply (a bad signature, another fingerprint or
        witness, a replay, an error). Exclude this fingerprint on the channel
        until a later valid response proves health, subject to the permanent
        retry limits. Name the witness in the decision and close report."""
        entry = self._sent.get((req.client, req.fp))
        if entry is not None:  # excluded until the channel answers a later request validly
            entry["bad"] += 1
            entry["bad_order"] = req.order
        wid = self.pins[req.slot].get("witness_id") if req.slot < len(self.pins) else None
        role = ROLES[req.slot] if req.slot < len(ROLES) else None
        entry = self.misbehaving.setdefault(wid or self._label_slot(req.slot), {
            "witness": wid, "role": role, "unusable_replies": 0, "why": why, "record_fps": []})
        entry["unusable_replies"] += 1
        entry["why"] = why
        if req.fp not in entry["record_fps"] and len(entry["record_fps"]) < 100:
            entry["record_fps"].append(req.fp)
        if req.call is not None:
            req.call.__dict__.setdefault("misbehaving", []).append({"witness": wid, "role": role, "why": why})

    def _still_due(self, req: _Request, now: float) -> bool:
        """A reply that may still come: its channel is up, and its wait has not
        ended, or the channel answered within the last wait and has answered
        nothing sent after this request."""
        client = req.client
        if not client.alive:
            return False
        if req.expires > now:
            return True
        if self._proven_lost(req, now):
            return False
        return now - self._last_reply.get((client, req.generation), float("-inf")) < self.wait_seconds

    def _prune_requests(self) -> None:
        """Forget each request whose fingerprint that witness has a journaled
        stamp for already: its reply could change nothing."""
        now = time.monotonic()
        for rid, req in list(self._maintenance.items()):
            if not req.client.alive or self._proven_lost(req, now):
                del self._maintenance[rid]
        for rid, req in list(self._requests.items()):
            if req.call is not None and req.call.status == WAITING:
                continue
            wid = self.pins[req.slot].get("witness_id") if req.slot < len(self.pins) else None
            if (wid and wid in self._stamped_by.get(req.fp, ())) or self._proven_lost(req, now):
                del self._requests[rid]  # its reply changes nothing, or it was proven lost

    def settle(self, seconds: float) -> None:
        """Wait up to `seconds` for every reply still due from a running
        witness: a request counts until its wait ends, so a reply that was lost
        is not waited for. Queued messages are processed in finite
        batches, with the deadline checked between batches."""
        with self._lock:
            self._check_open()
            deadline = time.monotonic() + seconds
            while True:
                for _ in range(SETTLE_BATCH):  # queued replies, with a finite batch
                    item = self._next(0)
                    if item is None:
                        break
                    self._take(item)
                self._prune_requests()
                now = time.monotonic()
                if now >= deadline:
                    return
                if not self._inbox.empty():
                    continue  # another finite batch, within the remaining budget
                if not any(self._still_due(r, now) for r in self._requests.values()):
                    return
                remaining = min(deadline - now, max(0.01, self.wait_seconds))
                if remaining <= 0:
                    return
                item = self._next(remaining)
                if item is not None:
                    self._take(item)

    def stamps_report(self) -> CloseReport:
        """Whether every call that ran holds the stamps its mode needs."""
        with self._lock:
            self._check_open()
            return self._stamps_report()

    def _stamps_report(self) -> CloseReport:
        with self._lock:
            required = self._required_witnesses()
            missing = []
            for seq, fp in self._approved:
                have = self._stamped_by.get(fp, set())
                lack = [wid if wid else "(no %s witness pinned)" % role
                        for role, wid in required if not wid or wid not in have]
                if lack:
                    missing.append({"record_seq": seq, "record_fp": fp, "missing": lack})
            report = CloseReport(not missing, missing)
            report.misbehaving = copy.deepcopy(self.misbehaving)  # snapshot unusable witness replies for the live report
            report.exhausted = self._exhausted(required)
            return report

    def _exhausted(self, required) -> List[Dict[str, Any]]:
        """Approved fingerprints a required witness's current channel will not be
        asked for again: its attempts ran out, or its answers were unusable."""
        now, out = time.monotonic(), []
        for seq, fp in self._approved:
            for role, wid in required:
                slot = ROLES.index(role) if role in ROLES else None
                client = self.slots[slot] if slot is not None and slot < len(self.slots) else None
                if not wid or client is None or wid in self._stamped_by.get(fp, ()):
                    continue
                if any(r.client is client and r.fp == fp and not self._proven_lost(r, now)
                       for r in self._requests.values()):
                    continue  # a reply may still come
                why = self._blocked(client, fp, now)
                if why is not None and why != "backoff":
                    st = self._sent.get((client, fp)) or {}
                    out.append({"record_seq": seq, "record_fp": fp, "witness": wid, "role": role,
                                "requests": st.get("total", 0), "why": why})
        return out

    def history(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """A consistent record/decision snapshot, also available after normal close."""
        with self._lock:
            if self.crashed is not None:
                self._check_open()
            return copy.deepcopy((self.journal.records(), self.journal.decisions()))

    # ------------------------------------------------------------ around the steps

    def connect(self, witnesses) -> None:
        """Use these witness clients, slot by slot, main first (after a witness
        restart, say); None, or a short list, leaves a slot empty. The pinned
        keys and slots stay the journal's. A new client gets a new generation;
        a retained client's channel and attempt totals stay unchanged."""
        if isinstance(witnesses, WitnessClient):
            witnesses = [witnesses]
        clients = list(witnesses or [])
        with self._lock:
            self._check_open()
            self._check_clients(clients)
            if len(clients) > len(self.pins):
                raise GateError("%d witness clients given for %d pinned witnesses" % (len(clients), len(self.pins)))
            clients += [None] * (len(self.pins) - len(clients))
            self._generation += 1
            for i, w in enumerate(clients):
                if w is not None:
                    if w not in self._channel_generations:
                        self._channel_generations[w] = self._generation
                        w.id_prefix = "g%d.w%d." % (self._generation, i)
                    w.attach(self._inbox)
            self.slots = clients

    def drain(self, seconds: float) -> int:
        """Read the witnesses' messages for up to `seconds`. Late stamps for
        refused calls change nothing; other witnesses' stamps for calls that
        ran are journaled. Returns how many messages it read. The deadline is
        checked before each read, so a witness that keeps sending cannot hold
        it past `seconds`; drain(0) therefore reads nothing, and
        settle() is the call that processes replies already queued."""
        n = 0
        with self._lock:
            self._check_open()
            deadline = time.monotonic() + seconds
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return n
                item = self._next(remaining)
                if item is None:
                    continue
                n += 1
                self._take(item)

    def ask_witness(self, op: str, timeout: float = 5.0, index: int = 0,
                    **fields: Any) -> Optional[Dict[str, Any]]:
        """A request outside Gate.tla's steps (a signed head, an inclusion or a
        consistency proof). Other messages read meanwhile are taken as usual."""
        with self._lock:
            self._check_open()
            if index >= len(self.slots) or self.slots[index] is None:
                return None
            w = self.slots[index]
            rid = w.new_request_id()
            if not w.send(dict(fields, op=op, id=rid)):
                return None
            deadline = time.monotonic() + timeout
            request = _Request(w, index, "", None, None, deadline)
            self._order_request(request)
            self._maintenance[rid] = request
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                item = self._next(remaining)
                if item is None:
                    continue
                source, msg = item
                if msg is not _EOF and source is w and msg.get("id") == rid:
                    self._maintenance_reply(source, msg)
                    return msg
                self._take(item)
                if msg is _EOF and source is w:
                    return None

    def _maintenance_reply(self, source, msg) -> bool:
        """Keep request order even when a head reply arrives after its timeout."""
        rid = msg.get("id") if isinstance(msg, dict) else None
        req = self._maintenance.get(rid) if isinstance(rid, str) else None
        if req is None or source is not req.client:
            return False
        del self._maintenance[rid]
        head = msg.get("head") if msg.get("ok") else None
        pin = self.pins[req.slot]
        valid = (signed_message_error(head) is None and head.get("kind") == "head"
                 and head.get("witness") == pin.get("witness_id")
                 and verify_signature(head, pin.get("pubkey")))
        self._note_answer(req, valid)
        return True

    def _capture_heads(self, heads, errors) -> None:
        """Capture each pinned witness's terminal head while its process lives."""
        for index, pin in enumerate(self.pins):
            wid, key = pin.get("witness_id"), pin.get("pubkey")
            label = wid or "(no %s witness pinned)" % ROLES[index]
            reply = self.ask_witness("head", timeout=max(0.1, self.wait_seconds), index=index)
            head = reply.get("head") if isinstance(reply, dict) and reply.get("ok") else None
            if (signed_message_error(head) is not None or head.get("kind") != "head"
                    or head.get("witness") != wid or not verify_signature(head, key)):
                errors[label] = "no valid final signed head from this witness"
            else:
                heads.append(copy.deepcopy(head))

    def _decision_file_differs(self, final: Dict[str, Any]) -> Optional[str]:
        """Where the decision file on disk first differs from the chain
        this gate holds in memory, or None when every line matches. In memory,
        line n's hash is the "prev" of line n + 1 (written by this gate, or
        checked when it read the file back at open), and the last line's is the
        chain head. The file's lines are read as the checker reads them: the
        non-empty ones."""
        held = [d.get("prev") for d in self.journal.decisions()[1:]] + [final["decision_hash"]]
        try:
            disk = [sha256_hex(ln) for ln in self.journal.decisions_path.read_bytes().splitlines() if ln.strip()]
        except OSError as exc:
            return "the decision file on disk is unreadable (%s)" % exc
        n = next((i for i, (a, b) in enumerate(zip(disk, held)) if a != b), min(len(disk), len(held)))
        if n == len(disk) == len(held):
            return None
        if n < min(len(disk), len(held)):
            what = "its hash on disk is %s, and the gate holds %s" % (disk[n], held[n])
        elif len(disk) < len(held):
            what = "the line is missing on disk"
        else:
            what = "the gate holds no such line"
        return ("the decision file on disk differs from the chain this gate holds, first at line %d: %s "
                "(%d lines on disk, %d held)" % (n, what, len(disk), len(held)))

    def _anchor_decisions(self, anchors, errors) -> None:
        """Every running slot saves the final decision chain before final heads.
        The chain anchored is the one this gate holds in memory. The decision
        file on disk is compared with that whole chain, line by line, and the
        first line that differs is reported under "decision file" in
        decision_head_errors; the anchor still goes out, so
        the checker fails the file against it."""
        final = self.journal.decision_head()
        differs = self._decision_file_differs(final)
        if differs is not None:
            errors["decision file"] = differs
        for index, pin in enumerate(self.pins):
            wid, key = pin.get("witness_id"), pin.get("pubkey")
            label = wid or "(no %s witness pinned)" % ROLES[index]
            reply = self.ask_witness("decision_head", timeout=max(0.1, self.wait_seconds),
                                     index=index, **final)
            anchor = reply.get("decision_head") if isinstance(reply, dict) and reply.get("ok") else None
            if (signed_message_error(anchor) is not None or anchor.get("kind") != "decision_head"
                    or anchor.get("witness") != wid or not verify_signature(anchor, key)
                    or any(anchor.get(k) != v for k, v in final.items())):
                errors[label] = "no valid final witnessed decision head from this witness"
            else:
                anchors.append(copy.deepcopy(anchor))

    def close(self, grace_seconds: float = 0.0) -> CloseReport:
        """With a grace time, first wait for replies still due and catch up any
        witness that missed fingerprints; then close the journal, which lets
        its lock go. Final decisions are sealed and anchored in each witness's
        log after catch-up. Signed heads are then captured before
        the owner stops the witnesses. Returns a CloseReport: whether every call that ran holds
        the stamps its mode needs, and those that do not. Safe to call twice.
        The witnesses are their owner's to stop."""
        with self._lock:
            if self.closed:
                if self.crashed is not None:
                    self._check_open()
                return self._close_report
            heads, head_errors, anchors, anchor_errors = [], {}, [], {}
            try:
                if grace_seconds > 0 and self.crashed is None:
                    self.settle(grace_seconds)
                    self.catch_up(grace_seconds)
                if self.crashed is None:
                    self._decisions_sealed = True
                    self._anchor_decisions(anchors, anchor_errors)
                    self._capture_heads(heads, head_errors)
            finally:
                self._close_report = self._stamps_report()
                self._close_report.signed_heads = heads
                self._close_report.head_errors = head_errors
                self._close_report.decision_heads = anchors
                self._close_report.decision_head_errors = anchor_errors
                self._close_report.misbehaving = copy.deepcopy(self.misbehaving)
                self.journal.close()
                self.closed = True
            if self.crashed is not None:
                self._check_open()
            return self._close_report
