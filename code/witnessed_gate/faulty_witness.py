"""A witness with faults, for tests and fault runs only: the hooks that the fault
runs and the bench's witness-fault runs share. Never use it as the
witness of a real run.

    python -m witnessed_gate.faulty_witness --state-dir DIR --mode MODE [--delay S] [--after N]

It is the real witness (witness.py) with one change named by --mode. It saves
exactly as the real witness does unless the fault is about saving. The first
--after N stamp requests are answered normally; the fault starts after them.

Modes:
  slow         each stamp reply leaves --delay seconds after the save
  drop         saves each fingerprint, never replies (the stamp is lost)
  outage       stops: exits at the first faulty request (the witness is down)
  malformed    replies with a line that is not JSON
  replay       answers every stamp request with the first stamp it ever made
  wrong-key    signs its stamps with a second key, not the one it announced
  wrong-fp     sends a correctly signed stamp for another fingerprint
  memory-only  keeps its list only in memory and saves nothing (Gate.tla's
               third wrong version: a restart wipes the list)
  observe      no fault: before each stamp it notes in DIR/observations.jsonl
               whether the gate's record file (--journal) already holds the
               fingerprint, a direct test of JournalBeforeSend
"""
import argparse
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from nacl.signing import SigningKey

from witnessed_gate import witness as w
from witnessed_gate.common import canon, sha256_hex, stamp_body

MODES = ("slow", "drop", "outage", "malformed", "replay", "wrong-key", "wrong-fp",
         "memory-only", "observe")


class MemoryOnlyStore(w.WitnessStore):
    """Keeps its list in memory only: nothing reaches the log file."""

    def _load(self) -> None:
        return None

    def save_line(self, line: Dict[str, Any]) -> None:
        return None


def make_responder(store: w.WitnessStore, mode: str, delay: float, after: int,
                   journal: Optional[str]):
    state = {"stamps": 0, "first": None}
    other_key = SigningKey.generate()

    def respond(req: Dict[str, Any]) -> Any:
        if req.get("op") != "stamp":
            return w.handle(store, req)
        state["stamps"] += 1
        if mode == "observe" and journal:
            fp = req.get("fp", "")
            try:
                holds = fp in Path(journal).read_text(encoding="utf-8")
            except OSError:
                holds = False
            with open(str(store.dir / "observations.jsonl"), "a", encoding="utf-8") as fh:
                fh.write(canon({"fp": fp, "journal_holds_fp": holds, "t": time.time_ns()}) + "\n")
        if state["stamps"] <= after or mode in ("observe", "memory-only"):
            reply = w.handle(store, req)
            if state["first"] is None and reply.get("ok"):
                state["first"] = reply["stamp"]
            return reply
        if mode == "outage":
            store.close()  # the folder's lock goes before the process does
            sys.exit(0)
        reply = w.handle(store, req)  # the save happens as in the real witness
        if state["first"] is None and reply.get("ok"):
            state["first"] = reply["stamp"]
        if mode == "slow":
            time.sleep(delay)
            return reply
        if mode == "drop":
            return None
        if mode == "malformed":
            return b'{"id": "' + str(req.get("id")).encode("utf-8") + b'", "ok": tru'
        if not reply.get("ok"):
            return reply
        stamp = reply["stamp"]
        if mode == "replay":
            return {"id": req.get("id"), "ok": True, "stamp": state["first"]}
        if mode == "wrong-key":
            body = {k: v for k, v in stamp.items() if k != "sig"}
            return {"id": req.get("id"), "ok": True, "stamp": store.sign_body(body, other_key)}
        if mode == "wrong-fp":
            other = sha256_hex(bytes.fromhex(stamp["fp"]))
            body = stamp_body(stamp["witness"], other, stamp["index"], stamp["head"], stamp["t"])
            return {"id": req.get("id"), "ok": True, "stamp": store.sign_body(body)}
        return reply

    return respond


def main(argv=None) -> int:
    p = w.arg_parser()
    p.add_argument("--mode", required=True, choices=MODES)
    p.add_argument("--delay", type=float, default=0.0)
    p.add_argument("--after", type=int, default=0)
    p.add_argument("--journal", default=None)
    args = p.parse_args(argv)
    cls = MemoryOnlyStore if args.mode == "memory-only" else w.WitnessStore
    try:
        store = cls(args.state_dir, args.witness_id, args.full_fsync)
    except (w.WitnessError, OSError, ValueError) as exc:
        return w.refuse_start(exc)
    try:
        w.serve(store, respond=make_responder(store, args.mode, args.delay, args.after, args.journal))
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
