"""Shared set-up for the unit tests: a scratch folder per test, witness
processes that are always stopped, an effects file written the way a tool
writes it (the effects line, version 2, bound to the approved record), and the
re-chaining a forger would do after editing a journal."""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[2]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from witnessed_gate import wire  # noqa: E402
from witnessed_gate.common import ZERO_HASH, canon, canon_bytes, sha256_hex  # noqa: E402
from witnessed_gate.gate import Gate, WitnessClient  # noqa: E402
from witnessed_gate.journal import decisions_path_for, record_fingerprint  # noqa: E402


def read_jsonl(path):
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def write_jsonl(path, rows):
    Path(path).write_text("".join(canon(r) + "\n" for r in rows), encoding="utf-8")


def rechain_records(path):
    """Recompute every record's prev_fp and fp, as a forger who edited the
    record file would. Returns {old fp: new fp}."""
    rows, prev, moved = read_jsonl(path), "", {}
    for r in rows:
        old = r["fp"]
        r["prev_fp"] = prev
        r["fp"] = record_fingerprint(r)
        moved[old] = r["fp"]
        prev = r["fp"]
    write_jsonl(path, rows)
    return moved


def rechain_decisions(path, moved=None):
    """Recompute every decision line's prev (and record_fp, if records moved)."""
    rows, prev = read_jsonl(path), ZERO_HASH
    for n, d in enumerate(rows):
        if moved and d.get("record_fp") in moved:
            d["record_fp"] = moved[d["record_fp"]]
        d["seq"], d["prev"] = n, prev
        prev = sha256_hex(canon_bytes(d))
    write_jsonl(path, rows)


class GateCase(unittest.TestCase):
    """A scratch folder, an effects file, and witness processes stopped at the end."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="wg_test_"))
        self.effects = self.dir / "effects.jsonl"
        self.journal = self.dir / "journal" / "run.jsonl"
        self.decisions = decisions_path_for(self.journal)
        self._clients = []
        self._gates = []

    def tearDown(self):
        for g in self._gates:
            try:
                g.close()
            except Exception:
                pass
        for c in self._clients:
            try:
                c.kill()
            except Exception:
                pass
        shutil.rmtree(str(self.dir), ignore_errors=True)

    def launch(self, name="witness", **faults):
        client = WitnessClient.launch(self.dir / name, faults=faults or None)
        self._clients.append(client)
        return client

    def witness_log(self, name="witness"):
        return self.dir / name / "log.jsonl"

    def gate(self, witness=None, **kw):
        g = Gate(self.journal, witness=witness, **kw)
        self._gates.append(g)
        return g

    def call(self, gate, call_id, kind="call", wait=None):
        """One action through the gate; the tool runs, and writes its effects
        line (version 2, from the approved record), only when the gate approves."""
        d = gate.decide({"call_id": call_id, "function": "append_effect",
                         "arguments": {"call_id": call_id, "text": "line for " + call_id}},
                        kind=kind, wait_seconds=wait)
        if d.approved:
            with open(str(self.effects), "a", encoding="utf-8") as fh:
                fh.write(canon(wire.effect_line(d.record)) + "\n")
        return d

    def effects_ids(self):
        return [x["call_id"] for x in read_jsonl(self.effects)]

    def decisions_of(self, kind):
        return [d for d in read_jsonl(self.decisions) if d["kind"] == kind]
