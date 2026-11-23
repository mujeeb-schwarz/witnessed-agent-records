"""BenchLedger preserves the record and ledger interfaces used by the courier.
Record order, fingerprints, receipts, witness configuration and planted
line-based edits remain compatible with that interface.
"""
import unittest
from dataclasses import dataclass
from typing import Optional

from helpers import GateCase, read_jsonl, write_jsonl

from witnessed_gate import checker
from witnessed_gate.common import check_stamp
from witnessed_gate.journal import record_fingerprint
from witnessed_gate.ledger import BenchLedger

SPRINT_FIELDS = {"seq", "run_id", "t", "handover", "labels", "verdicts", "decision", "prev_fp", "fp",
                 "receipt"}


@dataclass(frozen=True)
class Record:
    """The custody.core.Record fields, defined locally so the tests need no
    external record implementation."""
    seq: int
    run_id: str
    t: int
    handover: dict
    labels: list
    verdicts: list
    decision: str
    prev_fp: str
    fp: str
    receipt: Optional[dict]


class LedgerError(Exception):
    """Stands for the bench's custody.core.LedgerError."""


def record(t, action, handover_id):
    return Record(seq=0, run_id="u1", t=t,
                  handover={"action": action, "handover_id": handover_id, "from_place": "room",
                            "to_place": "notes", "t": t},
                  labels=[], verdicts=[{"rule": 1, "verdict": "kept", "reason": ""}],
                  decision="deliver", prev_fp="", fp="", receipt=None)


class LedgerCase(GateCase):
    def setUp(self):
        super().setUp()
        self._ledgers = []

    def tearDown(self):
        for ledger in self._ledgers:
            try:
                ledger.close()
            except Exception:
                pass
        super().tearDown()

    def ledger(self, run="run", **kw):
        ledger = BenchLedger(self.dir / run, "u1", refusal_error=LedgerError, **kw)
        self._ledgers.append(ledger)
        return ledger


class Interface(LedgerCase):
    def test_write_returns_the_record_with_its_fingerprint_and_stamp(self):
        ledger = self.ledger()
        f1 = ledger.write(record(1, "send", "h1"))
        f2 = ledger.write(record(2, "send", "h2"))
        self.assertTrue(SPRINT_FIELDS <= set(f1))
        self.assertEqual((f1["seq"], f1["prev_fp"], f1["t"]), (0, "", 1))
        self.assertEqual(f2["prev_fp"], f1["fp"])
        self.assertEqual(record_fingerprint(f1), f1["fp"])  # canonical record fingerprint
        self.assertEqual(f1["receipt"]["fp"], f1["fp"])
        self.assertIsNone(check_stamp(f1["receipt"], f1["fp"], ledger.gate.keys))
        lines = read_jsonl(ledger.journal_path)
        self.assertEqual(len(lines), 2)  # one line per record, in order
        strip = lambda r: {k: v for k, v in r.items() if k != "receipt"}  # noqa: E731
        self.assertEqual([strip(r) for r in ledger.records()], [strip(x) for x in lines])
        self.assertTrue(all(x["receipt"] is None for x in lines))  # written before the stamp
        ledger.close()
        report = checker.check_run(ledger.journal_path, ledger.witness_log_path)
        self.assertFalse(report["problems"], report["problems"])
        self.assertFalse(ledger.witness.alive)

    def test_refusal_raises_the_given_error_with_the_reason(self):
        ledger = self.ledger(witness_faults={"mode": "outage"}, wait_seconds=1.0)
        with self.assertRaises(LedgerError) as caught:
            ledger.write(record(1, "send", "h1"))
        self.assertIn("witness", str(caught.exception))
        self.assertEqual(ledger.outcomes()[0]["outcome"], "refused")
        self.assertIsNone(ledger.records()[0]["receipt"])


class Witnesses(LedgerCase):
    def test_a_deletion_needs_a_stamp_like_any_other_record(self):
        ledger = self.ledger(witness_faults={"mode": "outage"}, wait_seconds=1.0)
        with self.assertRaises(LedgerError):
            ledger.write(record(1, "delete", "h1"))

    def test_with_a_backup_the_deletion_runs_on_the_backup_stamp(self):
        ledger = self.ledger(witness_faults={"mode": "outage"}, wait_seconds=1.0, backup=True)
        filled = ledger.write(record(1, "delete", "h1"))
        self.assertEqual(filled["receipt"]["witness"], ledger.backup.witness_id)
        ledger.close()
        report = checker.check_run(ledger.journal_path, ledger.witness_logs)
        self.assertIs(report["ok"], False)  # ok is true only for a complete "pass" verdict
        self.assertFalse(report["evidence_complete"])
        self.assertEqual(report["status"], "pass_incomplete_evidence")  # no decision relies on this witness; its missing evidence is incomplete
        self.assertEqual(report["problems"], [])
        self.assertTrue(report["missing_required_logs"])
        self.assertTrue(any(n.startswith("Evidence is incomplete:") for n in report["notes"]))
        self.assertEqual(len(report["calls_missing_stamps"]), 1)

    def test_with_both_witnesses_down_the_record_is_refused(self):
        ledger = self.ledger(witness_faults={"mode": "outage"}, backup_faults={"mode": "outage"},
                             wait_seconds=1.0, backup=True)
        with self.assertRaises(LedgerError):
            ledger.write(record(1, "send", "h1"))


class PlantedEdits(LedgerCase):
    def test_an_edit_by_position_is_caught(self):
        ledger = self.ledger()
        for i in range(3):
            ledger.write(record(i, "send", "h%d" % i))
        ledger.close()
        lines = read_jsonl(ledger.journal_path)
        lines[1]["decision"] = "block"  # what the bench's edit_lines does with a set-field edit
        write_jsonl(ledger.journal_path, lines)
        report = checker.check_run(ledger.journal_path, ledger.witness_log_path)
        self.assertTrue(any("record line 1" in p for p in report["by_check"]["journal"]))
        del lines[1]  # and with mode drop
        write_jsonl(ledger.journal_path, lines)
        self.assertTrue(checker.check_run(ledger.journal_path, ledger.witness_log_path)["problems"])


if __name__ == "__main__":
    unittest.main()
