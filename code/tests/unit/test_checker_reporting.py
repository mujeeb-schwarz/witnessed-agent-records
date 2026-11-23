"""Report limitations and reject identity collapse in edited pins."""
from helpers import GateCase, read_jsonl, rechain_decisions, write_jsonl
from witnessed_gate import checker


class ReportWording(GateCase):
    def test_f21_timestamp_checks_do_not_claim_completed_durability(self):
        self.call(self.gate(self.launch()), "c1")
        report = checker.check_run(self.journal, self.witness_log(), self.effects)
        self.assertIn("timestamp", report["time_checks"])
        self.assertIn("not measured", report["time_checks"])
        self.assertTrue(any("synchronization" in n and "durability" in n for n in report["notes"]))


class DistinctPins(GateCase):
    def test_f5_duplicate_pin_ids_or_keys_are_explicit_journal_problems(self):
        self.call(self.gate(self.launch()), "c1")
        original = read_jsonl(self.decisions)
        for same_id in (True, False):
            with self.subTest(same_id=same_id):
                rows = read_jsonl(self.decisions)
                rows[0] = dict(original[0])
                pin = dict(original[0]["witnesses"][0], role="backup")
                if not same_id:
                    pin["witness_id"] = "other-id-with-same-key"
                rows[0]["witnesses"] = original[0]["witnesses"] + [pin]
                write_jsonl(self.decisions, rows)
                rechain_decisions(self.decisions)
                report = checker.check_run(self.journal, self.witness_log(), self.effects,
                                           catch_up_done=True)
                self.assertTrue(any("share" in p for p in report["by_check"]["journal"]))
