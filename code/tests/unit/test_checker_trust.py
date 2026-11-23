"""Independent measurement inputs and journal-local witness authority."""
from helpers import GateCase, read_jsonl, rechain_decisions, write_jsonl
from witnessed_gate import checker
from witnessed_gate.common import canon
from witnessed_gate.gate import Gate
from witnessed_gate.witness import WitnessStore


class TrustInputs(GateCase):
    def test_f7_journal_keys_are_explicitly_internal_consistency_only(self):
        w = self.launch()
        self.call(self.gate(w), "c1")
        report = checker.check_run(self.journal, self.witness_log(), self.effects)
        self.assertFalse(report["problems"], report["problems"])
        self.assertEqual(report["keys_source"], "journal")
        self.assertTrue(any("internal consistency only" in n for n in report["notes"]))

    def test_f7_trusted_inputs_and_legacy_alias(self):
        w = self.launch()
        self.call(self.gate(w), "c1")
        keys = {w.witness_id: w.pubkey}
        for key_arg in ("trusted_keys", "witness_keys"):
            report = checker.check_run(self.journal, self.witness_log(), self.effects,
                                       **{key_arg: keys}, mode="one",
                                       required_witnesses=[("main", w.witness_id)])
            self.assertFalse(report["problems"], report["problems"])
            self.assertEqual(report["keys_source"], "trusted")

    def test_f7_substituted_pins_cannot_supply_missing_trusted_keys(self):
        w = self.launch()
        self.call(self.gate(w), "c1")
        report = checker.check_run(self.journal, self.witness_log(), self.effects,
                                   trusted_keys={"independent-witness": "a" * 64})
        self.assertTrue(report["problems"])
        self.assertTrue(report["by_check"]["journal"])
        self.assertTrue(report["by_check"]["RunNeedsHeldStamp"])

    def test_f7_mode_roles_identities_and_keys_are_compared(self):
        w = self.launch()
        self.call(self.gate(w), "c1")
        for kw in ({"mode": "both"}, {"required_witnesses": ["other"]},
                   {"required_witnesses": [("backup", w.witness_id)]},
                   {"trusted_keys": {w.witness_id: "a" * 64}}):
            with self.subTest(kw=kw):
                report = checker.check_run(self.journal, self.witness_log(), self.effects, **kw)
                self.assertTrue(report["problems"])
                self.assertTrue(report["by_check"]["journal"])


class JournalAuthority(GateCase):
    def test_f11_another_journals_witness_cannot_approve_this_journal(self):
        main = self.launch()
        first = self.gate(main)
        d = self.call(first, "c1")
        other = WitnessStore(self.dir / "other")
        self.addCleanup(other.close)
        second_path = self.dir / "other-run.jsonl"
        second = Gate(second_path, witness_keys={other.witness_id: other.pubkey})
        self._gates.append(second)
        foreign = other.stamp(d.fp)
        rows = read_jsonl(self.decisions)
        approval = next(x for x in rows if x["kind"] == "approved")
        approval["stamp"] = foreign
        approval["stamp_received_ns"] = foreign["t"] + 1
        approval["wall_ns"] = foreign["t"] + 2
        write_jsonl(self.decisions, rows)
        rechain_decisions(self.decisions)
        report = checker.check_run([self.journal, second_path],
                                   [self.witness_log(), other.log_path],
                                   trusted_keys={main.witness_id: main.pubkey,
                                                 other.witness_id: other.pubkey})
        self.assertTrue(report["by_check"]["RunNeedsHeldStamp"])
        self.assertTrue(report["by_check"]["StampsOnlyFromAsked"])

    def test_f11_request_channel_history_is_explicitly_unmeasured(self):
        self.call(self.gate(self.launch()), "c1")
        report = checker.check_run(self.journal, self.witness_log(), self.effects)
        self.assertTrue(any("request/channel" in n and "not recorded" in n for n in report["notes"]))
