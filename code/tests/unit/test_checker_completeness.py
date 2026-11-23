"""Required logs and independently retained terminal heads bound Rule2 claims."""
from helpers import GateCase, read_jsonl, write_jsonl
from witnessed_gate import checker
from witnessed_gate.common import canon, chain_head


class EvidenceCompleteness(GateCase):
    def test_f14_required_logs_missing_or_empty_even_without_approvals(self):
        w = self.launch()
        self.gate(w)
        for logs in ([], [self.witness_log()], [self.dir / "missing"]):
            with self.subTest(logs=logs):
                report = checker.check_run(self.journal, logs, trusted_keys={w.witness_id: w.pubkey})
                self.assertIs(report["ok"], False)
                self.assertFalse(report["evidence_complete"])
                # no decision relies on this witness, so the missing log leaves incomplete evidence
                self.assertEqual(report["status"], "pass_incomplete_evidence")
                self.assertEqual([m["witness"] for m in report["missing_required_logs"]], [w.witness_id])

    def test_f14_pass_without_terminal_anchor_is_qualified(self):
        w = self.launch()
        self.call(self.gate(w), "c1")
        report = checker.check_run(self.journal, self.witness_log(), self.effects,
                                   trusted_keys={w.witness_id: w.pubkey})
        self.assertFalse(report["problems"], report["problems"])
        self.assertFalse(report["evidence_complete"])
        self.assertEqual(report["status"], "pass_incomplete_evidence")

    def test_f14_independently_retained_stamp_is_also_a_signed_head(self):
        w = self.launch()
        d = self.call(self.gate(w), "c1")
        report = checker.check_run(self.journal, self.witness_log(), self.effects,
                                   trusted_keys={w.witness_id: w.pubkey}, signed_heads=[d.stamp],
                                   mode="one", required_witnesses=[("main", w.witness_id)])
        # A retained stamp anchors the record chain, but not decisions.
        self.assertFalse(report["evidence_complete"], report)
        self.assertIn("decision heads", [u["input"] for u in report["unmeasured"]])

    def test_f14_unretained_refused_tail_needs_an_independent_head(self):
        w = self.launch()
        g = self.gate(w)
        self.call(g, "approved")
        c = g.propose({"call_id": "refused", "function": "f", "arguments": {}})
        g.write_in_journal(c)
        g.send_fingerprint(c)
        g.give_up(c, "refused before accepting a stamp")
        g.ask_witness("head")  # drain the refused record's late stamp
        before_close = read_jsonl(self.witness_log())
        terminal = g.close().signed_heads[0]
        kw = {"trusted_keys": {w.witness_id: w.pubkey}, "mode": "one",  # supply every independent measurement input
              "required_witnesses": [("main", w.witness_id)]}
        complete = checker.check_run(self.journal, self.witness_log(), self.effects,
                                     signed_heads=[terminal], **kw)
        self.assertFalse(complete["problems"], complete["problems"])
        self.assertTrue(complete["evidence_complete"])
        self.assertEqual(complete["status"], "pass")
        # Remove the refused record and the new close anchor together.
        write_jsonl(self.witness_log(), before_close[:-1])
        unanchored = checker.check_run(self.journal, self.witness_log(), self.effects, **kw)
        self.assertFalse(unanchored["problems"], unanchored["problems"])
        self.assertFalse(unanchored["evidence_complete"])
        anchored = checker.check_run(self.journal, self.witness_log(), self.effects,
                                     signed_heads=[terminal], **kw)
        self.assertTrue(anchored["problems"])
        self.assertFalse(anchored["evidence_complete"])
        self.assertTrue(anchored["by_check"]["Rule2"])

    def test_f14_null_slot_remains_required_and_incomplete(self):
        backup = self.launch("backup")
        g = self.gate(None, witnesses=[None, backup])
        self.call(g, "c1")
        report = checker.check_run(self.journal, self.witness_log("backup"), self.effects,
                                   catch_up_done=True, mode="both",
                                   required_witnesses=g.required_witnesses())
        self.assertFalse(report["evidence_complete"])
        self.assertTrue(report["by_check"]["StampsComplete"])
        self.assertIn("main", report["calls_missing_stamps"][0]["missing"])
        self.assertIsInstance(canon(report), str)
