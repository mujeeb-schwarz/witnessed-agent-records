"""The checker accepts clean runs and detects tampering with journals, witness
logs and effects files. Inclusion proofs, append-only signed heads and
evidence from multiple witnesses are checked independently.
"""
import unittest

from helpers import GateCase, read_jsonl, rechain_decisions, rechain_records, write_jsonl

from witnessed_gate import checker, wire
from witnessed_gate.common import canon, check_stamp, sha256_hex


class CheckerCase(GateCase):
    def run_three(self):
        self.wc = self.launch()
        self.g = self.gate(self.wc)
        return [self.call(self.g, cid) for cid in ("c1", "c2", "c3")]

    def check(self, **kw):
        return checker.check_run(self.journal, self.witness_log(), self.effects, **kw)


class CleanRuns(CheckerCase):
    def test_clean_run_with_approvals_and_refusals_passes(self):
        wc = self.launch()
        g = self.gate(wc)
        self.call(g, "c1")
        self.call(g, "c2")
        wc.kill()
        self.call(g, "c3")
        report = self.check()
        self.assertFalse(report["problems"], report["problems"])
        self.assertEqual(report["counts"]["decisions"], {"open": 1, "approved": 2, "refused": 1})


class TamperedJournal(CheckerCase):
    def test_edited_record_fails(self):
        self.run_three()
        rows = read_jsonl(self.journal)
        rows[0]["arguments"]["text"] = "something else"
        write_jsonl(self.journal, rows)
        report = self.check()
        self.assertTrue(report["problems"])
        self.assertTrue(any("does not match its fingerprint" in p for p in report["by_check"]["journal"]))

    def test_dropped_decision_line_fails(self):
        self.run_three()
        rows = read_jsonl(self.decisions)
        del rows[2]
        write_jsonl(self.decisions, rows)
        report = self.check()
        self.assertTrue(report["problems"])
        self.assertTrue(report["by_check"]["journal"])

    def test_rewrite_with_a_rebuilt_chain_is_caught_by_the_witness(self):
        self.run_three()
        rows = read_jsonl(self.journal)
        rows[0]["arguments"]["text"] = "something else"
        write_jsonl(self.journal, rows)
        rechain_decisions(self.decisions, rechain_records(self.journal))
        report = self.check()
        self.assertEqual(report["by_check"]["journal"], [])  # the forger's chain holds
        self.assertTrue(report["by_check"]["Check3"])          # the witness holds the old fingerprints
        self.assertTrue(report["by_check"]["Rule1"])
        self.assertTrue(report["by_check"]["RunNeedsHeldStamp"])

    def test_restart_without_its_refusal_fails(self):
        wc = self.launch()
        a = self.gate(wc)
        c = a.propose({"call_id": "c1", "function": "f", "arguments": {}})
        a.write_in_journal(c)
        a.journal.close()
        self.gate(wc)  # restart: refuses c1
        rows = [d for d in read_jsonl(self.decisions) if d["kind"] != "refused"]
        write_jsonl(self.decisions, rows)
        rechain_decisions(self.decisions)
        report = self.check()
        self.assertTrue(report["by_check"]["CrashRefusesUndecided"])


class TamperedWitnessLog(CheckerCase):
    def test_removed_entry_fails(self):
        self.run_three()
        rows = read_jsonl(self.witness_log())
        write_jsonl(self.witness_log(), rows[:-1])
        report = self.check()
        self.assertTrue(report["problems"])
        self.assertTrue(any("entries were removed" in p for p in report["by_check"]["Rule2"]))

    def test_rewritten_entry_fails(self):
        self.run_three()
        rows = read_jsonl(self.witness_log())
        rows[1]["fp"] = sha256_hex(b"another call")
        write_jsonl(self.witness_log(), rows)
        report = self.check()
        self.assertTrue(report["problems"])
        self.assertTrue(report["by_check"]["witness_log"])
        self.assertTrue(report["by_check"]["Rule2"])
        self.assertTrue(report["by_check"]["Check3"])


class TamperedEffects(CheckerCase):
    def add_effect(self, call_id, wall_ns):
        record = next((r for r in read_jsonl(self.journal) if r.get("call_id") == call_id), None)
        line = (wire.effect_line(record, wall_ns=wall_ns) if record else
                wire.unbound_effect_line("append_effect", {"call_id": call_id}))
        line["wall_ns"] = wall_ns
        with open(str(self.effects), "a", encoding="utf-8") as fh:
            fh.write(canon(line) + "\n")

    def test_effect_for_a_refused_call_fails(self):
        wc = self.launch()
        g = self.gate(wc)
        self.call(g, "c1")
        wc.kill()
        self.call(g, "c2")
        self.add_effect("c2", read_jsonl(self.effects)[-1]["wall_ns"] + 10 ** 9)
        self.assertTrue(self.check()["by_check"]["RefusedNeverRuns"])

    def test_second_effect_for_one_approval_fails(self):
        self.run_three()
        self.add_effect("c1", read_jsonl(self.effects)[-1]["wall_ns"] + 10 ** 9)
        self.assertTrue(any("second effect" in p for p in self.check()["by_check"]["Rule1"]))

    def test_effect_that_skipped_the_gate_fails(self):
        self.run_three()
        self.add_effect("x9", read_jsonl(self.effects)[-1]["wall_ns"] + 10 ** 9)
        self.assertTrue(any("did not pass the gate" in p for p in self.check()["by_check"]["Rule1"]))


class Proofs(CheckerCase):
    def test_inclusion_proof_against_the_chain(self):
        ds = self.run_three()
        reply = self.g.ask_witness("proof", fp=ds[1].fp)
        proof, head = reply["proof"], reply["head"]
        self.assertIsNone(checker.verify_inclusion(ds[1].fp, proof, head, self.g.keys))
        self.assertIsNotNone(checker.verify_inclusion(ds[0].fp, proof, head, self.g.keys))
        rebuilt = checker.inclusion_proof_from_log(checker.read_witness_log(self.witness_log()), ds[1].fp)
        self.assertEqual(rebuilt, proof)
        forged = dict(head, head="0" * 64)
        self.assertIsNotNone(checker.verify_inclusion(ds[1].fp, proof, forged, self.g.keys))

    def test_signed_heads_only_grow(self):
        self.wc = self.launch()
        self.g = self.gate(self.wc)
        self.call(self.g, "c1")
        h1 = self.g.ask_witness("head")["head"]
        self.call(self.g, "c2")
        self.call(self.g, "c3")
        h2 = self.g.ask_witness("head")["head"]
        fps = self.g.ask_witness("consistency", old_size=h1["size"])["fps"]
        self.assertIsNone(checker.verify_append_only(h1, h2, fps, self.g.keys))
        self.assertIsNotNone(checker.verify_append_only(h1, h2, list(reversed(fps)), self.g.keys))
        self.assertIn("smaller", checker.verify_append_only(h2, h1, [], self.g.keys))
        self.assertFalse(self.check(signed_heads=[h1, h2])["problems"])
        rows = read_jsonl(self.witness_log())
        write_jsonl(self.witness_log(), rows[:1])
        self.assertTrue(self.check(signed_heads=[h1, h2])["by_check"]["Rule2"])


class TwoWitnessLogs(CheckerCase):
    def test_rules_apply_per_witness(self):
        main, backup = self.launch("witness"), self.launch("backup")
        g = self.gate(None, witnesses=[main, backup])
        ds = [self.call(g, cid) for cid in ("c1", "c2")]
        g.settle(3.0)
        logs = [self.witness_log(), self.witness_log("backup")]
        self.assertFalse(checker.check_run(self.journal, logs, self.effects, catch_up_done=True)["problems"])
        self.assertIn("no key", check_stamp(dict(ds[0].stamp, witness="someone-else"), ds[0].fp, g.keys))
        rows = read_jsonl(self.witness_log("backup"))
        write_jsonl(self.witness_log("backup"), rows[:1])  # the backup's list loses its last entry
        report = checker.check_run(self.journal, logs, self.effects, catch_up_done=True)
        self.assertTrue(report["problems"])
        self.assertTrue(report["by_check"]["Rule2"])
        self.assertEqual([x["fp"] for x in report["only_one_witness_holds"]], [ds[1].fp])


if __name__ == "__main__":
    unittest.main()
