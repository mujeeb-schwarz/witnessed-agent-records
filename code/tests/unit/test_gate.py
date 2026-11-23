"""The gate against Gate.tla's steps: a normal run, the witness off, bad stamps,
a give-up with a late stamp, a restart, the witness's own restart, and two
witnesses in both modes."""
import unittest

from helpers import GateCase, read_jsonl

from witnessed_gate import checker
from witnessed_gate.gate import RECOVERY_REASON


class NormalRun(GateCase):
    def test_every_effect_has_a_stamp_the_gate_held_first(self):
        g = self.gate(self.launch())
        decisions = [self.call(g, cid) for cid in ("c1", "c2", "c3")]
        self.assertTrue(all(d.outcome == "ran" for d in decisions))
        self.assertEqual(self.effects_ids(), ["c1", "c2", "c3"])
        approved = {d["record_fp"]: d for d in self.decisions_of("approved")}
        effects = read_jsonl(self.effects)
        for d, eff in zip(decisions, effects):
            line = approved[d.fp]
            self.assertEqual(line["stamp"]["fp"], d.fp)
            self.assertLessEqual(line["stamp_received_ns"], line["wall_ns"])
            self.assertLess(line["wall_ns"], eff["wall_ns"])
        log = read_jsonl(self.witness_log())
        self.assertEqual([e["fp"] for e in log], [d.fp for d in decisions])
        report = checker.check_run(self.journal, self.witness_log(), self.effects)
        self.assertFalse(report["problems"], report["problems"])


class WitnessOff(GateCase):
    def test_witness_killed_every_call_refused_no_effects(self):
        wc = self.launch()
        g = self.gate(wc)
        wc.kill()
        decisions = [self.call(g, cid) for cid in ("c1", "c2", "c3")]
        self.assertTrue(all(d.outcome == "refused" for d in decisions))
        self.assertIn("witness", decisions[0].reason)
        self.assertEqual(self.effects_ids(), [])
        self.assertEqual(len(self.decisions_of("refused")), 3)
        report = checker.check_run(self.journal, self.witness_log(), self.effects)
        self.assertIs(report["ok"], False)  # ok is true only for a complete "pass" verdict
        self.assertFalse(report["evidence_complete"])
        self.assertEqual(report["status"], "pass_incomplete_evidence")  # no decision relies on this witness; its missing evidence is incomplete
        self.assertEqual(report["problems"], [])
        self.assertTrue(report["missing_required_logs"])
        self.assertTrue(any(n.startswith("Evidence is incomplete:") for n in report["notes"]))

    def test_no_witness_at_all(self):
        g = self.gate(None)
        d = self.call(g, "c1")
        self.assertEqual(d.outcome, "refused")
        self.assertEqual(self.effects_ids(), [])

    def test_outage_mid_run(self):
        g = self.gate(self.launch(mode="outage", after=1))
        self.assertEqual(self.call(g, "c1").outcome, "ran")
        d = self.call(g, "c2", wait=2.0)
        self.assertEqual(d.outcome, "refused")
        self.assertEqual(self.effects_ids(), ["c1"])
        self.assertFalse(checker.check_run(self.journal, self.witness_log(), self.effects)["problems"])


class BadStamps(GateCase):
    def test_stamp_signed_with_another_key_is_refused(self):
        g = self.gate(self.launch(mode="wrong-key"))
        d = self.call(g, "c1")
        self.assertEqual(d.outcome, "refused")
        self.assertIn("signature does not verify", d.reason)
        self.assertEqual(self.effects_ids(), [])
        self.assertFalse(checker.check_run(self.journal, self.witness_log(), self.effects)["problems"])

    def test_witness_whose_key_is_not_the_pinned_key_is_refused(self):
        expected = self.launch("witness_a")
        pinned = expected.pubkey
        expected.stop()
        g = self.gate(self.launch("witness_b"), witness_pubkey=pinned)
        d = self.call(g, "c1")
        self.assertEqual(d.outcome, "refused")
        self.assertIn("signature does not verify", d.reason)
        self.assertEqual(self.effects_ids(), [])

    def test_stamp_for_another_fingerprint_is_refused(self):
        g = self.gate(self.launch(mode="wrong-fp"))
        d = self.call(g, "c1")
        self.assertEqual(d.outcome, "refused")
        self.assertIn("names another fingerprint", d.reason)
        self.assertEqual(self.effects_ids(), [])
        self.assertFalse(checker.check_run(self.journal, self.witness_log(), self.effects)["problems"])

    def test_replayed_old_stamp_is_refused(self):
        g = self.gate(self.launch(mode="replay", after=1))
        self.assertEqual(self.call(g, "c1").outcome, "ran")
        d = self.call(g, "c2")
        self.assertEqual(d.outcome, "refused")
        self.assertIn("names another fingerprint", d.reason)
        self.assertEqual(self.effects_ids(), ["c1"])

    def test_malformed_reply_ends_in_refusal(self):
        g = self.gate(self.launch(mode="malformed"))
        d = self.call(g, "c1", wait=0.3)
        self.assertEqual(d.outcome, "refused")
        self.assertEqual(self.effects_ids(), [])


class GiveUpThenLateStamp(GateCase):
    def test_call_stays_refused_when_its_stamp_comes_late(self):
        g = self.gate(self.launch(mode="slow", delay=0.6))
        d1 = self.call(g, "c1", wait=0.15)
        self.assertEqual(d1.outcome, "refused")
        self.assertIn("gave up waiting", d1.reason)
        self.assertGreaterEqual(g.drain(2.0), 1)
        late = [x for x in g.ignored if x.get("record_fp") == d1.fp]
        self.assertEqual(len(late), 1)
        self.assertIn("late", late[0]["why"])
        self.assertNotIn(d1.fp, g.stamps_held)
        self.assertEqual([x["record_fp"] for x in self.decisions_of("approved")], [])
        d2 = self.call(g, "c2", wait=3.0)  # the slow witness still works
        self.assertEqual(d2.outcome, "ran")
        self.assertEqual(self.effects_ids(), ["c2"])
        self.assertFalse(checker.check_run(self.journal, self.witness_log(), self.effects)["problems"])


class Restart(GateCase):
    def test_restart_refuses_every_undecided_call_and_journals_it(self):
        wc = self.launch()
        a = self.gate(wc)
        self.assertEqual(self.call(a, "c1").outcome, "ran")
        c2 = a.propose({"call_id": "c2", "function": "append_effect", "arguments": {"call_id": "c2"}})
        a.write_in_journal(c2)
        a.send_fingerprint(c2)
        self.assertIsNone(a.await_stamp(c2, 2.0))  # the stamp is held in memory, then the gate crashes
        a.journal.close()
        wc.kill()

        wb = self.launch()
        b = self.gate(wb)
        self.assertEqual(b.recovered, [c2.fp])
        restart = self.decisions_of("restart")[-1]
        self.assertEqual(restart["undecided"], [c2.fp])
        refusal = [d for d in self.decisions_of("refused") if d["record_fp"] == c2.fp]
        self.assertEqual(len(refusal), 1)
        self.assertEqual(refusal[0]["reason"], RECOVERY_REASON)
        self.assertGreater(refusal[0]["seq"], restart["seq"])

        c3 = b.propose({"call_id": "c3", "function": "append_effect", "arguments": {"call_id": "c3"}})
        b.write_in_journal(c3)  # crash before the fingerprint goes out
        b.journal.close()
        wb.kill()  # the crash stops the witness too: only one process can own its folder
        c = self.gate(self.launch())
        self.assertEqual(c.recovered, [c3.fp])
        self.assertEqual(self.call(c, "c4").outcome, "ran")

        self.assertEqual(self.effects_ids(), ["c1", "c4"])
        log_fps = [e["fp"] for e in read_jsonl(self.witness_log())]
        self.assertIn(c2.fp, log_fps)      # stamped, yet refused: Check3 still holds
        self.assertNotIn(c3.fp, log_fps)   # never sent
        report = checker.check_run(self.journal, self.witness_log(), self.effects)
        self.assertFalse(report["problems"], report["problems"])
        self.assertEqual(report["counts"]["decisions"]["restart"], 2)


class WitnessRestart(GateCase):
    def test_list_survives_and_a_held_fingerprint_gets_the_same_stamp(self):
        wc = self.launch()
        g = self.gate(wc)
        d = self.call(g, "c1")
        wc.kill()
        again = self.launch()
        self.assertEqual(again.pubkey, wc.pubkey)
        self.assertEqual(again.hello["size"], 1)
        again.send({"op": "stamp", "id": "x1", "fp": d.fp})
        reply = again.next_message(5.0)
        self.assertEqual(reply["stamp"], d.stamp)
        self.assertEqual(len(read_jsonl(self.witness_log())), 1)
        g.connect(again)
        self.assertEqual(self.call(g, "c2").outcome, "ran")

    def test_memory_only_witness_loses_its_list_and_the_checker_sees_it(self):
        wc = self.launch(mode="memory-only")
        g = self.gate(wc)
        self.assertEqual(self.call(g, "c1").outcome, "ran")
        self.assertEqual(g.ask_witness("head")["head"]["size"], 1)  # held in memory only
        wc.kill()
        again = self.launch(mode="memory-only")  # the restart
        self.assertEqual(again.hello["size"], 0)  # the list is gone
        g.connect(again)
        self.assertEqual(g.ask_witness("head")["head"]["size"], 0)
        report = checker.check_run(self.journal, self.witness_log(), self.effects)
        self.assertTrue(report["problems"])
        self.assertTrue(report["by_check"]["Rule1"])
        self.assertTrue(report["by_check"]["Rule2"])


class JournalBeforeSend(GateCase):
    def test_witness_finds_the_record_on_disk_when_the_fingerprint_arrives(self):
        g = self.gate(self.launch(mode="observe", journal=str(self.journal)))
        for cid in ("c1", "c2", "c3"):
            self.call(g, cid)
        seen = read_jsonl(self.dir / "witness" / "observations.jsonl")
        self.assertEqual(len(seen), 3)
        self.assertTrue(all(x["journal_holds_fp"] for x in seen))


class TwoWitnesses(GateCase):
    def two(self, mode=None, main_faults=None, backup_faults=None):
        main = self.launch("witness", **(main_faults or {}))
        backup = self.launch("backup", **(backup_faults or {}))
        return self.gate(None, witnesses=[main, backup], witness_mode=mode), main, backup

    def check(self, **kw):
        return checker.check_run(self.journal, [self.witness_log("witness"), self.witness_log("backup")],
                                 self.effects, **kw)

    def test_gate_pins_both_keys_and_the_mode(self):
        g, main, backup = self.two()
        opened = self.decisions_of("open")[0]
        self.assertEqual([p["pubkey"] for p in opened["witnesses"]], [main.pubkey, backup.pubkey])
        self.assertEqual(opened["witness_mode"], "both")

    def test_both_up_every_call_ends_with_two_stamps(self):
        g, main, backup = self.two()
        ds = [self.call(g, cid) for cid in ("c1", "c2", "c3")]
        self.assertTrue(all(d.outcome == "ran" for d in ds))
        g.settle(3.0)
        report = self.check(catch_up_done=True)
        self.assertFalse(report["problems"], report["problems"])
        self.assertEqual(report["calls_missing_stamps"], [])
        self.assertEqual(report["only_one_witness_holds"], [])
        self.assertEqual(report["counts"]["decisions"]["second_stamp"], 3)

    def test_main_down_calls_run_on_the_backup_and_get_the_second_stamp_at_catch_up(self):
        g, main, backup = self.two()
        main.kill()
        ds = [self.call(g, cid) for cid in ("c1", "c2")]
        self.assertEqual([d.witness for d in ds], [backup.witness_id] * 2)
        self.assertEqual(self.effects_ids(), ["c1", "c2"])
        report = self.check()
        self.assertIs(report["ok"], False)  # ok is true only for a complete "pass" verdict
        self.assertFalse(report["evidence_complete"])
        self.assertEqual(report["status"], "pass_incomplete_evidence")  # no decision relies on this witness; its missing evidence is incomplete
        self.assertEqual(report["problems"], [])
        self.assertTrue(report["missing_required_logs"])
        self.assertTrue(any(n.startswith("Evidence is incomplete:") for n in report["notes"]))
        self.assertEqual([m["missing"] for m in report["calls_missing_stamps"]], [[main.witness_id]] * 2)
        self.assertTrue(self.check(catch_up_done=True)["by_check"]["StampsComplete"])
        again = self.launch("witness")
        g.connect([again, backup])
        self.assertEqual(g.catch_up(), 2)
        report = self.check(catch_up_done=True)
        self.assertFalse(report["problems"], report["problems"])
        self.assertEqual(report["only_one_witness_holds"], [])
        self.assertEqual(len(read_jsonl(self.witness_log("witness"))), 2)

    def test_backup_down_then_back_catches_up_the_other_way(self):
        g, main, backup = self.two()
        backup.kill()
        self.assertEqual(self.call(g, "c1").witness, main.witness_id)
        again = self.launch("backup")
        g.connect([main, again])
        self.call(g, "c2")
        g.settle(3.0)
        g.catch_up()
        report = self.check(catch_up_done=True)
        self.assertFalse(report["problems"], report["problems"])
        self.assertEqual(len(read_jsonl(self.witness_log("backup"))), 2)

    def test_both_down_every_call_refused_deletions_included(self):
        g, main, backup = self.two()
        main.kill()
        backup.kill()
        ds = [self.call(g, "c1"), self.call(g, "d1", kind="delete")]
        self.assertEqual([d.outcome for d in ds], ["refused", "refused"])
        self.assertEqual(self.effects_ids(), [])
        report = self.check()
        self.assertIs(report["ok"], False)  # ok is true only for a complete "pass" verdict
        self.assertFalse(report["evidence_complete"])
        self.assertEqual(report["status"], "pass_incomplete_evidence")  # no decision relies on this witness; its missing evidence is incomplete
        self.assertEqual(report["problems"], [])
        self.assertTrue(report["missing_required_logs"])
        self.assertTrue(any(n.startswith("Evidence is incomplete:") for n in report["notes"]))

    def test_backup_stamp_with_the_wrong_key_is_refused(self):
        g, main, backup = self.two(backup_faults={"mode": "wrong-key"})
        main.kill()
        d = self.call(g, "c1")
        self.assertEqual(d.outcome, "refused")
        self.assertIn("signature does not verify", d.reason)
        self.assertEqual(self.effects_ids(), [])

    def test_failover_mode_asks_the_backup_only_after_the_wait(self):
        g, main, backup = self.two(mode="failover", main_faults={"mode": "drop", "after": 1})
        d1 = self.call(g, "c1", wait=0.3)
        self.assertEqual(d1.witness, main.witness_id)
        self.assertNotIn("backup_sent_ns", d1.times)  # the backup was never asked for c1
        self.assertEqual(read_jsonl(self.witness_log("backup")), [])
        d2 = self.call(g, "c2", wait=0.3)  # the main witness saves it but never answers
        self.assertEqual(d2.witness, backup.witness_id)
        self.assertGreaterEqual(d2.times["backup_sent_ns"] - d2.times["sent_ns"], 0.3e9)  # only after the wait
        self.assertGreater(d2.times["stamp_received_ns"], d2.times["backup_sent_ns"])
        self.assertEqual([e["fp"] for e in read_jsonl(self.witness_log("backup"))], [d2.fp])
        self.assertFalse(self.check()["problems"])

    def test_failover_catch_up_runs_towards_the_main_witness_only(self):
        g, main, backup = self.two(mode="failover")
        main.kill()
        self.assertEqual(self.call(g, "c1").witness, backup.witness_id)
        again = self.launch("witness")
        g.connect([again, backup])
        self.assertEqual(self.call(g, "c2").witness, again.witness_id)  # c1's catch-up follows at once
        report = self.check(catch_up_done=True)
        self.assertFalse(report["problems"], report["problems"])
        self.assertEqual(len(read_jsonl(self.witness_log("witness"))), 2)
        self.assertEqual(len(read_jsonl(self.witness_log("backup"))), 1)


if __name__ == "__main__":
    unittest.main()
