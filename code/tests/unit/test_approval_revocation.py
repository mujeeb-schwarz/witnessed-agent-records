"""Approval registration respects identity revocation during a decision.
Tests also cover witness-free evidence, retries after channel recovery,
request ordering per gate, queued replies, retired lost requests, journal
paths, non-JSON keys, cleanup errors and live witness diagnostics.
"""
import asyncio
import time
from collections import Counter
from pathlib import Path

from helpers import GateCase, write_jsonl

from witnessed_gate import checker, wire
from witnessed_gate.gate import Gate


def content(call_id):
    return {"call_id": call_id, "function": "append_effect", "arguments": {"call_id": call_id}}


class Case(GateCase):
    def two(self, **kw):
        main, backup = self.launch("witness"), self.launch("backup")
        return self.gate(None, witnesses=[main, backup], **kw), main, backup

    def logs(self):
        return [self.witness_log("witness"), self.witness_log("backup")]

    def second_stamps_by(self, witness_id):
        return [d["record_fp"] for d in self.decisions_of("second_stamp") if d["stamp"]["witness"] == witness_id]

    def replies(self, client, rule):
        """Pass each reply from client through rule: None drops it."""
        put = client._put

        def filtered(msg):
            out = rule(msg)
            if out is not None:
                put(out)
        client._put = filtered
        return put

    def counted(self, client):
        sent = Counter()
        real = client.send

        def counting(msg, _real=real):
            if msg.get("op") == "stamp":
                sent[msg.get("fp")] += 1
            return _real(msg)
        client.send = counting
        return sent

    @staticmethod
    def first_fp_rule(times, replace=None):
        """A reply rule for the first fingerprint stamped: drop (or replace) its
        replies `times` times, then let them through."""
        state = {"fp": None, "left": times}

        def rule(msg):
            st = msg.get("stamp") if isinstance(msg, dict) else None
            if isinstance(st, dict):
                if state["fp"] is None:
                    state["fp"] = st.get("fp")
                if st.get("fp") == state["fp"] and state["left"] > 0:
                    state["left"] -= 1
                    return replace(msg) if replace else None
            return msg
        return rule, state


class ApprovalRevocationRace(Case):
    def test_an_approval_is_never_registered_after_its_id_was_revoked(self):
        from inspect_ai.tool import ToolCall, ToolCallView
        from inspect_approver.approver import OPEN_GATES, close_gates, witnessed_gate_approver
        path = self.dir / "calls.jsonl"
        approve = witnessed_gate_approver(str(path), witness_dir=str(self.dir / "slow-witness"),
                                          witness_faults={"mode": "slow", "delay": 0.4}, wait_seconds=2.0)
        self.addCleanup(close_gates)
        gate = OPEN_GATES[str(path)][0]
        args = {"call_id": "same", "text": "line"}

        async def overlapping():
            first = asyncio.ensure_future(approve("", ToolCall(id="tc-B", function="append_effect", arguments=args),
                                                  ToolCallView(), []))
            await asyncio.sleep(0.15)  # the first is waiting for its stamp
            second = await approve("", ToolCall(id="tc-B", function="append_effect", arguments=dict(args)),
                                   ToolCallView(), [])
            return await first, second
        first, second = asyncio.run(overlapping())
        self.assertEqual(second.decision, "reject")
        self.assertEqual(len(gate.approved_calls), 0)
        line = wire.effect_for_call("append_effect", args, gate.approved_calls, execution_id="tc-B")
        self.assertIsNone(line["record_fp"])
        self.assertEqual(first.decision, "reject")


class WitnessFreeEvidence(Case):
    def test_no_witness_is_never_a_complete_pass(self):
        g = self.gate(None)
        self.assertEqual(self.call(g, "c1").outcome, "refused")
        write_jsonl(self.effects, [])
        report = checker.check_run(self.journal, [], self.effects, trusted_keys={}, mode="both",
                                   required_witnesses=[], catch_up_done=True)
        self.assertEqual(report["problems"], [])
        self.assertEqual(report["status"], "pass_incomplete_evidence")
        self.assertIn("no witnesses", [u["input"] for u in report["unmeasured"]])


class RetriesAfterChannelRecovery(Case):
    def run_calls(self, g, n, pause):
        out = []
        for i in range(n):
            out.append(self.call(g, "c%d" % i))
            time.sleep(pause)
        return out

    def test_three_lost_replies_then_a_healthy_channel_still_retrieve_the_stamp(self):
        g, main, backup = self.two(wait_seconds=0.05)
        rule, state = self.first_fp_rule(3)
        self.replies(backup, rule)
        sent = self.counted(backup)
        ds = self.run_calls(g, 8, 0.25)
        report = g.close(2.0)
        self.assertEqual(state["left"], 0)  # three replies for c0 were lost
        self.assertIn(ds[0].fp, self.second_stamps_by(backup.witness_id))
        self.assertEqual(report.missing, [])
        self.assertLessEqual(sent[ds[0].fp], 9)

    def test_one_bad_answer_then_recovery_is_asked_again(self):
        g, main, backup = self.two(wait_seconds=0.05)
        rule, state = self.first_fp_rule(1, lambda msg: {"id": msg.get("id"), "ok": False,
                                                          "error": "simulated: a transient error"})
        self.replies(backup, rule)
        ds = self.run_calls(g, 5, 0.2)
        g.close(2.0)
        self.assertEqual(state["left"], 0)
        self.assertIn(ds[0].fp, self.second_stamps_by(backup.witness_id))

    def test_a_witness_that_keeps_answering_badly_stays_excluded_and_reported(self):
        g, main, backup = self.two(wait_seconds=0.05)
        rule, state = self.first_fp_rule(100, lambda msg: {"id": msg.get("id"), "ok": False,
                                                            "error": "simulated: always wrong for this one"})
        self.replies(backup, rule)
        sent = self.counted(backup)
        ds = self.run_calls(g, 5, 0.2)
        heads = [g.ask_witness("head", index=i)["head"] for i in (0, 1)]
        report = g.close(2.0)
        self.assertLessEqual(sent[ds[0].fp], 2)
        self.assertIn(backup.witness_id, report.misbehaving)
        exhausted = getattr(report, "exhausted", None)
        self.assertIn(ds[0].fp, [x["record_fp"] for x in exhausted or []])
        check = checker.check_run(self.journal, self.logs(), self.effects,
                                  trusted_keys={main.witness_id: main.pubkey, backup.witness_id: backup.pubkey},
                                  mode="both", required_witnesses=[("main", main.witness_id),
                                                                   ("backup", backup.witness_id)],
                                  signed_heads=heads, catch_up_done=True, exhausted=exhausted)
        self.assertEqual(check["problems"], [])
        self.assertEqual(check["status"], "pass_incomplete_evidence")
        self.assertIn("exhausted", [u["input"] for u in check["unmeasured"]])


class RequestOrderPerGate(Case):
    def test_a_client_reused_by_a_reopened_gate_gets_no_repeat_without_evidence(self):
        a, main, backup = self.two(wait_seconds=0.2)
        for i in range(5):
            self.call(a, "a%d" % i)
        a.close(2.0)  # every second stamp collected
        b = self.gate(None, witnesses=[main, backup], wait_seconds=0.2)  # the same live clients
        sent, hold = Counter(), {"on": True}
        real = type(main).send.__get__(main)

        def slow(msg):
            if msg.get("op") == "stamp":
                sent[msg.get("fp")] += 1
                if hold["on"]:
                    return True  # held: its reply is still to come
            return real(msg)
        main.send = slow
        d = b.decide(content("b1"))
        self.assertEqual(d.witness, backup.witness_id)
        hold["on"] = False
        time.sleep(0.4)
        b.catch_up(1.0)
        self.assertEqual(sent[d.fp], 1)


class SettlementReplies(Case):
    def test_settle_reads_a_late_reply_already_queued(self):
        g, main, backup = self.two(wait_seconds=0.2)
        held = []
        put = self.replies(backup, lambda msg: held.append(msg) if isinstance(msg, dict) and "stamp" in msg else msg)
        d = self.call(g, "c1")
        self.assertEqual(d.witness, main.witness_id)
        time.sleep(0.3)  # the backup's request is past its wait
        put(held.pop())  # its valid reply is now in the gate's inbox
        g.settle(1.0)
        self.assertIn(d.fp, self.second_stamps_by(backup.witness_id))

    def test_a_refused_calls_request_proven_lost_is_retired(self):
        w = self.launch()
        g = self.gate(w, wait_seconds=0.2)
        w.send = lambda msg: True  # c1's request never arrives
        self.assertEqual(self.call(g, "c1").outcome, "refused")
        del w.send
        lost = [r for r in g._requests.values() if r.call is not None and r.call.record["call_id"] == "c1"]
        self.assertEqual(len(lost), 1)
        self.assertEqual(self.call(g, "c2").outcome, "ran")  # a later request is answered
        g.settle(0.5)
        self.assertNotIn(lost[0], list(g._requests.values()))


class JournalPathArguments(Case):
    def test_journal_paths_without_a_file_name_are_problems(self):
        for bad_path in ("/", ".", "", Path("/")):
            with self.subTest(path=bad_path):
                report = checker.check_run(bad_path)
                self.assertEqual(report["status"], "fail")
                self.assertTrue(report["problems"])

    def test_a_bad_mode_is_an_argument_problem(self):
        w = self.launch()
        self.call(self.gate(w), "c1")
        report = checker.check_run(self.journal, self.witness_log(), self.effects, mode="sideways")
        self.assertTrue(report["by_check"]["arguments"])


class NonJsonStandIn(Case):
    def test_a_lone_surrogate_key_is_still_journaled_and_refused(self):
        g = self.gate(self.launch())
        d = g.decide({"\ud800": 1, "call_id": "s", "function": "f"})
        self.assertFalse(d.approved)
        self.assertIsNotNone(d.record)
        self.assertEqual([x["record_fp"] for x in self.decisions_of("refused")], [d.fp])
        k = g.decide(content("k"), kind="\udfff")  # the kind is journaled too
        self.assertFalse(k.approved)
        self.assertIsNotNone(k.record)
        self.assertEqual(self.call(g, "c1").outcome, "ran")


class CleanupAndWitnessDiagnostics(Case):
    def test_close_gates_keeps_every_error_of_a_gate(self):
        from inspect_approver import approver as am
        path = self.dir / "first.jsonl"
        am.witnessed_gate_approver(str(path), witness_dir=str(self.dir / "w0"), wait_seconds=0.3)
        gate, clients = am.OPEN_GATES[str(path)]
        gate.crashed = "simulated: a catch-up write failed"
        real_stop = clients[0].stop

        def failing_stop(*a, **kw):
            real_stop(*a, **kw)
            raise RuntimeError("simulated: the stop failed")
        clients[0].stop = failing_stop
        raised = None
        try:
            am.close_gates(0.1)
        except Exception as exc:  # noqa: BLE001 - the test reads what close_gates raised
            raised = exc
        errors = (getattr(raised, "errors", None) or {}).get(str(path))
        self.assertIsInstance(errors, list)
        self.assertEqual([e["operation"] for e in errors], ["close", "stop"])
        self.assertEqual(errors[1]["client"], clients[0].witness_id)

    def test_the_live_stamps_report_lists_misbehaving_witnesses(self):
        g = self.gate(self.launch(mode="wrong-key"))
        self.assertEqual(self.call(g, "c1").outcome, "refused")
        self.assertTrue(g.stamps_report().misbehaving)
