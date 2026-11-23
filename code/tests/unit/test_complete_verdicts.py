"""Complete verdicts require independently supplied evidence. Tests cover empty
required logs, failover, degraded state at close, unique tool-call identities,
sentinel failures, cleanup errors, non-JSON refusals, expired replies,
bounded retries, send-queue diagnostics, argument validation and CLI exits.
"""
import asyncio
import contextlib
import io
import json
import os
import signal
import time
from collections import Counter
from unittest import mock

from helpers import GateCase, read_jsonl, rechain_decisions, write_jsonl
from test_ledger import LedgerError, record

from witnessed_gate import checker, wire
from witnessed_gate.common import canon
from witnessed_gate.journal import decisions_path_for
from witnessed_gate.ledger import BenchLedger


def content(call_id):
    return {"call_id": call_id, "function": "append_effect", "arguments": {"call_id": call_id}}


def inputs(report):
    return [u.get("input") for u in report.get("unmeasured") or []]


class Case(GateCase):
    def logs(self):
        return [self.witness_log("witness"), self.witness_log("backup")]

    def two(self, **kw):
        main, backup = self.launch("witness"), self.launch("backup")
        return self.gate(None, witnesses=[main, backup], **kw), main, backup

    def one_full(self, w, heads, **kw):
        """A one-witness check with every trusted input."""
        args = dict(trusted_keys={w.witness_id: w.pubkey}, mode="one",
                    required_witnesses=[("main", w.witness_id)], signed_heads=heads, catch_up_done=True)
        args.update(kw)
        return checker.check_run(self.journal, self.witness_log(), self.effects, **args)

    def kinds(self, path):
        return [d["kind"] for d in read_jsonl(decisions_path_for(path)) if d["kind"] in ("approved", "refused")]


class PassNeedsEveryInput(Case):
    def test_a_check_without_the_effects_file_is_not_a_pass(self):
        w = self.launch()
        g = self.gate(w)
        self.call(g, "c1")
        head = g.ask_witness("head")["head"]
        w.kill()
        self.assertEqual(self.call(g, "c2").outcome, "refused")
        refused = [r for r in read_jsonl(self.journal) if r["call_id"] == "c2"][0]
        with open(str(self.effects), "a", encoding="utf-8") as fh:  # a faulty runner runs c2 anyway
            fh.write(canon(wire.unbound_effect_line(*wire.record_action(refused))) + "\n")
        self.assertEqual(self.one_full(w, [head])["status"], "fail")
        without = checker.check_run(self.journal, self.witness_log(), None, trusted_keys={w.witness_id: w.pubkey},
                                    mode="one", required_witnesses=[("main", w.witness_id)],
                                    signed_heads=[head], catch_up_done=True)
        self.assertNotEqual(without["status"], "pass")
        self.assertFalse(without["evidence_complete"])
        self.assertFalse(without["ok"])
        self.assertIn("effects", inputs(without))

    def test_roles_read_from_an_edited_open_line_are_not_a_pass(self):
        g, main, backup = self.two(witness_mode="failover", wait_seconds=0.3)
        main.kill()
        self.assertEqual([self.call(g, c).witness for c in ("c1", "c2")], [backup.witness_id] * 2)
        head = g.ask_witness("head", index=1)["head"]
        g.close()
        kw = dict(trusted_keys={main.witness_id: main.pubkey, backup.witness_id: backup.pubkey},
                  mode="failover", signed_heads=[head], catch_up_done=True)
        self.assertEqual(checker.check_run(self.journal, self.logs(), self.effects, **kw)["status"], "fail")
        rows = read_jsonl(self.decisions)
        pins = rows[0]["witnesses"]
        pins[0], pins[1] = dict(pins[1], role="main"), dict(pins[0], role="backup")
        write_jsonl(self.decisions, rows)
        rechain_decisions(self.decisions)
        swapped = checker.check_run(self.journal, self.logs(), self.effects, **kw)
        self.assertNotEqual(swapped["status"], "pass")
        self.assertFalse(swapped["evidence_complete"])
        self.assertIn("required_witnesses", inputs(swapped))
        pinned = checker.check_run(self.journal, self.logs(), self.effects,
                                   required_witnesses=[("main", main.witness_id)], **kw)
        self.assertEqual(pinned["status"], "fail")
        self.assertTrue(pinned["by_check"]["journal"])

    def test_a_pending_catch_up_is_not_a_pass(self):
        g, main, backup = self.two(wait_seconds=0.3)
        self.call(g, "c1")
        g.settle(2.0)
        backup.send = lambda msg: True  # the backup never gets c2
        self.call(g, "c2")
        del backup.send
        heads = [g.ask_witness("head", index=i)["head"] for i in (0, 1)]
        kw = dict(trusted_keys={main.witness_id: main.pubkey, backup.witness_id: backup.pubkey}, mode="both",
                  signed_heads=heads, required_witnesses=[("main", main.witness_id), ("backup", backup.witness_id)])
        pending = checker.check_run(self.journal, self.logs(), self.effects, **kw)
        self.assertEqual([m["missing"] for m in pending["calls_missing_stamps"]], [[backup.witness_id]])
        self.assertNotEqual(pending["status"], "pass")
        self.assertFalse(pending["evidence_complete"])
        self.assertIn("catch_up_done", inputs(pending))
        done = checker.check_run(self.journal, self.logs(), self.effects, catch_up_done=True, **kw)
        self.assertEqual(done["status"], "fail")

    def test_the_ledger_gives_every_trusted_input_for_a_complete_pass(self):
        ledger = BenchLedger(self.dir / "bench", "u1", backup=True, wait_seconds=0.5, close_grace_seconds=0.5,
                             refusal_error=LedgerError)
        self.addCleanup(ledger._stop_witnesses)
        keys, mode, required = ledger.public_keys(), ledger.mode, ledger.required_witnesses()
        self.assertEqual(required, [("main", ledger.witness.witness_id), ("backup", ledger.backup.witness_id)])
        write_jsonl(self.effects, [ledger.effect_line(ledger.write(record(1, "send", "h1")))])
        report = ledger.close()
        res = checker.check_run(ledger.journal_path, ledger.witness_logs, self.effects, trusted_keys=keys,
                                mode=mode, required_witnesses=required, signed_heads=report.signed_heads,
                                catch_up_done=report.catch_up_done)
        self.assertEqual((res["status"], res["ok"], res.get("unmeasured")), ("pass", True, []))


class EmptyRequiredLog(Case):
    def refused_after_stamping(self, g, call_id):
        c = g.propose(content(call_id))
        g.write_in_journal(c)
        g.send_fingerprint(c)
        self.assertIsNone(g.await_stamp(c, 3.0))
        g.give_up(c, "given up holding a stamp, which Gate.tla allows with one witness")

    def after_removing_the_last_entry(self, approved_before):
        w = self.launch()
        g = self.gate(w)
        if approved_before:
            self.call(g, "c0")
        self.refused_after_stamping(g, "c1")
        write_jsonl(self.witness_log(), read_jsonl(self.witness_log())[:-1])
        return self.one_full(w, [])

    def test_removing_the_only_entry_is_incomplete_evidence(self):
        report = self.after_removing_the_last_entry(False)
        self.assertEqual(report["problems"], [])
        self.assertEqual(report["status"], "pass_incomplete_evidence")
        self.assertTrue(report.get("missing_required_logs"))

    def test_removing_a_later_entry_is_incomplete_evidence_too(self):
        report = self.after_removing_the_last_entry(True)
        self.assertEqual(report["problems"], [])
        self.assertEqual(report["status"], "pass_incomplete_evidence")

    def test_an_empty_log_that_an_approval_relies_on_fails(self):
        w = self.launch()
        self.call(self.gate(w), "c0")
        write_jsonl(self.witness_log(), [])
        report = self.one_full(w, [])
        self.assertEqual(report["status"], "fail")
        self.assertTrue(report["by_check"]["Rule1"])
        self.assertTrue(report["by_check"]["Rule2"])


class FailoverWithAnEmptyBackupLog(Case):
    def test_a_clean_failover_run_is_a_complete_pass(self):
        ledger = BenchLedger(self.dir / "bench", "u1", backup=True, witness_mode="failover", wait_seconds=0.5,
                             close_grace_seconds=0.5, refusal_error=LedgerError)
        self.addCleanup(ledger._stop_witnesses)
        keys, required = ledger.public_keys(), [("main", ledger.witness.witness_id)]
        write_jsonl(self.effects, [ledger.effect_line(ledger.write(record(i, "send", "h%d" % i))) for i in (1, 2)])
        report = ledger.close()
        self.assertEqual(len(report.signed_heads), 2)
        self.assertEqual([e.get("kind") for e in read_jsonl(ledger.witness_logs[1])], ["decision_head"])
        # The backup stamped no records, but witnessed the final decisions.
        res = checker.check_run(ledger.journal_path, ledger.witness_logs, self.effects, trusted_keys=keys,
                                mode="failover", required_witnesses=required, signed_heads=report.signed_heads,
                                catch_up_done=report.catch_up_done)
        self.assertEqual(res["problems"], [])
        self.assertEqual(res["status"], "pass", res.get("unmeasured"))
        self.assertTrue(res["evidence_complete"])
        self.assertTrue(res["ok"])

    def test_both_witnesses_down_in_failover_is_incomplete_evidence(self):
        ledger = BenchLedger(self.dir / "bench", "u1", backup=True, witness_mode="failover", wait_seconds=0.5,
                             witness_faults={"mode": "outage"}, backup_faults={"mode": "outage"},
                             refusal_error=LedgerError)
        self.addCleanup(ledger._stop_witnesses)
        keys, required = ledger.public_keys(), [("main", ledger.witness.witness_id)]
        with self.assertRaises(LedgerError):
            ledger.write(record(1, "send", "h1"))
        report = ledger.close()
        res = checker.check_run(ledger.journal_path, ledger.witness_logs, self.effects, trusted_keys=keys,
                                mode="failover", required_witnesses=required, signed_heads=report.signed_heads,
                                catch_up_done=report.catch_up_done)
        self.assertEqual(res["problems"], [])
        self.assertEqual(res["status"], "pass_incomplete_evidence")
        self.assertFalse(res["evidence_complete"])


class DegradedAtClose(Case):
    def test_degraded_keeps_the_runs_value_after_close(self):
        clean = BenchLedger(self.dir / "bench", "u1", wait_seconds=0.5, refusal_error=LedgerError)
        clean.write(record(1, "send", "h1"))
        self.assertFalse(clean.degraded)
        clean.close()
        self.assertFalse(clean.degraded)
        blocker = self.dir / "blocker"
        blocker.write_text("a file where the main witness's folder should be\n", encoding="utf-8")
        broken = BenchLedger(self.dir / "bench", "u2", witness_dir=blocker, backup=True, wait_seconds=0.5,
                             refusal_error=LedgerError)
        self.assertTrue(broken.degraded)
        broken.close()
        self.assertTrue(broken.degraded)


class ToolCallIds(Case):
    def approver(self, name="calls"):
        from inspect_approver.approver import OPEN_GATES, close_gates, witnessed_gate_approver
        path = self.dir / (name + ".jsonl")
        approve = witnessed_gate_approver(str(path), witness_dir=str(self.dir / (name + "-witness")),
                                          wait_seconds=0.5)
        self.addCleanup(close_gates)
        return approve, OPEN_GATES[str(path)][0], path

    def ask(self, approve, call_id, text="line"):
        from inspect_ai.tool import ToolCall, ToolCallView
        args = {"call_id": "same", "text": text}
        call = ToolCall(id=call_id, function="append_effect", arguments=args)
        return asyncio.run(approve("", call, ToolCallView(), [])), args

    def test_an_id_seen_before_is_refused_and_its_waiting_approval_revoked(self):
        approve, gate, path = self.approver()
        first, args = self.ask(approve, "tc-B")
        self.assertEqual(first.decision, "approve")
        gate.main.send = lambda msg: False  # the witness can no longer be reached
        second, _ = self.ask(approve, "tc-B")
        self.assertEqual(second.decision, "reject")
        # a faulty runner executes the refused call anyway, under its id
        line = wire.effect_for_call("append_effect", args, gate.approved_calls, execution_id="tc-B")
        self.assertIsNone(line["record_fp"])
        self.assertEqual([r["call_id"] for r in read_jsonl(path)], ["tc-B", "tc-B"])
        self.assertEqual(self.kinds(path), ["approved", "refused"])

    def test_a_repeated_id_on_a_later_turn_is_refused_without_an_error(self):
        approve, gate, path = self.approver()
        self.assertEqual(self.ask(approve, "tc-D")[0].decision, "approve")
        again, _ = self.ask(approve, "tc-D", text="another line")
        self.assertEqual(again.decision, "reject")
        self.assertIn("tool-call id", again.explanation)
        self.assertEqual(self.kinds(path), ["approved", "refused"])

    def test_an_empty_id_is_refused_and_journaled(self):
        approve, gate, path = self.approver()
        rejected, _ = self.ask(approve, "")
        self.assertEqual(rejected.decision, "reject")
        self.assertEqual(self.kinds(path), ["refused"])

    def test_n10_a_failing_sentinel_check_journals_the_call_and_refuses_it(self):
        approve, gate, path = self.approver()
        with mock.patch("inspect_approver.approver.sentinel_active",
                        side_effect=RuntimeError("simulated: the private check broke")):
            rejected, _ = self.ask(approve, "tc-S")
        self.assertEqual(rejected.decision, "reject")
        self.assertIn("sentinel", rejected.explanation)
        self.assertEqual([r["call_id"] for r in read_jsonl(path)], ["tc-S"])
        self.assertEqual(self.kinds(path), ["refused"])


class CloseGates(Case):
    def test_close_gates_closes_every_gate_and_reports_every_error(self):
        from inspect_approver import approver as approver_module
        paths = [self.dir / "first.jsonl", self.dir / "second.jsonl"]
        for i, p in enumerate(paths):
            approver_module.witnessed_gate_approver(str(p), witness_dir=str(self.dir / ("w%d" % i)),
                                                    wait_seconds=0.3)
        first = approver_module.OPEN_GATES[str(paths[0])][0]
        second, second_clients = approver_module.OPEN_GATES[str(paths[1])]
        first.crashed = "simulated: a catch-up write failed"
        raised = None
        try:
            approver_module.close_gates(0.1)
        except Exception as exc:  # noqa: BLE001 - the test records what close_gates raised
            raised = exc
        second_closed, still_open = second.closed, list(approver_module.OPEN_GATES)
        try:  # clean up whatever the code under test left open
            approver_module.close_gates()
        except Exception:  # noqa: BLE001
            pass
        self.assertIsNotNone(raised)
        self.assertTrue(second_closed)
        self.assertEqual(still_open, [])
        self.assertIn(str(paths[0]), getattr(raised, "errors", {}))
        self.assertIn(str(paths[1]), getattr(raised, "reports", {}))
        self.assertFalse(any(c.alive for c in second_clients))


class ContentThatIsNotJson(Case):
    def test_content_that_is_not_json_is_a_journaled_refusal(self):
        g = self.gate(self.launch())
        for value in (float("nan"), {1, 2}):
            d = g.decide({"call_id": "n", "function": "f", "arguments": {"x": value}})
            self.assertFalse(d.approved)
            self.assertIsNotNone(d.record)
            self.assertIn("not JSON", d.reason)
        self.assertEqual(len([x for x in read_jsonl(self.decisions) if x["kind"] == "refused"]), 2)
        self.assertEqual(self.call(g, "c1").outcome, "ran")  # the gate stays usable
        self.assertEqual(checker.check_run(self.journal, self.witness_log(), self.effects)["problems"], [])


class LostRepliesExpire(Case):
    def test_settle_and_close_stop_waiting_for_a_lost_reply(self):
        g, main, backup = self.two(wait_seconds=0.3)
        backup.send = lambda msg: True  # c1's request to the backup is lost; the channel stays up
        self.assertEqual(self.call(g, "c1").outcome, "ran")
        started = time.monotonic()
        g.settle(3.0)
        self.assertLess(time.monotonic() - started, 1.5)
        started = time.monotonic()
        g.close(3.0)
        self.assertLess(time.monotonic() - started, 2.5)


class FullQueueReason(Case):
    def test_a_full_send_queue_is_named_in_the_reason(self):
        w = self.launch()
        g = self.gate(w, wait_seconds=0.2)
        os.kill(w._proc.pid, signal.SIGSTOP)  # the witness stops reading; the pipe and then the queue fill
        filled = 0
        for _ in range(40):  # refill until the writer is stuck on the full pipe and the queue stays full
            while filled < 5000 and w.send({"op": "head", "id": "pad%d" % filled, "pad": "x" * 4096}):
                filled += 1
            time.sleep(0.05)
            if not w.send({"op": "head", "id": "probe", "pad": ""}):
                break
        else:
            self.fail("the send queue never stayed full")
        d = self.call(g, "c1", wait=0.2)
        self.assertEqual(d.outcome, "refused")
        self.assertIn("send queue is full", d.reason)


class CheckerArguments(Case):
    def test_documented_argument_forms_never_raise(self):
        w = self.launch()
        self.call(self.gate(w), "c1")
        for kw in ({"required_witnesses": [w.witness_id, None]}, {"signed_heads": None},
                   {"trusted_keys": w.pubkey}, {"required_witnesses": [("main",)]},
                   {"catch_up_done": "yes"}, {"mode": 3}, {"signed_heads": [None, "x"]}):
            with self.subTest(kw=kw):
                report = checker.check_run(self.journal, self.witness_log(), self.effects, **kw)
                self.assertIn(report["status"], ("fail", "pass_incomplete_evidence", "pass"))
        bad = checker.check_run(self.journal, self.witness_log(), self.effects, trusted_keys=w.pubkey)
        self.assertTrue(bad["by_check"].get("arguments"))


class CheckerCommandLine(Case):
    def run_cli(self, *argv):
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = checker.main([str(a) for a in argv])
        except SystemExit as exc:
            code = exc.code
        return code, out.getvalue()

    def test_exit_codes_follow_the_status(self):
        w = self.launch()
        g = self.gate(w)
        self.call(g, "c1")
        heads = self.dir / "heads.jsonl"
        write_jsonl(heads, g.close().signed_heads)  # complete evidence requires closure
        key = "%s=%s" % (w.witness_id, w.pubkey)
        base = [self.journal, "--witness-log", self.witness_log(), "--effects", self.effects, "--key", key]
        code, out = self.run_cli(*base)
        self.assertEqual((code, json.loads(out)["status"]), (2, "pass_incomplete_evidence"))
        code, out = self.run_cli(*base, "--signed-heads", heads, "--mode", "one",
                                 "--required-witness", "main=" + w.witness_id, "--catch-up-done")
        self.assertEqual((code, json.loads(out)["status"]), (0, "pass"))
        rows = read_jsonl(self.journal)
        rows[0]["arguments"]["text"] = "edited"
        write_jsonl(self.journal, rows)
        code, out = self.run_cli(*base)
        self.assertEqual((code, json.loads(out)["status"]), (1, "fail"))

    def test_a_key_without_an_equals_sign_is_a_usage_error(self):
        w = self.launch()
        self.call(self.gate(w), "c1")
        code, out = self.run_cli(self.journal, "--witness-log", self.witness_log(), "--key", "no-equals-sign")
        self.assertEqual(code, 3)
        self.assertEqual(out, "")


class MalformedEffectsAndMissingEvidence(Case):
    def test_n1_a_refused_records_malformed_effect_lands_under_refused_never_runs(self):
        w = self.launch()
        g = self.gate(w)
        w.kill()
        self.assertEqual(self.call(g, "c1").outcome, "refused")
        line = wire.effect_line(read_jsonl(self.journal)[0])
        line["exec_id"] = "not hex"
        write_jsonl(self.effects, [line])
        report = checker.check_run(self.journal, self.witness_log(), self.effects)
        self.assertTrue(report["by_check"]["RefusedNeverRuns"])

    def test_n3_no_journal_is_no_evidence(self):
        report = checker.check_run([])
        self.assertFalse(report["ok"])
        self.assertTrue(report["problems"])
        self.assertEqual(report["status"], "fail")


class BoundedStampRequests(Case):
    """Each call sends at most MAX_REQUESTS stamp requests to each witness,
    including when a witness replays replies or responds slowly."""

    def counted(self, client):
        sent = Counter()
        real = client.send

        def counting(msg, _real=real):
            if msg.get("op") == "stamp":
                sent[msg.get("fp")] += 1
            return _real(msg)
        client.send = counting
        return sent

    def test_bug2_a_replaying_main_witness_is_not_asked_again_and_is_named(self):
        main, backup = self.launch("witness", mode="replay"), self.launch("backup")
        sent = self.counted(main)
        g = self.gate(None, witnesses=[main, backup], witness_mode="both", wait_seconds=0.2)
        decisions = [g.decide(content("c%d" % i)) for i in range(30)]
        self.assertTrue(all(d.approved for d in decisions))
        report = g.close(0.5)
        self.assertLessEqual(sent[decisions[1].fp], 3, "requests for call 1: %d" % sent[decisions[1].fp])
        self.assertLessEqual(max(sent.values()), 3)
        self.assertIn(main.witness_id, report.misbehaving)
        self.assertGreater(report.misbehaving[main.witness_id]["unusable_replies"], 0)
        check = checker.check_run(self.journal, self.logs(), misbehaving=report.misbehaving)
        self.assertIn(main.witness_id, check.get("misbehaving_witnesses", {}))

    def test_bug3_a_slower_main_witness_gets_no_repeat_requests(self):
        main, backup = self.launch("witness", mode="slow", delay=0.03), self.launch("backup")
        sent = self.counted(main)
        g = self.gate(None, witnesses=[main, backup], witness_mode="both", wait_seconds=0.1)
        for i in range(150):  # early requests outlive their wait while the main works through its queue
            g.decide(content("c%d" % i))
            time.sleep(0.002)
        g.close(0)
        self.assertLessEqual(max(sent.values()), 3)
        self.assertEqual(sum(v - 1 for v in sent.values()), 0, "the most for one call: %d" % max(sent.values()))
