"""Recovered witness state is synchronized before use, execution identities and
approval registries belong to one gate, and post-approval failures remain
visible. Tests cover fixed witness slots, exact reply sources, wait
deadlines, evidence ownership, concurrent history, bounded work, terminal
heads and record metadata.
"""
import threading
import time
from unittest.mock import patch

from helpers import GateCase, read_jsonl, write_jsonl
from witnessed_gate import checker, wire
from witnessed_gate.common import sha256_hex, verify_signature
from witnessed_gate.gate import GateCrashed, GateError, WitnessClient
from witnessed_gate.journal import Journal, JournalError
from witnessed_gate.ledger import BenchLedger
from witnessed_gate.witness import WitnessStore


def content(identity):
    return {"call_id": identity, "function": "append_effect", "arguments": {"text": "identical"}}


class RecoveredDurability(GateCase):
    def test_reopen_must_sync_uncertain_entry_and_release_lock_on_failure(self):
        state = self.dir / "store"
        fp = sha256_hex(b"uncertain")
        store = WitnessStore(state)
        with patch("witnessed_gate.witness.durable_sync", side_effect=OSError("sync failed")):
            with self.assertRaises(OSError):
                store.stamp(fp)
        store.close()
        with patch("witnessed_gate.witness.durable_sync", side_effect=OSError("recovery sync failed")) as sync:
            with self.assertRaisesRegex(OSError, "recovery sync failed"):
                reopened = WitnessStore(state, full_fsync=True)
                reopened.close()
            self.assertTrue(sync.call_args.args[1])
        with patch("witnessed_gate.witness.durable_sync", wraps=__import__(
                "witnessed_gate.witness", fromlist=["durable_sync"]).durable_sync) as sync:
            reopened = WitnessStore(state, full_fsync=True)
            try:
                sync.assert_called_once_with(reopened._fd, True)
                self.assertEqual(reopened.stamp(fp)["fp"], fp)
                self.assertEqual(reopened.size, 1)
            finally:
                reopened.close()


class ExecutionIdentity(GateCase):
    def test_unused_approval_cannot_cover_a_refused_identical_execution(self):
        g = self.gate(self.launch())
        approved = g.decide(content("framework-A"))
        registry = wire.ApprovedCalls()
        registry.add(approved.record)
        g.main.send = lambda msg: False
        refused = g.decide(content("framework-B"))
        self.assertFalse(refused.approved)
        effect = wire.effect_for_call("append_effect", content("framework-B")["arguments"], registry,
                                      execution_id="framework-B")
        self.assertIsNone(effect["record_fp"])
        self.assertEqual(effect["call_id"], "framework-B")
        self.assertEqual(len(registry), 1)
        write_jsonl(self.effects, [effect])
        report = checker.check_run(self.journal, self.witness_log(), self.effects)
        self.assertTrue(report["problems"], report)
        used = wire.effect_for_call("append_effect", content("framework-A")["arguments"], registry,
                                    execution_id="framework-A")
        self.assertEqual(used["record_fp"], approved.fp)

    def test_each_gate_owns_its_registry(self):
        a = self.gate(self.launch())
        from witnessed_gate.gate import Gate
        b = Gate(self.dir / "other.jsonl")
        self._gates.append(b)
        approved = a.decide(content("same-id"))
        a.approved_calls.add(approved.record)
        other = wire.effect_for_call("append_effect", content("same-id")["arguments"], b.approved_calls,
                                     execution_id="same-id")
        self.assertIsNone(other["record_fp"])
        self.assertEqual(len(a.approved_calls), 1)

    def test_ledger_does_not_attribute_an_unapproved_returned_record(self):
        ledger = BenchLedger(self.dir / "bench", "u1", wait_seconds=0.1)
        self.addCleanup(ledger.close)
        record = {"handover": {"action": "send", "text": "same"}}
        approved = ledger.write(record)
        refused = ledger.gate.decide(dict(record, call_id="refused-id"), wait_seconds=0)
        self.assertFalse(refused.approved)
        forged_return = dict(refused.record, call_id="refused-id")
        self.assertIsNone(ledger.effect_line(forged_return)["record_fp"])
        self.assertEqual(ledger.effect_line(approved)["record_fp"], approved["fp"])


class CatchUpFailure(GateCase):
    def fail_second_stamp(self, gate):
        append = gate.journal._dec_file.append

        def fail(raw):
            import json
            if json.loads(raw)["kind"] == "second_stamp":
                raise OSError("second stamp storage failed")
            append(raw)
        gate.journal._dec_file.append = fail
        # Make the second witness's reply deterministically arrive in catch_up.
        catch_up = gate.catch_up

        def catch(*args, **kwargs):
            gate.settle(1.0)
            return catch_up(*args, **kwargs)
        gate.catch_up = catch

    def test_durable_approval_returns_visible_error_and_every_later_operation_crashes(self):
        main, backup = self.launch(), self.launch("backup", mode="slow", delay=0.02)
        g = self.gate(None, witnesses=[main, backup], wait_seconds=0.2)
        self.fail_second_stamp(g)
        decision = g.decide(content("A"))
        self.assertTrue(decision.approved)
        self.assertEqual(len(self.decisions_of("approved")), 1)
        self.assertIn("second stamp storage failed", decision.catch_up_error)
        operations = [lambda: g.propose(content("B")), lambda: g.decide(content("B")),
                      lambda: g.connect([main, backup]), lambda: g.ask_witness("head"),
                      lambda: g.missed(main), lambda: g.catch_up(), lambda: g.settle(0),
                      lambda: g.stamps_report(), lambda: g.history(), lambda: g.required_witnesses(),
                      lambda: g.recover(), lambda: g.close()]
        for operation in operations:
            with self.subTest(operation=operation), self.assertRaises(GateCrashed):
                operation()
        self.assertTrue(g.closed)

    def test_ledger_return_exposes_catch_up_failure(self):
        ledger = BenchLedger(self.dir / "bench", "u1", backup=True,
                             backup_faults={"mode": "slow", "delay": 0.02}, wait_seconds=0.2)
        self.addCleanup(ledger._stop_witnesses)
        self.fail_second_stamp(ledger.gate)
        returned = ledger.write({"handover": {"action": "send"}})
        self.assertIn("second stamp storage failed", returned.catch_up_error)
        self.assertIsNotNone(returned["receipt"])
        with self.assertRaises(GateCrashed):
            ledger.write({"handover": {"action": "send"}})
        with self.assertRaises(GateCrashed):
            ledger.close()


class InspectFixedSlots(GateCase):
    def test_backup_without_main_stays_in_slot_one_in_both_modes(self):
        import asyncio
        from inspect_ai.tool import ToolCall, ToolCallView
        from inspect_approver.approver import OPEN_GATES, close_gates, witnessed_gate_approver
        for mode in ("both", "failover"):
            with self.subTest(mode=mode):
                path = self.dir / (mode + ".jsonl")
                approve = witnessed_gate_approver(str(path), witness_dir=None,
                    backup_witness_dir=str(self.dir / (mode + "-backup")), witness_mode=mode, wait_seconds=0.2)
                try:
                    gate, clients = OPEN_GATES[str(path)]
                    self.assertEqual(len(gate.pins), 2)
                    self.assertIsNone(gate.main)
                    self.assertIsNone(gate.main_id)
                    self.assertIs(gate.backup, clients[0])
                    self.assertTrue(gate.degraded)
                    approval = asyncio.run(approve("", ToolCall(id="tc-A", function="append_effect",
                        arguments={"text": "same"}), ToolCallView(), []))
                    self.assertEqual(approval.decision, "approve")
                    self.assertEqual(approval.metadata["witness"], gate.backup.witness_id)
                finally:
                    close_gates()


class ReplySource(GateCase):
    def test_correct_signature_requires_the_exact_source_channel(self):
        main, other = self.launch(), self.launch("other")
        g = self.gate(main)
        for n, wrong in enumerate((None, other)):
            with self.subTest(source=wrong):
                call = g.propose(content(str(n)))
                g.write_in_journal(call)
                g.send_fingerprint(call)
                source, reply = g._next(1.0)
                self.assertIs(source, main)
                self.assertIsNone(g.stamp_arrives(reply, source=wrong))
                self.assertNotIn(call.fp, g.stamps_held)
                self.assertIn(reply["id"], g._requests)
                self.assertEqual(g.stamp_arrives(reply, source=main), "held")
                g.run(call)


class ActualWaitDeadline(GateCase):
    def test_failover_request_expiry_uses_per_call_and_backup_waits(self):
        main, backup = self.launch(mode="drop"), self.launch("backup", mode="drop")
        g = self.gate(None, witnesses=[main, backup], witness_mode="failover",
                      wait_seconds=0.5, backup_wait_seconds=0.035)
        call = g.propose(content("A"))
        g.write_in_journal(call)
        g.send_fingerprint(call)
        start = time.monotonic()
        self.assertIsNotNone(g.await_stamp(call, wait_seconds=0.015))
        end = time.monotonic()
        requests = {r.slot: r for r in g._requests.values()}
        self.assertLess(requests[0].expires, start + 0.03)
        self.assertGreater(requests[1].expires, requests[0].expires + 0.025)
        self.assertLessEqual(requests[1].expires, end + 0.005)

    def test_lost_reply_after_stamping_retries_the_original_stamp_after_real_timeout(self):
        main, backup = self.launch(), self.launch("backup")
        dropped = []
        put = backup._put

        def drop_first_stamp(msg):
            if isinstance(msg, dict) and "stamp" in msg and not dropped:
                dropped.append(msg["stamp"])
                return
            put(msg)
        backup._put = drop_first_stamp
        g = self.gate(None, witnesses=[main, backup], wait_seconds=0.5)
        catch_up = g.catch_up
        g.catch_up = lambda *a, **kw: 0
        first = g.decide(content("A"), wait_seconds=0.02)
        self.assertTrue(first.approved)
        time.sleep(0.03)
        second = g.decide(content("B"), wait_seconds=0.02)
        self.assertTrue(second.approved)
        g.settle(0.03)
        self.assertEqual(len(dropped), 1)
        self.assertEqual(dropped[0]["fp"], first.fp)
        g.catch_up = catch_up
        self.assertIn((first.record["seq"], first.fp), g.missed(backup))
        self.assertEqual(g.catch_up(0.2), 1)
        original = [d["stamp"] for d in self.decisions_of("second_stamp")
                    if d["record_fp"] == first.fp and d["stamp"]["witness"] == backup.witness_id]
        self.assertEqual(original, dropped)
        self.assertEqual(len(read_jsonl(self.witness_log("backup"))), 2)


class EvidenceOwnership(GateCase):
    def test_record_name_aliases_cannot_share_a_decision_stream(self):
        bare = self.dir / "run"
        suffixed = self.dir / "run.jsonl"
        for first, second in ((bare, suffixed), (suffixed, bare)):
            with self.subTest(first=first):
                owner = Journal(first)
                try:
                    with self.assertRaisesRegex(JournalError, "another gate"):
                        alias = Journal(second)
                        alias.close()
                finally:
                    owner.close()
                # A failed partial acquisition must release every other lock.
                alias = Journal(second)
                alias.close()

    def test_a_record_cannot_own_another_journals_decision_file(self):
        owner = Journal(self.journal)
        try:
            with self.assertRaisesRegex(JournalError, "another gate"):
                alias = Journal(owner.decisions_path)
                alias.close()
        finally:
            owner.close()


class ConcurrentHistory(GateCase):
    def test_records_and_outcomes_are_each_one_consistent_snapshot(self):
        for method in ("records", "outcomes"):
            with self.subTest(method=method):
                ledger = BenchLedger(self.dir / method, "u1", wait_seconds=0.2)
                self.addCleanup(ledger.close)
                ledger.write({"handover": {"action": "send", "n": 0}})
                read, attempting, done = threading.Event(), threading.Event(), threading.Event()
                failures = []
                original = ledger.gate.journal.decisions

                def decisions():
                    snapshot = original()
                    read.set()
                    self.assertTrue(attempting.wait(1))
                    done.wait(0.08)
                    return snapshot

                def writer():
                    try:
                        if not read.wait(1):
                            raise AssertionError("reader never reached the decision read")
                        attempting.set()
                        for n in (1, 2):
                            ledger.write({"handover": {"action": "send", "n": n}})
                    except Exception as exc:
                        failures.append(exc)
                    finally:
                        done.set()
                thread = threading.Thread(target=writer)
                with patch.object(ledger.gate.journal, "decisions", decisions):
                    thread.start()
                    rows = getattr(ledger, method)()
                thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(failures, [])
                self.assertTrue(rows)
                if method == "records":
                    self.assertTrue(all(r["receipt"] is not None for r in rows), rows)
                else:
                    self.assertTrue(all(r["outcome"] == "ran" for r in rows), rows)
                self.assertEqual(len(getattr(ledger, method)()), 3)


class BoundedWork(GateCase):
    def test_stalled_witness_rejects_outbound_overflow_without_blocking(self):
        import os
        import signal
        client = self.launch()
        gate = self.gate(client, wait_seconds=0.01)
        os.kill(client._proc.pid, signal.SIGSTOP)
        client.send({"op": "head", "id": "pad", "pad": "x" * 300000})
        time.sleep(0.01)
        start = time.monotonic()
        accepted = [client.send({"op": "stamp", "id": str(n), "fp": "a" * 64}) for n in range(300)]
        self.assertIn(False, accepted)
        self.assertGreater(client._out.maxsize, 0)
        self.assertLessEqual(client._out.qsize(), client._out.maxsize)
        decision = gate.decide(content("overflow"))
        self.assertFalse(decision.approved)
        self.assertLess(time.monotonic() - start, 0.3)
        client.kill()  # closing a full queue must not wait for room in it

    def test_catch_up_checks_deadline_while_preparing_the_batch(self):
        client = self.launch()
        g = self.gate(client)
        for n in range(30):
            self.assertTrue(g.decide(content(str(n))).approved)
        for stamps in g._stamped_by.values():
            stamps.clear()
        sent = []
        client.send = lambda msg: sent.append(msg) or True
        holds = g.journal.holds_record
        checked = []

        def slow_validation(fp):
            checked.append(fp)
            time.sleep(0.005)
            return holds(fp)
        with patch.object(g.journal, "holds_record", slow_validation):
            start = time.monotonic()
            g.catch_up(0.012)
            elapsed = time.monotonic() - start
        self.assertLess(len(checked), 10)
        self.assertLessEqual(len(sent), 3)
        self.assertLess(elapsed, 0.08)


class TerminalHeads(GateCase):
    def test_ledger_close_captures_heads_after_catch_up_before_stopping(self):
        ledger = BenchLedger(self.dir / "bench", "u1", backup=True, wait_seconds=0.1,
                             close_grace_seconds=0.1)
        self.addCleanup(ledger._stop_witnesses)
        send = ledger.backup.send
        ledger.backup.send = lambda msg: False
        returned = ledger.write({"handover": {"action": "send", "text": "payload"}})
        write_jsonl(self.effects, [ledger.effect_line(returned)])
        ledger.backup.send = send
        trusted = ledger.public_keys()
        report = ledger.close()
        self.assertTrue(report.catch_up_done)
        self.assertEqual(len(report.signed_heads), 2)
        self.assertEqual(report.head_errors, {})
        self.assertEqual(ledger.signed_heads, report.signed_heads)
        self.assertFalse(ledger.witness.alive or ledger.backup.alive)
        for head, log in zip(report.signed_heads, ledger.witness_logs):
            rows = read_jsonl(log)
            self.assertEqual(head["kind"], "head")
            self.assertEqual((head["size"], head["head"]), (len(rows), rows[-1]["head"]))
            self.assertTrue(verify_signature(head, trusted[head["witness"]]))
        checked = checker.check_run(ledger.journal_path, ledger.witness_logs, self.effects,
            trusted_keys=trusted, mode=ledger.mode, required_witnesses=ledger.required_witnesses(),
            signed_heads=report.signed_heads,
            catch_up_done=report.catch_up_done)
        self.assertFalse(checked["problems"], checked)
        self.assertTrue(checked["evidence_complete"], checked)
        self.assertEqual(ledger.close().signed_heads, report.signed_heads)

    def test_invalid_terminal_head_is_exposed_as_missing_evidence(self):
        client = self.launch()
        g = self.gate(client)
        g.decide(content("A"))
        head = g.ask_witness("head")["head"]
        head["sig"] = "0" * 128
        with patch.object(g, "ask_witness", return_value={"ok": True, "head": head}):
            report = g.close()
        self.assertTrue(report.catch_up_done)
        self.assertEqual(report.signed_heads, [])
        self.assertIn(client.witness_id, report.head_errors)


class LedgerReturnMetadata(GateCase):
    def test_framework_identity_and_errors_do_not_change_the_record_fingerprint(self):
        from witnessed_gate.journal import record_fingerprint
        ledger = BenchLedger(self.dir / "bench", "u1")
        self.addCleanup(ledger.close)
        supplied = {"call_id": "same-untrusted-id", "handover": {"action": "send"}}
        first = ledger.write(supplied)
        second = ledger.write(supplied)
        self.assertNotEqual(first.call_id, second.call_id)
        self.assertEqual(first.call_id, first["fp"])
        self.assertEqual(record_fingerprint(first), first["fp"])
        self.assertIsNone(first.catch_up_error)
        self.assertTrue(first.gate_decision.approved)
        self.assertEqual(ledger.effect_line(first)["call_id"], first.call_id)


class RegistryOwnership(GateCase):
    def test_reusing_a_registry_refuses_install_and_releases_the_new_journal(self):
        from inspect_approver.approver import close_gates, witnessed_gate_approver
        registry = wire.ApprovedCalls()
        first, second = self.dir / "a.jsonl", self.dir / "b.jsonl"
        witnessed_gate_approver(str(first), registry=registry)
        try:
            with self.assertRaisesRegex(ValueError, "one gate"):
                witnessed_gate_approver(str(second), registry=registry)
            journal = Journal(second)
            journal.close()
        finally:
            close_gates()
