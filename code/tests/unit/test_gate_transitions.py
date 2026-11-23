"""Gate transitions enforce recovery at open, exclusive ownership, durable
approval and witness identity. Tests also cover concurrent decisions,
uncertain storage writes, execution binding, reply channels, retry limits,
ledger history and completion reports.
"""
import hashlib
import os
import signal
import shutil
import threading
import time
import unittest

from helpers import GateCase, read_jsonl, rechain_decisions, write_jsonl
from test_ledger import LedgerError, record

from witnessed_gate import checker
from witnessed_gate import gate as gate_module
from witnessed_gate import journal as journal_module
from witnessed_gate.common import canon_bytes, chain_head, sha256_hex
from witnessed_gate.gate import HELD, Gate, GateError, WitnessClient, WitnessGone
from witnessed_gate import witness as witness_module
from witnessed_gate.journal import Journal
from witnessed_gate.ledger import BenchLedger

try:
    from witnessed_gate import wire
except ImportError:  # leave the missing wire dependency for individual assertions to diagnose
    wire = None

GateCrashed = getattr(gate_module, "GateCrashed", Exception)
EFFECT_FIELDS = {"call_id", "exec_id", "record_fp", "function", "args_sha256", "wall_ns"}


def content(call_id):
    return {"call_id": call_id, "function": "append_effect", "arguments": {"call_id": call_id}}


class Case(GateCase):
    def held(self, g, call_id="c1"):
        """A call taken through the steps up to a held stamp, but not run."""
        c = g.propose(content(call_id))
        g.write_in_journal(c)
        g.send_fingerprint(c)
        self.assertIsNone(g.await_stamp(c, 3.0))
        return c

    def kinds_for(self, fp):
        return [d["kind"] for d in read_jsonl(self.decisions) if d.get("record_fp") == fp]

    def slow_decision_writes(self, g, seconds=0.25):
        orig = g.journal.write_decision

        def slow(kind, fields):
            time.sleep(seconds)
            return orig(kind, fields)
        g.journal.write_decision = slow

    def two(self, mode=None, main_faults=None, backup_faults=None, **kw):
        main = self.launch("witness", **(main_faults or {}))
        backup = self.launch("backup", **(backup_faults or {}))
        return self.gate(None, witnesses=[main, backup], witness_mode=mode, **kw), main, backup

    def logs(self):
        return [self.witness_log("witness"), self.witness_log("backup")]


class RecoveryOnlyAtOpen(Case):
    def test_recover_then_run_never_both_refuses_and_approves(self):
        g = self.gate(self.launch())
        c = self.held(g)
        try:
            g.recover()
        except GateError:
            pass
        try:
            g.run(c)
        except GateError:
            pass
        kinds = self.kinds_for(c.fp)
        self.assertFalse("approved" in kinds and "refused" in kinds, kinds)
        with self.assertRaises(GateError):  # recovery on an already open gate raises
            g.recover()

    def test_a_recovery_cut_short_is_finished_by_the_next_start(self):
        wc = self.launch()
        a = self.gate(wc)
        self.call(a, "c1")
        undecided = []
        for cid in ("c2", "c3"):
            c = a.propose(content(cid))
            a.write_in_journal(c)
            undecided.append(c)
        a.journal.close()
        j = Journal(self.journal)  # a restart that wrote its restart line and one refusal, then crashed
        j.write_decision("restart", {"records_seen": 3, "undecided": [c.fp for c in undecided]})
        j.write_decision("refused", {"record_seq": undecided[0].record["seq"], "record_fp": undecided[0].fp,
                                     "reason": gate_module.RECOVERY_REASON})
        j.close()
        b = self.gate(wc)
        self.assertEqual(b.recovered, [undecided[1].fp])
        for c in undecided:
            self.assertEqual(self.kinds_for(c.fp), ["refused"])
        report = checker.check_run(self.journal, self.witness_log(), self.effects)
        self.assertFalse(report["problems"], report["problems"])


class EveryTransitionTakesTheLock(Case):
    def race(self, first, second):
        errors = []

        def do(fn):
            try:
                fn()
            except GateError as exc:
                errors.append(exc)
        t1 = threading.Thread(target=do, args=(first,))
        t2 = threading.Thread(target=do, args=(second,))
        t1.start()
        time.sleep(0.05)
        t2.start()
        t1.join(10)
        t2.join(10)
        return errors

    def test_run_and_give_up_at_once_end_in_one_decision(self):
        g = self.gate(self.launch())
        c = self.held(g)
        self.slow_decision_writes(g)
        errors = self.race(lambda: g.run(c), lambda: g.give_up(c, "given up at the same moment"))
        deciding = [k for k in self.kinds_for(c.fp) if k in ("approved", "refused")]
        self.assertEqual(len(deciding), 1, deciding)
        self.assertEqual(len(errors), 1)

    def test_two_runs_at_once_approve_once(self):
        g = self.gate(self.launch())
        c = self.held(g)
        self.slow_decision_writes(g)
        errors = self.race(lambda: g.run(c), lambda: g.run(c))
        self.assertEqual(self.kinds_for(c.fp).count("approved"), 1, self.kinds_for(c.fp))
        self.assertEqual(len(errors), 1)


class OneOwnerAtATime(Case):
    def test_a_second_gate_cannot_open_a_journal_in_use(self):
        self.gate(None)
        with self.assertRaises(Exception) as caught:
            self._gates.append(Gate(self.journal))  # reached only if the open succeeds
        self.assertIn("another", str(caught.exception))

    def test_a_second_witness_cannot_open_a_state_folder_in_use(self):
        self.launch()
        with self.assertRaises(WitnessGone) as caught:
            self.launch()
        self.assertIn("another", str(caught.exception))

    def test_each_ledger_gets_its_own_witness_folders(self):
        made = []
        try:
            for run_id in ("u1", "u2"):
                made.append(BenchLedger(self.dir / "run", run_id, backup=True, refusal_error=LedgerError,
                                        wait_seconds=1.0))
            a, b = made
            self.assertNotEqual(a.witness_dir, b.witness_dir)
            self.assertNotEqual(a.backup_dir, b.backup_dir)
            self.assertTrue(all(x.witness.alive and x.backup.alive for x in made))
            for ledger in made:
                self.assertEqual(ledger.write(record(1, "send", "h1"))["receipt"]["fp"],
                                 ledger.records()[0]["fp"])
        finally:
            for ledger in made:
                ledger.close()


class UncertainWriteStopsTheGate(Case):
    def test_a_failed_sync_after_the_approval_write_poisons_the_journal(self):
        wc = self.launch()
        g = self.gate(wc)
        self.call(g, "c1")
        c = self.held(g, "c2")
        orig = journal_module.durable_sync

        def failing(fd, full=False):
            raise OSError(5, "simulated: the sync failed after the write")
        journal_module.durable_sync = failing
        raised, out = None, None
        try:
            out = g.run(c)
        except Exception as exc:  # noqa: BLE001 - the test records what reached the caller
            raised = exc
        finally:
            journal_module.durable_sync = orig
        self.assertIsNotNone(raised, "run returned %r after a failed approval write" % (out,))
        self.assertNotIn("refused", self.kinds_for(c.fp))  # no refusal appended after it
        lines = len(read_jsonl(self.journal))
        with self.assertRaises(GateCrashed):
            g.decide(content("c3"))
        self.assertEqual(len(read_jsonl(self.journal)), lines)  # nothing more appended
        g.journal.close()
        again = self.gate(wc)  # the chain still holds: the approval line reached the file
        self.assertEqual(again.recovered, [])
        report = checker.check_run(self.journal, self.witness_log(), self.effects)
        self.assertFalse(report["problems"], report["problems"])

    def test_a_failed_approval_write_leaves_the_call_for_recovery_to_refuse(self):
        wc = self.launch()
        g = self.gate(wc)
        c = self.held(g)

        def refuse(raw):
            raise OSError(28, "simulated: no space left on the device")
        g.journal._dec_file.append = refuse
        raised = None
        try:
            g.run(c)
        except Exception as exc:  # noqa: BLE001
            raised = exc
        del g.journal._dec_file.append
        self.assertIsNotNone(raised)
        with self.assertRaises(GateCrashed):
            g.decide(content("c2"))
        g.journal.close()
        again = self.gate(wc)
        self.assertEqual(again.recovered, [c.fp])
        self.assertEqual(self.kinds_for(c.fp), ["refused"])


    def test_a_failed_save_stops_the_witness_log(self):
        store = witness_module.WitnessStore(self.dir / "w_store")
        try:
            store.stamp(sha256_hex(b"first"))
            orig = witness_module.durable_sync

            def failing(fd, full=False):
                raise OSError(5, "simulated: the sync failed after the write")
            witness_module.durable_sync = failing
            try:
                with self.assertRaises(OSError):
                    store.stamp(sha256_hex(b"second"))
            finally:
                witness_module.durable_sync = orig
            with self.assertRaises(witness_module.WitnessError):  # no line after an uncertain one
                store.stamp(sha256_hex(b"third"))
        finally:
            store.close()
        reloaded = witness_module.WitnessStore(self.dir / "w_store")  # the saved list still checks
        try:
            self.assertEqual([e["fp"] for e in reloaded.entries], [sha256_hex(b"first"), sha256_hex(b"second")])
        finally:
            reloaded.close()


class WitnessIdentities(Case):
    def test_the_same_client_twice_is_refused(self):
        wc = self.launch()
        with self.assertRaises(GateError):
            self._gates.append(Gate(self.journal, witnesses=[wc, wc]))

    def test_two_witnesses_with_one_id_are_refused(self):
        a = WitnessClient.launch(self.dir / "wa", witness_id="same-id")
        self._clients.append(a)
        b = WitnessClient.launch(self.dir / "wb", witness_id="same-id")
        self._clients.append(b)
        with self.assertRaises(GateError):
            self._gates.append(Gate(self.journal, witnesses=[a, b]))

    def test_two_witnesses_with_one_key_are_refused(self):
        a = self.launch("ka")
        (self.dir / "kb").mkdir()
        shutil.copy(str(self.dir / "ka" / "signing.key"), str(self.dir / "kb" / "signing.key"))
        b = WitnessClient.launch(self.dir / "kb", witness_id="kb-id")
        self._clients.append(b)
        self.assertEqual(a.pubkey, b.pubkey)
        with self.assertRaises(GateError):
            self._gates.append(Gate(self.journal, witnesses=[a, b]))

    def test_a_backup_never_becomes_the_main_witness(self):
        blocker = self.dir / "blocker"
        blocker.write_text("a file where the main witness's folder should be\n", encoding="utf-8")
        ledger = BenchLedger(self.dir / "run", "u1", witness_dir=blocker, backup=True,
                             refusal_error=LedgerError, wait_seconds=1.0)
        try:
            pins = read_jsonl(ledger.decisions_path)[0]["witnesses"]
            self.assertEqual(len(pins), 2, pins)
            self.assertNotEqual(pins[0].get("witness_id"), ledger.backup.witness_id)
            self.assertEqual(pins[1]["witness_id"], ledger.backup.witness_id)
            self.assertIsNone(ledger.witness)
            self.assertTrue(ledger.degraded)
            filled = ledger.write(record(1, "send", "h1"))
            self.assertEqual(filled["receipt"]["witness"], ledger.backup.witness_id)
            self.assertEqual(ledger.outcomes()[0]["reason"], "stamped by the backup witness")
        finally:
            ledger.close()


class EffectsBoundToTheApprovedRecord(Case):
    def test_the_ledger_builds_the_effect_line_from_the_returned_record(self):
        ledger = BenchLedger(self.dir / "run", "u1", backup=True, refusal_error=LedgerError, wait_seconds=1.0)
        one = BenchLedger(self.dir / "run", "u2", refusal_error=LedgerError, wait_seconds=1.0)
        try:
            f1 = ledger.write(record(1, "send", "h1"))
            f2 = ledger.write(record(2, "delete", "h2"))
            e1, e2 = ledger.effect_line(f1), ledger.effect_line(f2)
            self.assertEqual(set(e1), EFFECT_FIELDS)
            self.assertEqual((e1["record_fp"], e2["record_fp"]), (f1["fp"], f2["fp"]))
            self.assertEqual((e1["function"], e2["function"]), ("send", "delete"))
            self.assertEqual(e1["args_sha256"], hashlib.sha256(canon_bytes(f1["handover"])).hexdigest())
            self.assertNotEqual(e1["exec_id"], ledger.effect_line(f1)["exec_id"])
            self.assertEqual(len(e1["exec_id"]), 32)
            self.assertEqual(list(ledger.public_keys().items()),
                             [(ledger.witness.witness_id, ledger.witness.pubkey),
                              (ledger.backup.witness_id, ledger.backup.pubkey)])
            self.assertEqual((ledger.mode, one.mode), ("both", "one"))
            self.assertFalse(ledger.degraded or one.degraded)
        finally:
            ledger.close()
            one.close()

    def test_the_registry_binds_an_effect_on_its_exact_function_and_arguments(self):
        self.assertIsNotNone(wire, "no wire module")
        reg = wire.ApprovedCalls()
        g = self.gate(self.launch())
        d = g.decide(content("c1"))
        reg.add(d.record)
        self.assertIsNone(reg.take("append_effect", {"call_id": "c1", "extra": 1}, execution_id="c1"))
        line = wire.effect_for_call("append_effect", {"call_id": "c1"}, reg, execution_id="c1")
        self.assertEqual((line["record_fp"], line["call_id"]), (d.fp, "c1"))
        again = wire.effect_for_call("append_effect", {"call_id": "c1"}, reg, execution_id="c1")  # no second approval
        self.assertIsNone(again["record_fp"])


class RepliesBoundToTheWitnessAsked(Case):
    def test_a_stamp_counts_only_from_the_witness_asked(self):
        g, main, backup = self.two(mode="failover")
        sent = []
        main.send = lambda msg: sent.append(msg) or True  # the main witness never gets it
        c = g.propose(content("c1"))
        g.write_in_journal(c)
        g.send_fingerprint(c)
        self.assertEqual([m["fp"] for m in sent], [c.fp])
        self.assertTrue(backup.send({"op": "stamp", "id": "probe", "fp": c.fp}))  # outside the gate
        source, reply = g._inbox.get(timeout=5.0)
        self.assertIs(source, backup)
        forged = dict(reply, id=sent[0]["id"])  # the backup's valid stamp, on the main's request
        self.assertNotEqual(g.stamp_arrives(forged, main), HELD)
        self.assertNotIn(c.fp, g.stamps_held)

    def test_a_second_wait_does_not_ask_the_backup_again(self):
        g, main, backup = self.two(mode="failover", main_faults={"mode": "drop"},
                                   backup_faults={"mode": "drop"}, backup_wait_seconds=0.2)
        asked = []
        orig = backup.send

        def counting(msg):
            if msg.get("op") == "stamp":
                asked.append(msg["fp"])
            return orig(msg)
        backup.send = counting
        c = g.propose(content("c1"))
        g.write_in_journal(c)
        g.send_fingerprint(c)
        self.assertIsNotNone(g.await_stamp(c, 0.2))
        self.assertIsNotNone(g.await_stamp(c, 0.2))
        self.assertEqual(asked, [c.fp])

    def test_request_ids_do_not_repeat_after_a_witness_restart(self):
        ids = []

        def recorded(client):
            orig = client.send

            def send(msg):
                if msg.get("op") == "stamp":
                    ids.append(msg["id"])
                return orig(msg)
            client.send = send
            return client
        wc = recorded(self.launch())
        g = self.gate(wc)
        self.assertEqual(self.call(g, "c1").outcome, "ran")
        wc.kill()
        g.connect(recorded(self.launch()))
        self.assertEqual(self.call(g, "c2").outcome, "ran")
        self.assertEqual(len(ids), len(set(ids)), ids)


class LostReplyIsAskedAgain(Case):
    def test_a_lost_reply_on_a_live_channel_is_asked_again_at_catch_up(self):
        g, main, backup = self.two(wait_seconds=0.3)
        backup.send = lambda msg: True  # this request never reaches the backup; the channel stays up
        d1 = self.call(g, "c1")
        self.assertEqual(d1.witness, main.witness_id)
        del backup.send
        time.sleep(0.4)  # c1's request to the backup is past its wait
        self.assertEqual(self.call(g, "c2").outcome, "ran")
        g.settle(1.0)
        g.catch_up(2.0)
        self.assertIn(d1.fp, [e["fp"] for e in read_jsonl(self.witness_log("backup"))])
        report = checker.check_run(self.journal, self.logs(), self.effects, catch_up_done=True)
        self.assertFalse(report["problems"], report["problems"])


class RecoveredStateIsValidated(Case):
    def test_a_rechained_fake_approval_does_not_reach_a_witness(self):
        wc = self.launch()
        g = self.gate(wc)
        self.call(g, "c1")
        g.close()
        wc.kill()
        fake = sha256_hex(b"a fingerprint that is no record")
        rows = read_jsonl(self.decisions)
        rows.append({"kind": "approved", "record_seq": 0, "record_fp": fake, "stamp": None,
                     "stamp_received_ns": rows[-1]["wall_ns"], "wall_ns": rows[-1]["wall_ns"] + 1})
        write_jsonl(self.decisions, rows)
        rechain_decisions(self.decisions)
        again = self.launch()
        reopened = None
        try:
            reopened = Gate(self.journal, witness=again)
            self._gates.append(reopened)
            reopened.catch_up(2.0)
        except GateError:
            pass
        self.assertNotIn(fake, [e["fp"] for e in read_jsonl(self.witness_log())])
        self.assertIsNone(reopened, "the gate opened a journal holding an approval of no record")

    def test_a_witness_refuses_to_start_on_a_log_with_a_forged_line(self):
        wc = self.launch()
        g = self.gate(wc)
        self.call(g, "c1")
        wc.stop()
        rows = read_jsonl(self.witness_log())
        last, fake = rows[-1], sha256_hex(b"forged entry")
        rows.append({"index": len(rows), "fp": fake, "prev_head": last["head"],
                     "head": chain_head(last["head"], fake), "t": last["t"] + 1,
                     "witness": last["witness"], "sig": "00" * 64})
        write_jsonl(self.witness_log(), rows)
        with self.assertRaises(WitnessGone):
            self.launch()


class SendsNeverBlockTheGate(Case):
    def test_a_witness_that_stops_reading_cannot_block_a_send_or_a_decision(self):
        wc = self.launch()
        g = self.gate(wc)
        os.kill(wc._proc.pid, signal.SIGSTOP)  # the witness stops reading; its pipe fills
        t = threading.Thread(target=wc.send, args=({"op": "head", "id": "pad", "pad": "x" * 300000},),
                             daemon=True)
        started = time.monotonic()
        t.start()
        t.join(2.0)
        self.assertFalse(t.is_alive(), "send blocked on a witness that does not read")
        d = self.call(g, "c1", wait=0.3)
        self.assertEqual(d.outcome, "refused")
        self.assertLess(time.monotonic() - started, 2.5)


class DurabilityReachesTheWitnesses(Case):
    def test_full_fsync_reaches_both_witnesses_and_the_open_line(self):
        ledger = BenchLedger(self.dir / "run", "u1", backup=True, full_fsync=True,
                             refusal_error=LedgerError, wait_seconds=1.0)
        try:
            for client in (ledger.witness, ledger.backup):
                self.assertIn("--full-fsync", client.argv)
                self.assertIs(client.hello.get("full_fsync"), True)
            self.assertIs(read_jsonl(ledger.decisions_path)[0].get("full_fsync"), True)
            ledger.write(record(1, "send", "h1"))
        finally:
            ledger.close()


class LedgerHistoryFollowsTheJournal(Case):
    def test_a_reopened_ledger_lists_every_record_of_its_journal(self):
        first = BenchLedger(self.dir / "run", "u1", refusal_error=LedgerError, wait_seconds=1.0)
        try:
            first.write(record(1, "send", "h1"))
            first.write(record(2, "send", "h2"))
        finally:
            first.close()
        second = BenchLedger(self.dir / "run", "u1", refusal_error=LedgerError, wait_seconds=1.0)
        try:
            second.write(record(3, "send", "h3"))
            lines = read_jsonl(second.journal_path)
            strip = lambda r: {k: v for k, v in r.items() if k != "receipt"}  # noqa: E731
            self.assertEqual([strip(r) for r in second.records()], [strip(x) for x in lines])
            self.assertEqual([o["outcome"] for o in second.outcomes()], ["ran"] * 3)
            self.assertTrue(all(r["receipt"]["fp"] == r["fp"] for r in second.records()))
        finally:
            second.close()


class GiveUpWithAHeldStamp(Case):
    def test_with_two_witnesses_a_held_stamp_blocks_give_up(self):
        g, main, backup = self.two()
        c = self.held(g)
        with self.assertRaises(GateError):
            g.give_up(c, "giving up while holding a stamp")
        self.assertEqual(g.run(c).outcome, "ran")

    def test_with_one_witness_gate_tla_allows_it(self):
        g = self.gate(self.launch())
        c = self.held(g)
        self.assertEqual(g.give_up(c, "Gate.tla lets the gate give up at any moment").outcome, "refused")


class CloseReportsTheCatchUp(Case):
    def test_close_lists_the_calls_that_lack_a_required_stamp(self):
        g, main, backup = self.two()
        backup.kill()
        d = self.call(g, "c1")
        report = g.close(0.3)
        self.assertFalse(report.catch_up_done)
        self.assertEqual([(m["record_fp"], m["missing"]) for m in report.missing], [(d.fp, [backup.witness_id])])
        check = checker.check_run(self.journal, self.logs(), self.effects, catch_up_done=report.catch_up_done)
        self.assertIs(check["ok"], False)  # ok is true only for a complete "pass" verdict
        self.assertFalse(check["evidence_complete"])
        self.assertEqual(check["status"], "pass_incomplete_evidence")  # no decision relies on this witness; its missing evidence is incomplete
        self.assertEqual(check["problems"], [])
        self.assertTrue(check["missing_required_logs"])
        self.assertTrue(any(n.startswith("Evidence is incomplete:") for n in check["notes"]))

    def test_close_with_every_stamp_held(self):
        g, main, backup = self.two()
        self.call(g, "c1")
        report = g.close(2.0)
        self.assertTrue(report.catch_up_done, report.missing)
        self.assertEqual(report.missing, [])


if __name__ == "__main__":
    unittest.main()
