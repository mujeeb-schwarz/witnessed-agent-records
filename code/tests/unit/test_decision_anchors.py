"""Decision-chain anchors detect rewritten decisions and remain stable during
head capture. Tests also cover unused approvals, retained channels, signed
heads as evidence of channel health, settlement deadlines, claim ownership
and the limits of step-start timestamps.
"""
import copy
import time
from unittest import mock

from helpers import GateCase, read_jsonl, rechain_decisions, write_jsonl
from test_approval_revocation import Case, content
from witnessed_gate import checker, wire
from witnessed_gate.common import canon_bytes, sha256_hex
from witnessed_gate.witness import WitnessStore, stamp_from_line


def inputs(report):
    return [u['input'] for u in report['unmeasured']]


class DecisionAnchors(GateCase):
    def check(self, w, heads):
        return checker.check_run(self.journal, self.witness_log(), self.effects,
                                 trusted_keys={w.witness_id: w.pubkey}, mode='one',
                                 required_witnesses=[('main', w.witness_id)], signed_heads=heads)

    def test_refused_to_approved_without_a_key_fails_with_kept_heads(self):
        w = self.launch(mode='drop')
        g = self.gate(w, wait_seconds=0.05)
        d = self.call(g, 'deletion', kind='delete')
        self.assertFalse(d.approved)
        write_jsonl(self.effects, [])
        closed = g.close(0.1)
        self.assertEqual(self.check(w, closed.signed_heads)['status'], 'pass')
        # Rebuild the lost stamp from the saved log,
        # replace the refusal, re-chain decisions and add an effect; no key.
        entry = next(e for e in read_jsonl(self.witness_log()) if e.get('fp') == d.fp)
        rows = read_jsonl(self.decisions)
        refused = next(r for r in rows if r['kind'] == 'refused')
        refused.update(kind='approved', stamp=stamp_from_line(entry),
                       stamp_received_ns=refused['wall_ns'] - 1)
        refused.pop('reason')
        write_jsonl(self.decisions, rows)
        rechain_decisions(self.decisions)
        effect = wire.effect_line(d.record)
        effect['wall_ns'] = refused['wall_ns'] + 1
        write_jsonl(self.effects, [effect])
        checked = self.check(w, closed.signed_heads)
        self.assertEqual(checked['status'], 'fail')
        self.assertTrue(checked['by_check'].get('DecisionHeads'))
        self.assertFalse(checked['by_check']['Rule2'])  # kept witness heads still match

    def test_a_run_that_never_closed_is_incomplete_even_with_a_kept_head(self):
        w = self.launch()
        g = self.gate(w)
        self.call(g, 'c1')
        heads = [g.ask_witness('head')['head']]
        checked = self.check(w, heads)
        self.assertEqual(checked['problems'], [])
        self.assertEqual(checked['status'], 'pass_incomplete_evidence')
        self.assertIn('decision heads', inputs(checked))

    def test_close_reports_anchors_and_proofs_cross_them_after_reload(self):
        w = self.launch()
        g = self.gate(w)
        d = self.call(g, 'c1')
        old_head = g.ask_witness('head')['head']
        closed = g.close()
        anchors = getattr(closed, 'decision_heads', [])
        self.assertEqual(len(anchors), 1)
        self.assertEqual(anchors[0]['decision_hash'], sha256_hex(canon_bytes(read_jsonl(self.decisions)[-1])))
        self.assertEqual(anchors[0]['length'], len(read_jsonl(self.decisions)))
        self.assertEqual(self.check(w, closed.signed_heads)['status'], 'pass')
        proof = checker.inclusion_proof_from_log(read_jsonl(self.witness_log()), d.fp)
        self.assertIsNone(checker.verify_inclusion(d.fp, proof, closed.signed_heads[0], g.keys))
        w.kill()
        again = self.launch()
        reopened = self.gate(again)
        proof = reopened.ask_witness('proof', fp=d.fp)
        self.assertIsNone(checker.verify_inclusion(d.fp, proof['proof'], proof['head'], g.keys))
        consistency = reopened.ask_witness('consistency', old_size=old_head['size'])
        self.assertIsNone(checker.verify_append_only(old_head, consistency['head'], consistency['fps'], g.keys))
        second_close = reopened.close()
        self.assertEqual(len(second_close.decision_heads), 1)
        self.assertEqual(self.check(again, second_close.signed_heads)['status'], 'pass')

    def test_a_late_second_stamp_during_head_capture_does_not_change_the_anchor(self):
        main, backup = self.launch(), self.launch('backup')
        g = self.gate(None, witnesses=[main, backup], wait_seconds=0.1)
        held = []
        put = backup._put
        def hold(msg):
            if isinstance(msg, dict) and 'stamp' in msg:
                held.append(msg)
            else:
                put(msg)
        backup._put = hold
        self.call(g, 'c1')
        g.ask_witness('head', index=1)  # guarantees the stamp was produced and held
        real = main.send
        def release(msg):
            if msg.get('op') == 'decision_head':
                for reply in held:
                    put(reply)
                held.clear()
            return real(msg)
        main.send = release
        closed = g.close()
        report = checker.check_run(self.journal, [self.witness_log(), self.witness_log('backup')], self.effects,
                                   trusted_keys=g.keys, mode='both', required_witnesses=g.required_witnesses(),
                                   signed_heads=closed.signed_heads)
        self.assertEqual(len(getattr(closed, 'decision_heads', [])), 2)
        self.assertFalse(report['by_check'].get('DecisionHeads'))

    def test_an_anchor_request_that_was_not_saved_is_incomplete_and_reported(self):
        w = self.launch()
        g = self.gate(w)
        self.call(g, 'c1')
        send = w.send
        w.send = lambda msg: True if msg.get('op') == 'decision_head' else send(msg)
        closed = g.close()
        self.assertEqual(closed.decision_heads, [])
        self.assertIn(w.witness_id, closed.decision_head_errors)
        checked = self.check(w, closed.signed_heads)
        self.assertEqual(checked['status'], 'pass_incomplete_evidence')
        self.assertIn('decision heads', inputs(checked))

    def test_decision_anchor_content_is_signed_and_reload_rejects_tampering(self):
        from witnessed_gate.witness import WitnessError
        w = self.launch()
        g = self.gate(w)
        self.call(g, 'c1')
        closed = g.close()
        w.kill()
        rows = read_jsonl(self.witness_log())
        rows[-1]['decision_hash'] = 'f' * 64
        write_jsonl(self.witness_log(), rows)
        self.assertEqual(self.check(w, closed.signed_heads)['status'], 'fail')
        with self.assertRaises(WitnessError):
            WitnessStore(self.dir / 'witness')


    def test_stamp_and_decision_leaves_cannot_duplicate_each_others_fingerprint(self):
        from witnessed_gate.common import decision_head_fp
        from witnessed_gate.witness import WitnessError
        for anchor_first in (True, False):
            with self.subTest(anchor_first=anchor_first):
                store = WitnessStore(self.dir / ('store-%s' % anchor_first))
                try:
                    fp = decision_head_fp('a' * 64, 1, 'b' * 64)
                    if anchor_first:
                        store.decision_head('a' * 64, 1, 'b' * 64)
                        with self.assertRaises(WitnessError):
                            store.stamp(fp)
                    else:
                        store.stamp(fp)
                        with self.assertRaises(WitnessError):
                            store.decision_head('a' * 64, 1, 'b' * 64)
                    self.assertEqual(store.size, 1)
                finally:
                    store.close()
                reopened = WitnessStore(store.dir)
                reopened.close()

    def test_decision_head_proof_and_repeated_anchor_are_consistent(self):
        store = WitnessStore(self.dir / 'store')
        self.addCleanup(store.close)
        first = store.decision_head('a' * 64, 1, 'b' * 64)
        self.assertEqual(first, store.decision_head('a' * 64, 1, 'b' * 64))
        self.assertEqual(store.size, 1)
        proof = store.inclusion_proof(first['fp'])
        self.assertIsNone(checker.verify_inclusion(first['fp'], proof, store.signed_head(), store.pubkey))


class ApprovalEffects(GateCase):
    def test_removing_a_delivered_calls_effect_is_incomplete_evidence(self):
        w = self.launch()
        g = self.gate(w)
        self.call(g, 'c1')
        self.call(g, 'c2')
        closed = g.close()
        kw = dict(trusted_keys=g.keys, mode='one', required_witnesses=g.required_witnesses(),
                  signed_heads=closed.signed_heads, catch_up_done=True)
        self.assertEqual(checker.check_run(self.journal, self.witness_log(), self.effects, **kw)['status'], 'pass')
        effects = read_jsonl(self.effects)
        write_jsonl(self.effects, effects[1:])
        checked = checker.check_run(self.journal, self.witness_log(), self.effects, **kw)
        self.assertEqual(checked['problems'], [])
        self.assertEqual(checked['status'], 'pass_incomplete_evidence')
        missing = next(u for u in checked['unmeasured'] if u['input'] == 'approvals without effect')
        self.assertEqual(missing['fingerprints'], [effects[0]['record_fp']])

    def test_an_empty_effects_file_does_not_complete_an_unused_approval(self):
        w = self.launch()
        g = self.gate(w)
        d = g.decide(content('unused'))
        self.assertTrue(d.approved)
        closed = g.close()
        write_jsonl(self.effects, [])
        checked = checker.check_run(self.journal, self.witness_log(), self.effects,
                                   trusted_keys=g.keys, mode='one', required_witnesses=g.required_witnesses(),
                                   signed_heads=closed.signed_heads)
        self.assertEqual(checked['status'], 'pass_incomplete_evidence')
        self.assertIn('approvals without effect', inputs(checked))


class RetainedChannel(Case):
    def retained_recovers(self, bad):
        g, main, backup = self.two(wait_seconds=0.03)
        replace = (lambda msg: {'id': msg['id'], 'ok': False, 'error': 'transient'}) if bad else None
        rule, state = self.first_fp_rule(1, replace)
        self.replies(backup, rule)
        sent = self.counted(backup)
        first = self.call(g, 'c0')
        g.drain(0.1)
        self.assertEqual(state['left'], 0)
        attempts = g._sent[(backup, first.fp)]
        old_request = attempts['last']
        prefix, total = backup.id_prefix, attempts['total']
        main.kill()
        replacement = self.launch('witness')
        g.connect([replacement, backup])
        self.call(g, 'c1')
        g.settle(0.1)
        g.catch_up(0.5)
        self.assertIn(first.fp, self.second_stamps_by(backup.witness_id))
        self.assertEqual(backup.id_prefix, prefix)
        self.assertIs(g._sent[(backup, first.fp)], attempts)
        self.assertEqual(attempts['last'].generation, old_request.generation)
        self.assertGreater(attempts['total'], total)
        self.assertEqual(attempts['total'], sent[first.fp])
        self.assertLessEqual(attempts['total'], 9)

    def test_an_outstanding_lost_request_recovers_when_only_the_other_slot_is_replaced(self):
        self.retained_recovers(bad=False)

    def test_a_transient_bad_answer_recovers_when_only_the_other_slot_is_replaced(self):
        self.retained_recovers(bad=True)


class HeadProvesHealth(Case):
    def needs_retry(self, bad):
        g, main, backup = self.two(wait_seconds=0.03)
        replace = (lambda msg: {'id': msg['id'], 'ok': False, 'error': 'transient'}) if bad else None
        rule, state = self.first_fp_rule(1, replace)
        self.replies(backup, rule)
        d = self.call(g, 'c0')
        g.drain(0.1)
        self.assertEqual(state['left'], 0)
        req = g._sent[(backup, d.fp)]['last']
        return g, backup, d, req

    def test_a_verified_head_rearms_a_transient_bad_answer(self):
        g, backup, d, req = self.needs_retry(bad=True)
        reply = g.ask_witness('head', index=1)
        self.assertTrue(reply['ok'])
        g.catch_up(0.3)
        self.assertIn(d.fp, self.second_stamps_by(backup.witness_id))
        self.assertGreater(g._valid_answered[(backup, req.generation)], req.order)

    def test_a_later_verified_head_proves_an_expired_request_lost(self):
        g, backup, d, req = self.needs_retry(bad=False)
        g.ask_witness('head', index=1)
        self.assertTrue(g._proven_lost(req, time.monotonic()))
        g.catch_up(0.3)
        self.assertIn(d.fp, self.second_stamps_by(backup.witness_id))

    def test_an_invalid_head_does_not_rearm_and_a_valid_head_after_it_does(self):
        g, backup, d, req = self.needs_retry(bad=True)
        def corrupt(msg):
            if isinstance(msg, dict) and isinstance(msg.get('head'), dict):
                msg = copy.deepcopy(msg)
                msg['head']['sig'] = '0' * 128
            return msg
        self.replies(backup, corrupt)
        g.ask_witness('head', index=1)
        g.catch_up(0.1)
        self.assertNotIn(d.fp, self.second_stamps_by(backup.witness_id))
        self.assertLessEqual(g._valid_answered.get((backup, req.generation), 0), req.order)
        # Remove only the corruption wrapper; the first-fingerprint rule remains.
        # Its original _put is the bound client method, safe after the one bad answer.
        del backup._put
        g.ask_witness('head', index=1)
        g.catch_up(0.3)
        self.assertIn(d.fp, self.second_stamps_by(backup.witness_id))

    def test_a_verified_head_arriving_after_its_timeout_still_proves_health(self):
        g, backup, d, req = self.needs_retry(bad=True)
        held = []
        put = self.replies(backup, lambda msg: held.append(msg) if isinstance(msg, dict) and 'head' in msg else msg)
        self.assertIsNone(g.ask_witness('head', index=1, timeout=0.03))
        self.assertEqual(len(held), 1)
        del backup._put
        put(held[0])
        g.drain(0.02)
        g.catch_up(0.3)
        self.assertIn(d.fp, self.second_stamps_by(backup.witness_id))

    def test_an_older_verified_head_cannot_rearm_a_newer_bad_answer(self):
        g, main, backup = self.two(wait_seconds=0.03)
        held = []
        put = self.replies(backup, lambda msg: held.append(msg) if isinstance(msg, dict) and 'head' in msg else msg)
        self.assertIsNone(g.ask_witness('head', index=1, timeout=0.03))
        del backup._put
        rule, state = self.first_fp_rule(1, lambda msg: {'id': msg['id'], 'ok': False, 'error': 'transient'})
        self.replies(backup, rule)
        d = self.call(g, 'c0')
        g.drain(0.1)
        put(held[0])
        g.drain(0.02)
        g.catch_up(0.1)
        self.assertNotIn(d.fp, self.second_stamps_by(backup.witness_id))
        g.ask_witness('head', index=1)
        g.catch_up(0.3)
        self.assertIn(d.fp, self.second_stamps_by(backup.witness_id))


class FiniteSettlement(GateCase):
    def flood(self, close):
        w = self.launch()
        g = self.gate(w)
        # Deterministic continuous producer: every read immediately has another
        # message. A finite fail-safe prevents the test from hanging.
        state = {'reads': 0, 'now': 0.0}
        item = (w, {'id': 'unsolicited', 'ok': False})
        g._inbox.put(item)
        def next_message(timeout):
            state['reads'] += 1
            if state['reads'] > 256:
                raise AssertionError('settlement never checked its deadline during a continuous stream')
            state['now'] += 0.001
            return item
        with mock.patch.object(g, '_next', side_effect=next_message), \
                mock.patch('witnessed_gate.gate.time.monotonic', side_effect=lambda: state['now']), \
                mock.patch.object(g, 'ask_witness', return_value=None):
            if close:
                g.close(grace_seconds=0.005)
            else:
                g.settle(0.005)
        self.assertLessEqual(state['reads'], 64)
        self.assertLessEqual(state['now'], 0.065)  # allow floating-point addition's rounding
        if close:
            self.assertTrue(g.closed)

    def test_settlement_checks_its_deadline_despite_continuous_messages(self):
        self.flood(close=False)

    def test_close_finishes_despite_continuous_messages(self):
        self.flood(close=True)


class ClaimOwnership(GateCase):
    def test_a_claimed_identity_requires_its_token_even_when_none_is_supplied(self):
        registry = wire.ApprovedCalls()
        token = registry.claim('claimed')
        record = dict(content('claimed'), fp='a' * 64)
        self.assertFalse(registry.add(record))
        self.assertFalse(registry.add(record, object()))
        self.assertEqual(len(registry), 0)
        self.assertTrue(registry.add(record, token))
        self.assertEqual(len(registry), 1)

    def test_unclaimed_bench_identities_stay_tokenless_and_revoked_claims_stay_dead(self):
        registry = wire.ApprovedCalls()
        self.assertTrue(registry.add(dict(content('bench'), fp='b' * 64)))
        token = registry.claim('revoked')
        registry.revoke('revoked')
        self.assertFalse(registry.add(dict(content('revoked'), fp='c' * 64), token))
        self.assertFalse(registry.add(dict(content('revoked'), fp='c' * 64)))
        token = registry.claim('owned')
        self.assertFalse(registry.add(dict(content('owned'), fp='d' * 64)))
        self.assertTrue(registry.add(dict(content('owned'), fp='d' * 64), token))


class TimestampScope(GateCase):
    def test_replay_and_delayed_writes_preserve_capture_order_and_explain_the_limit(self):
        import json
        main, backup = self.launch(mode='replay'), self.launch('backup', mode='replay')
        g = self.gate(None, witnesses=[main, backup], wait_seconds=0.1)
        persisted = set()
        append = g.journal._rec_file.append
        def delayed_append(raw):
            time.sleep(0.002)  # delay after wall_ns capture, before durable append
            append(raw)
            persisted.add(json.loads(raw)['fp'])
        for client in (main, backup):
            send = client.send
            def checked_send(msg, real=send):
                if msg.get('op') == 'stamp':
                    self.assertIn(msg['fp'], persisted)
                return real(msg)
            client.send = checked_send
        with mock.patch.object(g.journal._rec_file, 'append', side_effect=delayed_append):
            decisions = [self.call(g, 'c%d' % i) for i in range(12)]
        self.assertTrue(decisions[0].approved)
        self.assertTrue(all(not d.approved for d in decisions[1:]))
        closed = g.close(0.1)
        checked = checker.check_run(self.journal, [self.witness_log(), self.witness_log('backup')], self.effects,
                                   trusted_keys=g.keys, mode='both', required_witnesses=g.required_witnesses(),
                                   signed_heads=closed.signed_heads)
        self.assertEqual(checked['by_check']['JournalBeforeSend'], [])
        self.assertEqual(checked['status'], 'pass')
        self.assertIn('JournalBeforeSend', checked['time_checks'])

    def test_a_clock_adjustment_can_flag_a_correct_write_then_send_order(self):
        w = self.launch()
        g = self.gate(w)
        call = g.propose(content('clock-step'))
        # Simulate a wall clock stepping backwards between journal capture and
        # witness capture. The real child witness keeps the current wall clock.
        with mock.patch('witnessed_gate.journal.time.time_ns', return_value=10 ** 30):
            g.write_in_journal(call)
        self.assertTrue(g.send_fingerprint(call))
        self.assertIsNone(g.await_stamp(call))
        g.give_up(call, 'one-witness model permits refusal while holding a stamp')
        write_jsonl(self.effects, [])
        closed = g.close()
        checked = checker.check_run(self.journal, self.witness_log(), self.effects,
                                   trusted_keys=g.keys, mode='one', required_witnesses=g.required_witnesses(),
                                   signed_heads=closed.signed_heads)
        failed = {name for name, problems in checked['by_check'].items() if problems}
        self.assertEqual(failed, {'JournalBeforeSend'})
        self.assertIn('clock adjustments', checked['time_checks'])
