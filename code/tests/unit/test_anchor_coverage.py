"""Every logged decision anchor is compared with the chain at its length.
Decisions never anchored before a restart leave incomplete evidence, and
only a signed message of kind "head" counts as a retained terminal head.
Tests cover keyless refusal-to-approval forgery, unknown journal identities,
edits while a gate runs, failover anchors and drain deadlines.
"""
from unittest import mock

from helpers import GateCase, read_jsonl, rechain_decisions, write_jsonl
from witnessed_gate import checker, wire
from witnessed_gate.witness import signed_from_line, stamp_from_line


def inputs(report):
    return [u['input'] for u in report['unmeasured']]


def anchor_gaps(report):
    return [u for u in report['unmeasured'] if u['input'] == 'decision heads']


class Run(GateCase):
    """A run with one witness, both witnesses, or main-to-backup failover."""

    def start(self, run_mode, **faults):
        self.mode = run_mode
        self.names = ['witness'] if run_mode == 'one' else ['witness', 'backup']
        self.clients = [self.launch(n, **faults) for n in self.names]
        write_jsonl(self.effects, [])

    def relaunch(self):
        """The witnesses start again on their folders, without faults."""
        for c in self.clients:
            c.kill()
        self.clients = [self.launch(n) for n in self.names]

    def open_gate(self):
        if self.mode == 'one':
            g = self.gate(self.clients[0], wait_seconds=0.05)
        else:
            mode = {'witness_mode': 'failover'} if self.mode == 'failover' else {}
            g = self.gate(None, witnesses=self.clients, wait_seconds=0.05, **mode)
        self.keys, self.req = dict(g.keys), g.required_witnesses()
        return g

    def stop(self, g):
        """The gate process ends here: no close, so no anchor."""
        g.journal.close()
        self._gates.remove(g)

    def logs(self):
        return [self.witness_log(n) for n in self.names]

    def check(self, heads, catch_up_done=True):
        return checker.check_run(self.journal, self.logs(), self.effects, trusted_keys=self.keys,
                                 mode=self.mode, required_witnesses=self.req, signed_heads=heads,
                                 catch_up_done=catch_up_done)

    def refused_deletion(self, g):
        d = self.call(g, 'del1', kind='delete')
        self.assertFalse(d.approved)
        return d

    def forge(self, refused):
        """Replace a refusal with an approval holding a stamp rebuilt from the
        main witness's log, re-chain all decisions and add an effects line.
        No signing key is used and no witness log is changed."""
        entry = next(e for e in read_jsonl(self.logs()[0]) if e.get('fp') == refused.fp)
        rows = read_jsonl(self.decisions)
        target = next(r for r in rows if r['kind'] == 'refused' and r['record_fp'] == refused.fp)
        target.update(kind='approved', stamp=stamp_from_line(entry), stamp_received_ns=target['wall_ns'] - 1)
        target.pop('reason')
        write_jsonl(self.decisions, rows)
        rechain_decisions(self.decisions)
        effect = wire.effect_line(refused.record)
        effect['wall_ns'] = target['wall_ns'] + 1
        write_jsonl(self.effects, read_jsonl(self.effects) + [effect])

    def wids(self):
        return [wid for _, wid in self.req]


class EveryDecisionAnchor(Run):
    def test_v1_forged_with_kept_heads_fails_in_mode_one(self):
        self.start('one', mode='drop')
        g = self.open_gate()
        d = self.refused_deletion(g)
        closed = g.close(0.1)
        self.assertEqual(self.check(closed.signed_heads, closed.catch_up_done)['status'], 'pass')
        self.forge(d)
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked['status'], 'fail')
        self.assertTrue(checked['by_check']['DecisionHeads'])
        self.assertFalse(checked['by_check']['Rule2'])

    def test_v3_forgery_between_two_closes_fails_with_heads_from_the_second_close(self):
        self.start('both', mode='drop')
        g = self.open_gate()
        d = self.refused_deletion(g)
        g.close(0.1)
        self.forge(d)
        self.relaunch()
        second = self.open_gate().close(0.1)
        checked = self.check(second.signed_heads, second.catch_up_done)
        self.assertEqual(checked['status'], 'fail')
        found = checked['by_check']['DecisionHeads']
        for wid in self.wids():  # each witness's first anchor, at length 2, contradicts the chain
            self.assertTrue(any(wid in p and 'length 2' in p for p in found), found)

    def test_v5_honest_reopen_then_stop_without_close_is_incomplete_not_failed(self):
        self.start('one')
        g = self.open_gate()
        self.call(g, 'c1')
        g.close(0.1)
        self.relaunch()
        g2 = self.open_gate()
        self.call(g2, 'c2')
        head = g2.ask_witness('head')['head']
        self.stop(g2)
        checked = self.check([head])
        self.assertEqual(checked['problems'], [])
        self.assertEqual(checked['status'], 'pass_incomplete_evidence')
        gaps = anchor_gaps(checked)
        self.assertEqual(len(gaps), 1, gaps)
        self.assertEqual(gaps[0]['count'], 2)  # the restart line and c2's approval follow the anchor
        self.assertEqual(gaps[0]['lines'], [2, 3])

    def test_an_anchor_longer_than_the_chain_fails_as_removed_lines(self):
        self.start('one')
        g = self.open_gate()
        self.call(g, 'c1')
        closed = g.close(0.1)
        write_jsonl(self.decisions, read_jsonl(self.decisions)[:1])
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked['status'], 'fail')
        self.assertTrue(any('removed' in p and 'length 2' in p for p in checked['by_check']['DecisionHeads']))


class DecisionCoverageBeforeRestart(Run):
    def test_v4_forgery_while_the_gate_is_down_is_incomplete_evidence(self):
        self.start('both', mode='drop')
        g = self.open_gate()
        d = self.refused_deletion(g)
        self.stop(g)
        self.forge(d)
        self.relaunch()
        closed = self.open_gate().close(0.1)
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked['problems'], [])
        self.assertEqual(checked['status'], 'pass_incomplete_evidence')
        gaps = anchor_gaps(checked)
        self.assertEqual(sorted(u['witness'] for u in gaps), sorted(self.wids()))
        for u in gaps:
            self.assertEqual((u['restart_line'], u['lines']), (2, [0, 1]))

    def test_an_honest_crash_and_restart_then_close_is_incomplete_evidence(self):
        self.start('one')
        g = self.open_gate()
        self.call(g, 'c1')
        self.stop(g)
        self.relaunch()
        g2 = self.open_gate()
        self.call(g2, 'c2')
        closed = g2.close(0.1)
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked['problems'], [])
        self.assertEqual(checked['status'], 'pass_incomplete_evidence')
        gaps = anchor_gaps(checked)
        self.assertEqual([(u['witness'], u['restart_line'], u['lines']) for u in gaps],
                         [(self.wids()[0], 2, [0, 1])])


class RetainedTerminalHeadKind(Run):
    def v6(self):
        """Honest: close, reopen, one call, close."""
        self.start('one')
        g = self.open_gate()
        self.call(g, 'c1')
        g.close(0.1)
        self.relaunch()
        g2 = self.open_gate()
        self.call(g2, 'c2')
        return g2.close(0.1)

    def test_v6_honest_close_reopen_close_passes(self):
        closed = self.v6()
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked['problems'], [])
        self.assertEqual(checked['status'], 'pass')

    def test_v6_an_anchor_rebuilt_from_the_log_is_not_a_kept_head(self):
        self.v6()
        minted = [signed_from_line(read_jsonl(p)[-1]) for p in self.logs()]
        self.assertEqual([h['kind'] for h in minted], ['decision_head'])
        checked = self.check(minted)
        self.assertNotEqual(checked['status'], 'pass')
        self.assertIn('signed_heads', inputs(checked))
        self.assertTrue(any('signed head 0 given' in n and 'decision_head' in n for n in checked['notes']))

    def test_v6_a_stamp_rebuilt_from_the_log_is_not_a_kept_head(self):
        self.v6()
        entries = read_jsonl(self.logs()[0])
        stamp = stamp_from_line([e for e in entries if e.get('kind') != 'decision_head'][-1])
        checked = self.check([stamp])
        self.assertNotEqual(checked['status'], 'pass')
        self.assertIn('signed_heads', inputs(checked))

    def test_a_stamp_at_the_tail_of_the_log_is_not_a_kept_head(self):
        # The run never closed, so its log ends with a stamp. Rebuilding that
        # stamp does not produce a terminal head retained outside the run.
        self.start('one')
        g = self.open_gate()
        self.call(g, 'c1')
        tail = stamp_from_line(read_jsonl(self.logs()[0])[-1])
        checked = self.check([tail])
        self.assertEqual(checked['problems'], [])
        unanchored = next((u for u in checked['unmeasured'] if u['input'] == 'signed_heads'), None)
        self.assertIsNotNone(unanchored)
        self.assertEqual(unanchored['witnesses'], self.wids())


class UnknownJournalIdentity(Run):
    """An anchor naming no supplied decision file fails the check."""

    def test_v1_with_the_opening_line_rewritten_and_relinked_fails(self):
        self.start('one', mode='drop')
        g = self.open_gate()
        d = self.refused_deletion(g)
        closed = g.close(0.1)
        self.forge(d)
        rows = read_jsonl(self.decisions)
        rows[0]['wall_ns'] += 1  # a new journal identity, which no anchor names
        write_jsonl(self.decisions, rows)
        rechain_decisions(self.decisions)
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked['status'], 'fail')
        self.assertTrue(any('not given' in p for p in checked['by_check']['DecisionHeads']),
                        checked['by_check']['DecisionHeads'])


class DecisionEditsWhileRunning(Run):
    """Closing detects decision-file edits made while the gate runs."""

    def test_a_relinked_edit_before_close_fails_and_close_reports_it(self):
        self.start('one', mode='drop')
        g = self.open_gate()
        self.call(g, 'c0')
        d = self.refused_deletion(g)
        self.forge(d)  # on disk, with the gate still open
        closed = g.close(0.1)
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked['status'], 'fail')
        self.assertTrue(checked['by_check']['DecisionHeads'])
        self.assertIn('decision file', closed.decision_head_errors)


class FailoverDecisionAnchors(Run):
    """Failover detects forged approvals and compares backup anchors even
    when the main witness is down at close."""

    def test_v1_failover_forged_with_kept_heads_fails(self):
        self.start('failover', mode='drop')
        g = self.open_gate()
        d = self.refused_deletion(g)
        closed = g.close(0.1)
        self.assertEqual(self.check(closed.signed_heads, closed.catch_up_done)['status'], 'pass')
        self.forge(d)
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked['status'], 'fail')
        self.assertTrue(checked['by_check']['DecisionHeads'])

    def test_v3_failover_forgery_between_two_closes_fails(self):
        self.start('failover', mode='drop')
        g = self.open_gate()
        d = self.refused_deletion(g)
        g.close(0.1)
        self.forge(d)
        self.relaunch()
        second = self.open_gate().close(0.1)
        checked = self.check(second.signed_heads, second.catch_up_done)
        self.assertEqual(checked['status'], 'fail')
        self.assertTrue(any('length 2' in p for p in checked['by_check']['DecisionHeads']))

    def test_main_down_at_close_is_incomplete_and_the_backups_anchor_still_counts(self):
        self.start('failover', mode='drop')
        g = self.open_gate()
        d = self.refused_deletion(g)
        main, backup = self.clients[0].witness_id, self.clients[1].witness_id
        self.clients[0].kill()
        closed = g.close(0.1)
        self.assertIn(main, closed.decision_head_errors)
        self.assertEqual([a['witness'] for a in closed.decision_heads], [backup])
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked['problems'], [])
        self.assertEqual(checked['status'], 'pass_incomplete_evidence')
        self.assertIn(main, [u['witness'] for u in anchor_gaps(checked)])
        self.forge(d)
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked['status'], 'fail')
        self.assertTrue(any(backup in p for p in checked['by_check']['DecisionHeads']),
                        checked['by_check']['DecisionHeads'])


class DrainDeadline(GateCase):
    def test_a_witness_that_keeps_sending_cannot_hold_drain_past_its_deadline(self):
        w = self.launch()
        g = self.gate(w)
        state = {'reads': 0, 'now': 0.0}
        item = (w, {'id': 'unsolicited', 'ok': False})

        def next_message(timeout):
            state['reads'] += 1
            if state['reads'] > 400:  # a finite fail-safe prevents the loop from hanging the suite
                raise AssertionError('drain never checked its deadline during a continuous stream')
            state['now'] += 0.001
            return item
        with mock.patch.object(g, '_next', side_effect=next_message), \
                mock.patch('witnessed_gate.gate.time.monotonic', side_effect=lambda: state['now']):
            read = g.drain(0.2)
        self.assertLessEqual(state['now'], 0.2015)  # one read may end at the deadline, with rounding
        self.assertEqual(read, state['reads'])
