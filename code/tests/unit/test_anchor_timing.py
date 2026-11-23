"""Only anchors signed before a restart's wall_ns cover decisions before that
restart. Later anchors still cover the chain through their own length for
tail-evidence reporting. Tests cover clean and interrupted sessions,
multiple journals, empty decision files, contradictory supplied anchors,
and documentation of the clock assumption and unauthenticated-anchor limit.
"""
import json
import unittest
from pathlib import Path

from helpers import CODE_DIR, read_jsonl
from test_anchor_coverage import Run, anchor_gaps
from test_supplied_heads_and_close_check import mint_anchor
from witnessed_gate import checker
from witnessed_gate.common import canon_bytes, sha256_hex
from witnessed_gate.gate import Gate
from witnessed_gate.witness import signed_from_line

RULE = "an anchor counts for a restart only if its signed time `t` is earlier than the restart line's `wall_ns`"
CLOCK = "a clock step can only push an honest run to `pass_incomplete_evidence`"
LIMIT = "an anchor obtained while the gate is down, before the restart line is written"


def flat(text):
    return " ".join((text or "").split()).lower()


def prefix(path, length):
    """The journal identity and the decision chain's hash at length, read from
    the decision file the way the checker reads it."""
    raw = Path(path).read_bytes().splitlines()
    return {"journal": sha256_hex(canon_bytes(json.loads(raw[0]))), "length": length,
            "decision_hash": sha256_hex(raw[length - 1])}


def gaps_of(report):
    """One witness: (restart line, or -1 for the lines after its longest anchor; lines; count)."""
    return sorted((u.get("restart_line", -1), u.get("lines"), u["count"]) for u in anchor_gaps(report))


class AnchorTimingBeforeRestart(Run):
    def probe(self, rewrite):
        """Open a journal, refuse a call, stop without closing, and reopen with
        restart line 2. Request an anchor of the two-line prefix directly from
        the witness after the restart, then close to anchor the whole chain."""
        self.start("one", mode="drop")
        g = self.open_gate()
        refused = self.refused_deletion(g)
        held = g.journal.decision_head()
        self.stop(g)
        self.assertEqual(prefix(self.decisions, 2), held)  # the helper reads the chain as the gate holds it
        if rewrite:
            self.forge(refused)  # while the gate is down: the refusal becomes an approval, re-chained
        self.relaunch()
        g2 = self.open_gate()
        rows = read_jsonl(self.decisions)
        self.assertEqual([r["kind"] for r in rows], ["open", "approved" if rewrite else "refused", "restart"])
        reply = g2.ask_witness("decision_head", timeout=1.0, index=0, **prefix(self.decisions, 2))
        self.assertGreaterEqual(reply["decision_head"]["t"], rows[2]["wall_ns"])  # made after the restart
        closed = g2.close(0.1)
        lengths = [e["length"] for e in read_jsonl(self.witness_log()) if e.get("kind") == "decision_head"]
        self.assertEqual(lengths, [2, 3])
        return self.check(closed.signed_heads, closed.catch_up_done)

    def test_an_anchor_of_the_prefix_made_after_the_restart_does_not_count(self):
        checked = self.probe(rewrite=False)
        self.assertEqual(checked["problems"], [])
        self.assertEqual(checked["status"], "pass_incomplete_evidence")  # a post-restart anchor cannot establish pre-restart coverage
        self.assertEqual(gaps_of(checked), [(2, [0, 1], 2)])

    def test_a_refusal_rewritten_before_the_reopen_does_not_pass(self):
        checked = self.probe(rewrite=True)
        self.assertNotEqual(checked["status"], "pass")  # a post-restart anchor cannot establish pre-restart coverage
        self.assertIn((2, [0, 1], 2), gaps_of(checked))

    def test_a_clean_close_and_reopen_passes_its_anchor_made_before_the_restart(self):
        self.start("one")
        g = self.open_gate()
        self.call(g, "c1")
        g.close(0.1)
        self.relaunch()
        g2 = self.open_gate()
        self.call(g2, "c2")
        closed = g2.close(0.1)
        rows = read_jsonl(self.decisions)
        self.assertEqual(rows[2]["kind"], "restart")
        first = [e for e in read_jsonl(self.witness_log()) if e.get("kind") == "decision_head"][0]
        self.assertEqual(first["length"], 2)  # the restart line sits at the anchor's length
        self.assertLess(first["t"], rows[2]["wall_ns"])  # and the anchor was signed before it
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked["problems"], [])
        self.assertEqual(checked["status"], "pass")

    def test_an_unclean_stop_and_restart_with_no_anchor_before_it_is_incomplete(self):
        # An honest two-witness restart without earlier anchors leaves
        # incomplete evidence for the decisions before the restart.
        self.start("both", mode="drop")
        g = self.open_gate()
        self.refused_deletion(g)
        self.stop(g)
        self.relaunch()
        closed = self.open_gate().close(0.1)
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked["problems"], [])
        self.assertEqual(checked["status"], "pass_incomplete_evidence")
        self.assertEqual(sorted((u["witness"], u.get("restart_line"), u.get("lines")) for u in anchor_gaps(checked)),
                         sorted((w, 2, [0, 1]) for w in self.wids()))

    def test_a_late_anchor_still_counts_for_the_lines_after_the_longest_anchor(self):
        # Never closed after the restart: the late anchor of the prefix (length 2)
        # is the witness's longest, so only line 2 follows it; it does not
        # count for the restart at line 2.
        self.start("one", mode="drop")
        g = self.open_gate()
        self.refused_deletion(g)
        self.stop(g)
        self.relaunch()
        g2 = self.open_gate()
        self.assertTrue(g2.ask_witness("decision_head", timeout=1.0, index=0, **prefix(self.decisions, 2))["ok"])
        head = g2.ask_witness("head")["head"]
        self.stop(g2)
        checked = self.check([head])
        self.assertEqual(checked["problems"], [])
        self.assertEqual(checked["status"], "pass_incomplete_evidence")
        self.assertEqual(gaps_of(checked), [(-1, [2, 2], 1), (2, [0, 1], 2)])

    def test_an_anchor_made_between_two_restarts_counts_for_the_later_one_only(self):
        # Each restart is judged by its own wall_ns. Restart lines 2 and 3; the
        # anchor of the two-line prefix is made after the first and before the second.
        self.start("one", mode="drop")
        g = self.open_gate()
        self.refused_deletion(g)
        self.stop(g)
        self.relaunch()
        g2 = self.open_gate()
        self.assertTrue(g2.ask_witness("decision_head", timeout=1.0, index=0, **prefix(self.decisions, 2))["ok"])
        self.stop(g2)
        self.relaunch()
        closed = self.open_gate().close(0.1)
        self.assertEqual([r["kind"] for r in read_jsonl(self.decisions)], ["open", "refused", "restart", "restart"])
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked["problems"], [])
        self.assertEqual(checked["status"], "pass_incomplete_evidence")
        self.assertEqual(gaps_of(checked), [(2, [0, 1], 2), (3, [2, 2], 1)])


class DecisionEvidenceAcrossJournals(Run):
    """Check multiple clean journals, unclosed and empty decision files,
    and contradictory independently supplied anchors."""

    def test_three_clean_sessions_in_three_journals_given_together_pass(self):
        self.start("one")
        paths = [self.journal] + [self.dir / "journal" / name for name in ("second.jsonl", "third.jsonl")]
        for n, path in enumerate(paths):
            if n:
                self.relaunch()
                g = Gate(path, witness=self.clients[0], wait_seconds=0.05)
                self._gates.append(g)
            else:
                g = self.open_gate()
            self.call(g, "c%d" % n)
            closed = g.close(0.1)
        anchors = [e for e in read_jsonl(self.witness_log()) if e.get("kind") == "decision_head"]
        self.assertEqual(len({e["journal"] for e in anchors}), 3)
        checked = checker.check_run(paths, self.logs(), self.effects, trusted_keys=self.keys, mode=self.mode,
                                    required_witnesses=self.req, signed_heads=closed.signed_heads,
                                    catch_up_done=closed.catch_up_done)
        self.assertEqual(checked["problems"], [])
        self.assertEqual(checked["status"], "pass")

    def test_no_records_never_closed_is_incomplete(self):
        self.start("one")
        g = self.open_gate()
        head = g.ask_witness("head")["head"]
        self.stop(g)
        self.assertEqual(read_jsonl(self.journal), [])
        checked = self.check([head])
        self.assertEqual(checked["problems"], [])
        self.assertEqual(checked["status"], "pass_incomplete_evidence")
        self.assertEqual([u["count"] for u in anchor_gaps(checked)], [1])

    def test_a_literally_empty_decision_file_fails(self):
        self.start("one")
        closed = self.open_gate().close(0.1)
        self.decisions.write_bytes(b"")
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked["status"], "fail")
        self.assertTrue(any("open line" in p for p in checked["by_check"].get("journal", [])), checked["problems"])

    def test_a_bad_earlier_anchor_then_a_matching_one_given_fails(self):
        self.start("one")
        g = self.open_gate()
        self.call(g, "c1")
        self.call(g, "c2")
        closed = g.close(0.1)
        bad = mint_anchor(self, "witness", closed.decision_heads[0]["journal"], 2, "ab" * 32)
        good = signed_from_line(read_jsonl(self.witness_log())[-1])
        self.assertEqual(self.check(closed.signed_heads + [good], closed.catch_up_done)["status"], "pass")
        checked = self.check(closed.signed_heads + [bad, good], closed.catch_up_done)
        self.assertEqual(checked["status"], "fail")
        found = checked["by_check"]["DecisionHeads"]
        self.assertTrue(any("signed head 1 given" in p and "rewritten" in p for p in found), found)


class DocumentedAnchorTiming(unittest.TestCase):
    def test_the_readme_states_the_rule_the_clock_model_and_the_limit(self):
        readme = flat((CODE_DIR / "README.md").read_text(encoding="utf-8"))
        for phrase in (RULE, CLOCK, LIMIT):
            self.assertIn(phrase.lower(), readme)


if __name__ == "__main__":
    unittest.main()
