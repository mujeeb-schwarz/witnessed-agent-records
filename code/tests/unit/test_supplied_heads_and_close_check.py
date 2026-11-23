"""Authenticated decision heads supplied independently receive decision-chain
checks but add no logged coverage or retained terminal head. Closing compares
every decision line with the in-memory chain. Tests also check documentation
of shared-log journal inputs and report fields, repeated clean sessions,
missing anchors and failover coverage.
"""
import contextlib
import io
import unittest

from nacl.signing import SigningKey

from helpers import CODE_DIR, read_jsonl, write_jsonl
from test_anchor_coverage import Run, anchor_gaps, inputs
from witnessed_gate import checker
from witnessed_gate.common import canon_bytes, decision_head_body
from witnessed_gate.gate import Gate
from witnessed_gate.witness import signed_from_line

PHRASE = "every journal whose decisions a given witness log anchors"


def flat(text):
    return " ".join((text or "").split())


def mint_anchor(case, name, journal, length, decision_hash):
    """Sign a decision head with the witness's key read from its folder,
    using the size and head of its log's last entry, without saving the
    decision head in the log."""
    key = SigningKey(bytes.fromhex((case.dir / name / "signing.key").read_text().strip()))
    last = read_jsonl(case.witness_log(name))[-1]
    body = decision_head_body(last["witness"], journal, length, decision_hash,
                              last["index"], last["head"], last["t"])
    body["sig"] = key.sign(canon_bytes(body)).signature.hex()
    return body


class SuppliedDecisionAnchors(Run):
    def passing_run(self):
        self.start("one")
        g = self.open_gate()
        self.call(g, "c1")
        self.call(g, "c2")
        closed = g.close(0.1)
        self.assertEqual(self.check(closed.signed_heads, closed.catch_up_done)["status"], "pass")
        return closed

    def probe(self, **change):
        """The terminal head is kept (signed head 0); the probe is signed head 1."""
        closed = self.passing_run()
        real = closed.decision_heads[0]
        fields = {k: real[k] for k in ("journal", "length", "decision_hash")}
        fields.update(change)
        checked = self.check(closed.signed_heads + [mint_anchor(self, "witness", **fields)],
                             closed.catch_up_done)
        self.assertEqual(checked["by_check"]["Rule2"], [])  # it matches the log: only its content is wrong
        self.assertEqual(checked["status"], "fail")
        return checked["by_check"]["DecisionHeads"]

    def test_a_given_anchor_with_a_wrong_decision_hash_fails(self):
        found = self.probe(decision_hash="ab" * 32)
        self.assertTrue(any("signed head 1 given" in p and "rewritten" in p for p in found), found)

    def test_a_given_anchor_longer_than_the_chain_fails(self):
        found = self.probe(length=9)  # the chain holds 3 lines
        self.assertTrue(any("signed head 1 given" in p and "removed" in p for p in found), found)

    def test_a_given_anchor_naming_no_given_journal_fails(self):
        found = self.probe(journal="cd" * 32)
        self.assertTrue(any("signed head 1 given" in p and "not given" in p for p in found), found)

    def test_the_matching_anchor_given_beside_the_terminal_head_still_passes(self):
        closed = self.passing_run()
        rebuilt = signed_from_line(read_jsonl(self.witness_log())[-1])
        checked = self.check(closed.signed_heads + [rebuilt], closed.catch_up_done)
        self.assertEqual(checked["problems"], [])
        self.assertEqual(checked["status"], "pass")

    def test_the_matching_anchor_alone_is_incomplete_with_the_refusal_reason(self):
        # A valid decision anchor in signed_heads supplies no terminal head.
        closed = self.passing_run()
        rebuilt = signed_from_line(read_jsonl(self.witness_log())[-1])
        checked = self.check([rebuilt], closed.catch_up_done)
        self.assertEqual(checked["problems"], [])
        self.assertEqual(checked["status"], "pass_incomplete_evidence")
        self.assertIn("signed_heads", inputs(checked))
        self.assertTrue(any("signed head 0 given" in n and "refused" in n for n in checked["notes"]))

    def test_a_matching_given_anchor_is_checked_but_never_counts_as_anchoring(self):
        # The run never closed, so its log holds no anchor. A matching decision
        # head signed with the witness's key, never saved in its log, adds no
        # coverage: the decision lines stay unanchored.
        self.start("one")
        g = self.open_gate()
        self.call(g, "c1")
        minted = mint_anchor(self, "witness", **g.journal.decision_head())
        head = g.ask_witness("head")["head"]
        self.stop(g)
        checked = self.check([head, minted])
        self.assertEqual(checked["problems"], [])
        self.assertEqual(checked["status"], "pass_incomplete_evidence")
        self.assertEqual([(u["witness"], u["count"]) for u in anchor_gaps(checked)], [(self.wids()[0], 2)])


class CloseComparesEveryDecisionLine(Run):
    def test_an_earlier_line_edited_on_disk_is_reported_at_close(self):
        self.start("one")
        g = self.open_gate()
        self.call(g, "c1")
        self.call(g, "c2")
        rows = read_jsonl(self.decisions)
        self.assertGreaterEqual(len(rows), 3)
        rows[1]["wall_ns"] += 1  # line 1 changes; the line count and the last line stay
        write_jsonl(self.decisions, rows)
        closed = g.close(0.1)
        why = closed.decision_head_errors.get("decision file", "")
        self.assertIn("first at line 1:", why)
        self.assertEqual(closed.decision_heads[0]["length"], len(rows))  # the anchor: the chain in memory
        self.assertEqual(self.check(closed.signed_heads, closed.catch_up_done)["status"], "fail")

    def test_an_honest_close_reports_nothing_including_after_a_reopen(self):
        self.start("one")
        g = self.open_gate()
        self.call(g, "c1")
        self.call(g, "c2")
        self.assertEqual(g.close(0.1).decision_head_errors, {})
        self.relaunch()  # the next gate reads the earlier lines back from disk
        g2 = self.open_gate()
        self.call(g2, "c3")
        closed = g2.close(0.1)
        self.assertEqual(closed.decision_head_errors, {})
        self.assertEqual(self.check(closed.signed_heads, closed.catch_up_done)["status"], "pass")


class EveryAnchoredJournal(Run):
    def test_the_docstring_the_cli_help_and_the_readme_say_so(self):
        self.assertIn(PHRASE, flat(checker.check_run.__doc__))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            checker.main(["--help"])
        self.assertIn(PHRASE, flat(out.getvalue()))
        self.assertIn(PHRASE, flat((CODE_DIR / "README.md").read_text(encoding="utf-8")))

    def test_one_log_anchoring_two_journals_fails_with_one_given_and_passes_with_both(self):
        # Every journal whose decisions the shared log anchors must be supplied.
        self.start("one")
        g = self.open_gate()
        self.call(g, "c1")
        g.close(0.1)
        self.relaunch()
        other = self.dir / "journal" / "other.jsonl"
        g2 = Gate(other, witness=self.clients[0], wait_seconds=0.05)
        self._gates.append(g2)
        self.call(g2, "c2")
        closed = g2.close(0.1)
        alone = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(alone["status"], "fail")
        self.assertTrue(any("not given" in p for p in alone["by_check"]["DecisionHeads"]))
        both = checker.check_run([self.journal, other], self.logs(), self.effects, trusted_keys=self.keys,
                                 mode=self.mode, required_witnesses=self.req, signed_heads=closed.signed_heads,
                                 catch_up_done=closed.catch_up_done)
        self.assertEqual(both["problems"], [])
        self.assertEqual(both["status"], "pass")


class DocumentedReportFields(unittest.TestCase):
    def test_the_readme_lists_decision_evidence_report_fields(self):
        readme = (CODE_DIR / "README.md").read_text(encoding="utf-8")
        marker = "Decision evidence report fields"
        self.assertIn(marker, readme)
        part = readme[readme.index(marker):][:2500]
        for name in ("`count`", "`lines`", "`restart_line`", "`\"decision file\"`", "decision_head_errors"):
            self.assertIn(name, part)


class DecisionCoverageAcrossSessions(Run):
    """Check decision coverage over repeated clean sessions, a later close
    with the main witness down, an unclosed run and an opening-only journal."""

    def test_three_clean_sessions_on_one_decision_file_pass(self):
        self.start("one")
        for n in range(3):
            if n:
                self.relaunch()
            g = self.open_gate()
            self.call(g, "c%d" % n)
            closed = g.close(0.1)
        anchors = [e["length"] for e in read_jsonl(self.witness_log()) if e.get("kind") == "decision_head"]
        self.assertEqual(anchors, [2, 4, 6])  # restart lines 2 and 4 each sit at an anchor's length
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked["problems"], [])
        self.assertEqual(checked["status"], "pass")

    def test_failover_main_down_at_the_later_close_reports_the_lines_after_its_older_anchor(self):
        self.start("failover")
        g = self.open_gate()
        self.call(g, "c1")
        g.close(0.1)
        self.relaunch()
        g2 = self.open_gate()
        self.call(g2, "c2")
        main = self.clients[0].witness_id
        self.clients[0].kill()
        closed = g2.close(0.1)
        self.assertIn(main, closed.decision_head_errors)
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked["problems"], [])
        self.assertEqual(checked["status"], "pass_incomplete_evidence")
        gaps = [u for u in anchor_gaps(checked) if u["witness"] == main]
        self.assertEqual([(u.get("lines"), u["count"]) for u in gaps], [([2, 3], 2)])

    def test_never_closed_with_no_anchor_is_incomplete(self):
        self.start("one")
        g = self.open_gate()
        self.call(g, "c1")
        head = g.ask_witness("head")["head"]
        self.stop(g)
        checked = self.check([head])
        self.assertEqual(checked["problems"], [])
        self.assertEqual(checked["status"], "pass_incomplete_evidence")
        self.assertIn("decision heads", inputs(checked))
        self.assertNotIn("signed_heads", inputs(checked))
        self.assertEqual([u["count"] for u in anchor_gaps(checked)], [2])

    def test_a_closed_journal_with_only_its_opening_line_passes(self):
        self.start("one")
        closed = self.open_gate().close(0.1)
        self.assertEqual(read_jsonl(self.journal), [])
        self.assertEqual([d["kind"] for d in read_jsonl(self.decisions)], ["open"])
        checked = self.check(closed.signed_heads, closed.catch_up_done)
        self.assertEqual(checked["problems"], [])
        self.assertEqual(checked["status"], "pass")
