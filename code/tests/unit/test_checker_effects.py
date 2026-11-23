"""Version 2 effects bind executions to exact approved records and actions."""
from helpers import GateCase, read_jsonl, write_jsonl
from witnessed_gate import checker, wire


class ExactEffects(GateCase):
    def check(self):
        return checker.check_run(self.journal, self.witness_log(), self.effects)

    def test_f6_refused_action_cannot_consume_an_aliased_unused_approval(self):
        w = self.launch()
        g = self.gate(w)
        g.decide({"call_id": "shared", "function": "allowed", "arguments": {}})
        w.kill()
        refused = g.decide({"call_id": "shared", "function": "refused", "arguments": {}})
        write_jsonl(self.effects, [wire.effect_line(refused.record)])
        report = self.check()
        self.assertTrue(report["problems"])
        self.assertTrue(report["by_check"]["RefusedNeverRuns"])

    def test_f6_function_and_arguments_must_match_the_record(self):
        d = self.call(self.gate(self.launch()), "c1")
        for changes in ({"function": "different"}, {"args_sha256": "a" * 64}):
            with self.subTest(changes=changes):
                write_jsonl(self.effects, [dict(wire.effect_line(d.record), **changes)])
                self.assertTrue(self.check()["by_check"]["effects"])

    def test_f6_repeated_execution_id_is_detected_across_records(self):
        g = self.gate(self.launch())
        self.call(g, "c1")
        self.call(g, "c2")
        rows = read_jsonl(self.effects)
        rows[1]["exec_id"] = rows[0]["exec_id"]
        write_jsonl(self.effects, rows)
        self.assertTrue(self.check()["by_check"]["effects"])

    def test_f6_malformed_and_unbound_effects_cannot_consume_approvals(self):
        d = self.call(self.gate(self.launch()), "c1")
        base = wire.effect_line(d.record)
        variants = [dict(base, record_fp=None), dict(base, exec_id="f"),
                    dict(base, exec_id="A" * 32), dict(base, wall_ns=True),
                    dict(base, args_sha256="x"), dict(base, record_fp="A" * 64),
                    {k: v for k, v in base.items() if k != "record_fp"}]
        for row in variants:
            with self.subTest(row=row):
                write_jsonl(self.effects, [row])
                self.assertTrue(self.check()["problems"])

    def test_f6_call_id_is_for_reading_only_and_bench_records_work(self):
        g = self.gate(self.launch())
        d = self.call(g, "shared")
        rows = [dict(wire.effect_line(d.record), call_id="unrelated-display-id")]
        bench = g.decide({"run_id": "r1", "handover": {"parcel": [1, 2]}}, kind="deliver")
        rows.append(wire.effect_line(bench.record))
        write_jsonl(self.effects, rows)
        self.assertFalse(self.check()["problems"], self.check()["problems"])
