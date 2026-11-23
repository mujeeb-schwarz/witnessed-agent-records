"""Bad evidence is a failed report, including read and canonicalization errors."""
import json
from unittest.mock import patch
from helpers import GateCase, read_jsonl, write_jsonl
from witnessed_gate import checker


class MalformedEvidence(GateCase):
    def clean(self):
        self.call(self.gate(self.launch()), "c1")
        return {p: p.read_bytes() for p in (self.journal, self.decisions, self.witness_log(), self.effects)}

    def assert_failed_report(self, **kw):
        report = checker.check_run(self.journal, self.witness_log(), self.effects, **kw)
        self.assertTrue(report["problems"], report)
        self.assertTrue(report["problems"])
        return report

    def test_f12_read_errors_and_invalid_encodings_are_problems(self):
        original = self.clean()
        for path in original:
            for data in (b'\xff\n', b'{"x":"\\ud800"}\n', b'{"x":NaN}\n',
                         b'{"x":Infinity}\n', b'{"x":1e9999}\n', b'[' * 1500):
                with self.subTest(path=path, data=data[:30]):
                    path.write_bytes(data)
                    self.assert_failed_report()
                    path.write_bytes(original[path])
        with patch("pathlib.Path.read_bytes", side_effect=PermissionError("no access")):
            self.assert_failed_report()

    def test_f12_unhashable_and_wrong_typed_file_fields_are_problems(self):
        original = self.clean()
        changes = [(self.journal, 0, "fp", []), (self.journal, 0, "wall_ns", True),
                   (self.journal, 0, "seq", False), (self.decisions, 0, "witnesses", 1),
                   (self.decisions, 0, "witness_mode", []), (self.decisions, 1, "kind", []),
                   (self.decisions, 1, "record_fp", []), (self.decisions, 1, "record_seq", {}),
                   (self.decisions, 1, "stamp", {"witness": []}),
                   (self.witness_log(), 0, "fp", []), (self.witness_log(), 0, "witness", {}),
                   (self.witness_log(), 0, "index", []), (self.effects, 0, "wall_ns", True)]
        for path, index, field, value in changes:
            with self.subTest(path=path, field=field, value=value):
                rows = read_jsonl(path)
                rows[index][field] = value
                write_jsonl(path, rows)
                self.assert_failed_report()
                path.write_bytes(original[path])

    def test_f12_malformed_restart_pin_and_external_head_are_problems(self):
        original = self.clean()
        rows = read_jsonl(self.decisions)
        rows[0]["witnesses"][0]["witness_id"] = []
        write_jsonl(self.decisions, rows)
        self.assert_failed_report()
        self.decisions.write_bytes(original[self.decisions])
        rows = read_jsonl(self.decisions)
        rows.append({"kind": "restart", "seq": 2, "prev": "0" * 64, "wall_ns": 2,
                     "records_seen": 1, "undecided": [[], {}]})
        write_jsonl(self.decisions, rows)
        self.assert_failed_report()
        self.decisions.write_bytes(original[self.decisions])
        self.assert_failed_report(signed_heads=[{"kind": "head", "witness": []}])

    def test_f12_missing_effects_file_is_reported(self):
        self.clean()
        self.effects.unlink()
        self.assertTrue(self.assert_failed_report()["by_check"]["effects"])

    def test_f12_no_approvals_need_no_lazily_created_effects_file(self):
        w = self.launch()
        g = self.gate(w)
        w.kill()
        self.call(g, "refused")
        report = checker.check_run(self.journal, self.witness_log(), self.effects)
        self.assertEqual(report["by_check"]["effects"], [])
