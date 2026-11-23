"""The Inspect approver runs scripted tool calls through the mock model in a
subprocess, without an API key, a real model or network access. HOME points
at the test's temporary folder to contain Inspect's data files.

Records use Inspect's tool-call identity ("tc-c1"), independently of a
call_id argument supplied to the tool ("c1"). Effects identify the approved
record for the execution, preserving the calls' order and identity.
"""
import hashlib
import json
import os
import subprocess
import sys
import unittest

from helpers import CODE_DIR, GateCase, read_jsonl

from witnessed_gate import checker
from witnessed_gate.common import canon_bytes
from witnessed_gate.journal import decisions_path_for

EFFECT_FIELDS = {"call_id", "exec_id", "record_fp", "function", "args_sha256", "wall_ns"}


class InspectDemo(GateCase):
    def demo(self, *args):
        home = self.dir / "home"
        home.mkdir(exist_ok=True)
        env = dict(os.environ, HOME=str(home))
        out = subprocess.run([sys.executable, "-m", "inspect_approver.demo",
                              "--work-dir", str(self.dir / "demo"), *args],
                             cwd=str(CODE_DIR), env=env, capture_output=True, text=True, timeout=300)
        lines = [ln for ln in out.stdout.splitlines() if ln.startswith("RESULT ")]
        self.assertTrue(lines, out.stderr[-3000:])
        result = json.loads(lines[-1][len("RESULT "):])
        self.assertEqual(result["status"], "success", result.get("error"))
        return result

    def check(self, result):
        return checker.check_run(result["journal"], result["witness_log"], result["effects"])

    def effect_ids(self, result):
        path = result["effects"]
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            return [json.loads(x)["call_id"] for x in fh if x.strip()]

    def test_only_approver_every_call_stamped_before_its_tool_runs(self):
        result = self.demo()
        self.assertEqual(result["approval_policy"], [{"name": "witnessed_gate", "tools": "*"}])
        self.assertEqual([(a["approver"], a["decision"], a["call_id"]) for a in result["approvals"]],
                         [("witnessed_gate", "approve", c) for c in ("c1", "c2", "c3")])
        self.assertEqual(self.effect_ids(result), ["tc-c1", "tc-c2", "tc-c3"])
        report = self.check(result)
        self.assertFalse(report["problems"], report["problems"])
        self.assertEqual(report["counts"]["decisions"]["approved"], 3)

    def test_witness_off_every_call_rejected_no_effects(self):
        result = self.demo("--witness", "off")
        self.assertEqual([a["decision"] for a in result["approvals"]], ["reject"] * 3)
        self.assertEqual(self.effect_ids(result), [])
        report = self.check(result)
        self.assertFalse(report["problems"], report["problems"])
        self.assertEqual(report["counts"]["decisions"]["refused"], 3)

    def test_with_a_backup_every_call_ends_with_two_stamps(self):
        result = self.demo("--backup", "on")
        self.assertEqual([a["decision"] for a in result["approvals"]], ["approve"] * 3)
        report = checker.check_run(result["journal"], result["witness_logs"], result["effects"],
                                   catch_up_done=True)
        self.assertFalse(report["problems"], report["problems"])
        self.assertEqual(report["calls_missing_stamps"], [])

    def test_main_witness_down_the_backup_stamps_every_call(self):
        result = self.demo("--backup", "on", "--main-fault", "outage")
        self.assertEqual([a["decision"] for a in result["approvals"]], ["approve"] * 3)
        self.assertEqual(self.effect_ids(result), ["tc-c1", "tc-c2", "tc-c3"])
        report = checker.check_run(result["journal"], result["witness_logs"], result["effects"])
        self.assertIs(report["ok"], False)  # ok is true only for a complete "pass" verdict
        self.assertFalse(report["evidence_complete"])
        self.assertEqual(report["status"], "pass_incomplete_evidence")  # no decision relies on this witness; its missing evidence is incomplete
        self.assertEqual(report["problems"], [])
        self.assertTrue(report["missing_required_logs"])
        self.assertTrue(any(n.startswith("Evidence is incomplete:") for n in report["notes"]))
        self.assertEqual(len(report["calls_missing_stamps"]), 3)

    # Execution identity and rejection of tool-watching sentinel monitors

    def bound_effects(self, result):
        """Every effects line, checked against the approved record it names."""
        records = {r["fp"]: r for r in read_jsonl(result["journal"])}
        approved = [d["record_fp"] for d in read_jsonl(decisions_path_for(result["journal"]))
                    if d["kind"] == "approved"]
        effects = read_jsonl(result["effects"])
        self.assertEqual(sorted(e["record_fp"] for e in effects), sorted(approved))  # one to one
        for e in effects:
            self.assertEqual(set(e), EFFECT_FIELDS)
            rec = records[e["record_fp"]]
            self.assertEqual((e["function"], e["call_id"]), (rec["function"], rec["call_id"]))
            self.assertEqual(e["args_sha256"], hashlib.sha256(canon_bytes(rec["arguments"])).hexdigest())
            self.assertRegex(e["exec_id"], "^[0-9a-f]{32}$")
        self.assertEqual(len({e["exec_id"] for e in effects}), len(effects))
        return effects

    def test_f6_records_carry_inspects_call_id_and_effects_bind_to_the_approval(self):
        result = self.demo()
        records = read_jsonl(result["journal"])
        self.assertEqual([r["call_id"] for r in records], ["tc-c1", "tc-c2", "tc-c3"])
        self.assertEqual([r["call_id"] for r in records], [r["tool_call_id"] for r in records])
        self.assertEqual(len(self.bound_effects(result)), 3)

    def test_f6_a_call_id_in_the_arguments_cannot_alias_another_call(self):
        result = self.demo("--calls", "a:append_effect:x,b:append_effect:x")
        records = read_jsonl(result["journal"])
        self.assertEqual([r["call_id"] for r in records], ["tc-a", "tc-b"])
        self.assertEqual([r["arguments"]["call_id"] for r in records], ["x", "x"])
        self.assertEqual(len(self.bound_effects(result)), 2)
        report = self.check(result)
        self.assertFalse(report["problems"], report["problems"])

    def test_unused_approval_cannot_cover_a_refused_identical_framework_execution(self):
        # A faulty runner ignores the real approver's rejection, while Inspect
        # still supplies the actual executing call's id through its observer.
        script = r"""
import asyncio
import sys
from pathlib import Path
from inspect_ai import eval as inspect_eval
from inspect_ai.approval import Approval, ApprovalPolicy, approver
from inspect_ai.model import get_model
from inspect_ai.tool import ToolCall, ToolCallView
from inspect_approver.approver import OPEN_GATES, close_gates, witnessed_gate_approver
from inspect_approver.demo import MODEL, demo_task, scripted_outputs
from witnessed_gate import wire

work = Path(sys.argv[1])
registry = wire.ApprovedCalls()
real = witnessed_gate_approver(str(work / "calls.jsonl"),
    witness_dir=str(work / "witness"), registry=registry)
try:
    args = {"call_id": "same", "text": "line for same"}
    unused = asyncio.run(real("", ToolCall(id="tc-A", function="append_effect", arguments=args),
                              ToolCallView(), []))
    assert unused.decision == "approve"
    gate, _ = OPEN_GATES[str(work / "calls.jsonl")]
    gate.main.send = lambda msg: False

    @approver(name="faulty_runner")
    def faulty_runner():
        async def approve(message, call, view, history):
            refused = await real(message, call, view, history)
            assert refused.decision == "reject"
            return Approval(decision="approve")
        return approve

    logs = inspect_eval(demo_task(str(work / "effects.jsonl"), registry),
        model=get_model(MODEL, memoize=False, custom_outputs=scripted_outputs([("B", "append_effect", "same")])),
        approval=[ApprovalPolicy(faulty_runner(), "*")], log_dir=str(work / "logs"), display="none")
    assert logs[0].status == "success"
    assert len(registry) == 1
finally:
    close_gates()
"""
        home = self.dir / "home"
        home.mkdir(exist_ok=True)
        out = subprocess.run([sys.executable, "-c", script, str(self.dir)], cwd=str(CODE_DIR),
            env=dict(os.environ, HOME=str(home)), capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr[-4000:])
        effects = read_jsonl(self.effects)
        self.assertEqual(len(effects), 1)
        self.assertEqual(effects[0]["call_id"], "tc-B")
        self.assertIsNone(effects[0]["record_fp"])
        records = read_jsonl(self.dir / "calls.jsonl")
        self.assertEqual([r["call_id"] for r in records], ["tc-A", "tc-B"])
        decisions = read_jsonl(decisions_path_for(self.dir / "calls.jsonl"))
        self.assertEqual([d["kind"] for d in decisions if d.get("record_fp") == records[1]["fp"]], ["refused"])
        self.assertTrue(checker.check_run(self.dir / "calls.jsonl", self.witness_log(), self.effects)["problems"])

    def test_f18_a_sentinel_that_checks_tool_calls_makes_the_approver_reject(self):
        result = self.demo("--pretend-sentinel")
        self.assertEqual([a["decision"] for a in result["approvals"]], ["reject"] * 3)
        self.assertTrue(all("sentinel" in (a["explanation"] or "") for a in result["approvals"]))
        records = read_jsonl(result["journal"])
        refusals = [d for d in read_jsonl(decisions_path_for(result["journal"])) if d["kind"] == "refused"]
        self.assertEqual([r["call_id"] for r in records], ["tc-c1", "tc-c2", "tc-c3"])
        self.assertEqual([d["record_fp"] for d in refusals], [r["fp"] for r in records])
        self.assertTrue(all("sentinel" in d["reason"] for d in refusals))

        self.assertEqual(self.effect_ids(result), [])


if __name__ == "__main__":
    unittest.main()
