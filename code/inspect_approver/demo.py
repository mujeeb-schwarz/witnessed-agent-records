"""A demo task on Inspect's mock model: scripted tool calls, each of which must
pass the witnessed gate before its tool runs. No API key and no real model.

    python -m inspect_approver.demo --work-dir DIR [--witness off] [--wait S]
        [--backup on] [--witness-mode both|failover] [--main-fault MODE]
        [--calls c1:append_effect,d1:delete_note] [--pretend-sentinel]

It prints one line "RESULT {json}" with the eval's status, every approval
event (approver, decision, call id) and the paths of the journal, the
witness's log and the effects file, for witnessed_gate.checker to check.
Inspect writes its log under DIR/logs.

Both tools append one line to the effects file each time they run: the
effects line, version 2 (witnessed_gate.wire), bound to the approved record
whose function and arguments are exactly the tool's own, taken from the
approver's registry. A tool sees only its arguments, so the binding never
comes from a field the model wrote; a run no approval covers writes a line
with record_fp null. delete_note stands for a deletion, which needs a stamp
like any other call.

--calls takes id:function or id:function:argument_call_id; the id becomes
Inspect's tool-call id "tc-<id>", and the call_id among the tool's arguments is
the id unless a third part gives another (two calls may then share one, as a
model could write). --pretend-sentinel is a test hook: it makes the approver
see a sentinel monitor that checks tool calls, as if one were configured.
"""
import argparse
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from inspect_ai import Task
from inspect_ai import eval as inspect_eval
from inspect_ai.agent import react
from inspect_ai.approval import ApprovalPolicy
from inspect_ai.dataset import Sample
from inspect_ai.log import read_eval_log
from inspect_ai.model import ModelOutput, ModelUsage, get_model
from inspect_ai.tool import Tool, tool
from inspect_ai.solver import solver
from inspect_approver.execution import current_call_id, install_execution_identity

from inspect_approver.approver import close_gates, witnessed_gate_approver
from witnessed_gate import wire
from witnessed_gate.common import canon

MODEL = "mockllm/model"
DEFAULT_CALLS: List[Tuple[str, ...]] = [("c1", "append_effect"), ("c2", "append_effect"),
                                        ("c3", "append_effect")]


def append_line(path: str, row: Dict[str, Any]) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (canon(row) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


@tool(parallel=False)
def append_effect(effects_path: str, registry: wire.ApprovedCalls) -> Tool:
    async def execute(call_id: str, text: str) -> str:
        """Append one line to the effects file.

        Args:
            call_id: The call's own id, written in its line.
            text: A short text for the line.
        """
        append_line(effects_path, wire.effect_for_call("append_effect", {"call_id": call_id, "text": text},
                                                       registry, execution_id=current_call_id()))
        return "appended a line for %s" % call_id

    return execute


@tool(parallel=False)
def delete_note(effects_path: str, registry: wire.ApprovedCalls) -> Tool:
    async def execute(call_id: str, note: str) -> str:
        """Delete a note. In this demo it appends one line saying so to the effects file.

        Args:
            call_id: The call's own id, written in its line.
            note: The note to delete.
        """
        append_line(effects_path, wire.effect_for_call("delete_note", {"call_id": call_id, "note": note},
                                                       registry, execution_id=current_call_id()))
        return "deleted %s" % note

    return execute


def scripted_outputs(calls: Sequence[Tuple[str, ...]]) -> List[ModelOutput]:
    """One tool call per model turn, then a plain answer, which ends react(submit=False).
    Each output carries its own usage: without it the mock model counts tokens
    with tiktoken, which fetches an encoding file over the network."""
    outputs = []
    for spec in calls:
        call_id, function = spec[0], spec[1]
        arg_id = spec[2] if len(spec) > 2 else call_id
        args = ({"call_id": arg_id, "text": "line for %s" % arg_id} if function == "append_effect"
                else {"call_id": arg_id, "note": "note-%s" % arg_id})
        outputs.append(ModelOutput.for_tool_call(MODEL, function, args, tool_call_id="tc-" + call_id))
    outputs.append(ModelOutput.from_content(MODEL, "done"))
    for out in outputs:
        out.usage = ModelUsage(input_tokens=1, output_tokens=1, total_tokens=2)
    return outputs


@solver
def execution_identity():
    async def solve(state, generate):
        install_execution_identity()
        return state
    return solve


def demo_task(effects_path: str, registry: wire.ApprovedCalls) -> Task:
    return Task(dataset=[Sample(input="Make the scripted tool calls.", target="done")],
                solver=[execution_identity(), react(submit=False, tools=[append_effect(effects_path, registry),
                                                                       delete_note(effects_path, registry)])])


def run_demo(work_dir, witness: bool = True, wait_seconds: float = 2.0,
             calls: Sequence[Tuple[str, ...]] = DEFAULT_CALLS,
             witness_faults: Optional[Dict[str, Any]] = None, backup: bool = False,
             witness_mode: Optional[str] = None, grace_seconds: float = 1.0) -> Dict[str, Any]:
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)
    journal = work / "journal" / "demo.jsonl"
    effects = work / "effects.jsonl"
    witness_dir = work / "witness"
    backup_dir = work / "witness_backup"
    registry = wire.ApprovedCalls()
    approver = witnessed_gate_approver(
        journal=str(journal), witness_dir=str(witness_dir) if witness else None,
        wait_seconds=wait_seconds, backup_witness_dir=str(backup_dir) if backup else None,
        witness_mode=witness_mode, witness_faults=witness_faults, registry=registry)
    try:
        logs = inspect_eval(demo_task(str(effects), registry),
                            model=get_model(MODEL, memoize=False, custom_outputs=scripted_outputs(calls)),
                            approval=[ApprovalPolicy(approver, "*")],
                            log_dir=str(work / "logs"), display="none")
    finally:
        close_gates(grace_seconds)
    log = read_eval_log(logs[0].location)
    events = log.samples[0].events if log.samples else []
    approvals = [{"approver": e.approver, "decision": e.decision, "function": e.call.function,
                  "call_id": e.call.arguments.get("call_id"), "explanation": e.explanation}
                 for e in events if getattr(e, "event", None) == "approval"]
    tool_events = [{"function": e.function, "error": e.error.message if e.error else None}
                   for e in events if getattr(e, "event", None) == "tool"]
    config = getattr(log.eval.config, "approval", None)
    policy = [{"name": a.name, "tools": a.tools} for a in (config.approvers if config else [])]
    return {"status": log.status, "error": log.error.message if log.error else None,
            "approvals": approvals, "tool_events": tool_events,
            "approval_policy": policy, "journal": str(journal),
            "witness_log": str(witness_dir / "log.jsonl"),
            "witness_logs": [str(witness_dir / "log.jsonl")] + ([str(backup_dir / "log.jsonl")] if backup else []),
            "effects": str(effects)}


def pretend_sentinel() -> None:
    """Test hook: the approver's sentinel check answers "a monitor that checks
    tool calls is active" from now on. Inspect's own state is not touched, so
    no sentinel runs; only the approver's branch is exercised."""
    import inspect_approver.approver as approver_module
    approver_module.sentinel_active = lambda: True


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--work-dir", required=True)
    p.add_argument("--witness", choices=("on", "off"), default="on")
    p.add_argument("--wait", type=float, default=2.0)
    p.add_argument("--backup", choices=("on", "off"), default="off")
    p.add_argument("--witness-mode", choices=("both", "failover"), default=None)
    p.add_argument("--main-fault", default=None, help="a faulty_witness mode for the main witness")
    p.add_argument("--calls", default=None, help="comma-separated id:function[:argument_call_id]")
    p.add_argument("--pretend-sentinel", action="store_true",
                   help="test hook: the approver sees a sentinel monitor that checks tool calls")
    args = p.parse_args(argv)
    calls = DEFAULT_CALLS
    if args.calls:
        calls = [tuple(item.split(":", 2)) for item in args.calls.split(",")]
    if args.pretend_sentinel:
        pretend_sentinel()
    result = run_demo(args.work_dir, witness=args.witness == "on", wait_seconds=args.wait, calls=calls,
                      witness_faults={"mode": args.main_fault} if args.main_fault else None,
                      backup=args.backup == "on", witness_mode=args.witness_mode)
    print("RESULT " + canon(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
