"""An Inspect approver built on witnessed_gate (inspect_ai 0.3.291).

Each tool call Inspect hands the approver goes through the gate's steps:
journaled as given, its fingerprint sent to the witness process (or to both
witnesses, with a backup), and approved only once the gate holds a valid
signed stamp for it. Otherwise the call is rejected. The approver never
changes the call.

The record's call_id is Inspect's own tool-call id (call.id); a call_id among
the tool's arguments is journaled with the other arguments and never used as
the call's identity. Each approved record goes into a registry owned by
that gate; a tool takes the approved record for its framework call id, with
exactly its own function and arguments, and writes the effects line, version 2,
bound to that record's fingerprint.

How it is made the only approver, applied to every tool, as implemented by
inspect_ai 0.3.291:
- Pass it at eval level: eval(..., approval=[ApprovalPolicy(approver, "*")]).
  eval_resolve_tasks sets it with init_tool_approval (inspect_ai/_eval/eval.py),
  and a task's own policy is used only when none is active (init_task_context
  in inspect_ai/_eval/context.py: `if not have_tool_approval()`), so this one
  replaces any task-level policy.
- "*" holds a glob character, so tool_call_matcher matches it with fnmatch
  against every function name (inspect_ai/approval/_policy.py).
- The agent is react(submit=False) with no approval= argument: react(approval=...)
  would replace the active policies inside the agent (inspect_ai/agent/_react.py,
  react_no_submit passes approval=None to execute_tools, which then keeps the
  active policy).
- A sentinel monitor runs after the approvers and may change the call's
  arguments, and Inspect then runs the changed call without asking the
  approvers again (inspect_ai/model/_call_tools.py: sentinel_before_tool_call,
  then revalidated_tool_call). The stamp would then cover a call that never
  ran. So this approver rejects every call while a sentinel is active that
  watches tool calls, or whose stages it cannot read: it asks
  active_sentinel() (inspect_ai/_sentinel/_context.py, which _call_tools.py
  itself imports) and then _watches(BeforeToolCall) (_sentinel/_dispatch.py),
  both private functions of 0.3.291, and it refuses to install on an Inspect
  without active_sentinel, where it could not tell. The approver runs in a
  "final" sentinel scope, so the public checks_tool_calls() reads False inside
  it and cannot be used for this. If the optional
  inspect_sentinel package is absent and _dispatch cannot be imported, any
  active sentinel is conservatively treated as watching tool calls.
- The approver must not change the call in place: Inspect refuses an "approve"
  whose call was changed (approver_result_error, inspect_ai/model/_call_tools.py).
Inspect counts time in an approver as waiting (apply_tool_approval runs it
under suspend_limits). The gate's wait_seconds bounds stamp waiting; total
latency also includes locking, storage and catch-up.
"""
import copy
from typing import Any, Dict, List, Optional, Tuple

import anyio
from inspect_ai.approval import Approval, Approver, approver
from inspect_ai.model import ChatMessage
from inspect_ai.tool import ToolCall, ToolCallView

from witnessed_gate import wire
from witnessed_gate.gate import CloseReport, Gate, GateCrashed, WitnessClient

INSPECT_ROUTES = ["every tool call that Inspect runs itself and hands to its approval policy; "
                  "this approver is the only policy, for '*'"]
SENTINEL_REASON = ("rejected: a sentinel monitor that checks tool calls is active, and it may change "
                   "the call after this approval, so a stamp would not cover the call that runs")

EMPTY_ID_REASON = ("rejected: the tool call has no id, so its run could not be bound to its own approval")
REPEATED_ID_REASON = ("rejected: the tool-call id %r was used before in this gate, so its run could not be bound to "
                      "its own approval; an approval still waiting under that id is revoked")

REVOKED_REASON = ("rejected: the tool-call id %r was used by another call while this one was decided, so its "
                  "approval, though journaled, cannot be bound to a run and is withheld")

# the gates this process has opened, by journal path, so a runner can close them
OPEN_GATES: Dict[str, Tuple[Gate, List[WitnessClient]]] = {}


def can_see_sentinels() -> bool:
    """Whether this Inspect lets the approver see an active sentinel monitor."""
    try:
        from inspect_ai._sentinel._context import active_sentinel
    except ImportError:
        return False
    return callable(active_sentinel)


def sentinel_active() -> bool:
    """True while a sentinel monitor is active that watches tool calls, or
    whose stages cannot be read (then it is taken as watching them). Looked up
    by name at each call, so the demo's test hook can stand in for it."""
    from inspect_ai._sentinel._context import active_sentinel
    if active_sentinel() is None:
        return False
    try:
        from inspect_ai._sentinel import _dispatch
        return bool(_dispatch._watches(_dispatch.BeforeToolCall))
    except (ImportError, AttributeError):
        return True


@approver(name="witnessed_gate")
def witnessed_gate_approver(journal: str, witness_dir: Optional[str] = None,
                            wait_seconds: float = 2.0, backup_witness_dir: Optional[str] = None,
                            witness_mode: Optional[str] = None,
                            witness_faults: Optional[Dict[str, Any]] = None,
                            backup_faults: Optional[Dict[str, Any]] = None,
                            operator: str = "the eval's runner; the witness is a separate process on the same machine",
                            full_fsync: bool = False, registry: Optional[wire.ApprovedCalls] = None
                            ) -> Approver:
    """The witnessed gate as an Inspect approver.

    Args:
        journal: The record file of the gate's journal (its decision file sits beside it).
        witness_dir: The main witness's state directory; None runs with no main witness.
        wait_seconds: How long the gate waits for a stamp before it gives up.
        backup_witness_dir: The backup witness's state directory; None runs with one witness.
        witness_mode: With a backup, "both" (default: every fingerprint to both) or "failover".
        witness_faults: A faulty main witness for tests (see witnessed_gate.faulty_witness).
        backup_faults: A faulty backup witness for tests.
        operator: Who runs the witness, written in the journal's open line.
        full_fsync: Sync the journal and both witnesses' logs with F_FULLFSYNC.
        registry: This gate's approval registry; by default the gate owns a fresh one.

    It rejects every call while a sentinel monitor that checks tool calls is
    active, since such a monitor may change a call after it is approved, and it
    refuses to install where it cannot tell (see the module's docstring).
    """
    if not can_see_sentinels():
        raise RuntimeError("this Inspect gives no way to tell whether a sentinel monitor may change a call "
                           "after approval, so the witnessed gate does not install")
    clients: List[Optional[WitnessClient]] = []
    gate = None
    try:
        if witness_dir:
            clients.append(WitnessClient.launch(witness_dir, faults=witness_faults, full_fsync=full_fsync))
        if backup_witness_dir:
            if not witness_dir:
                clients.append(None)
            clients.append(WitnessClient.launch(backup_witness_dir, faults=backup_faults, full_fsync=full_fsync))
        gate = Gate(journal, witnesses=clients, wait_seconds=wait_seconds, witness_mode=witness_mode,
                    operator=operator, routes=INSPECT_ROUTES, full_fsync=full_fsync)
        approved = registry if registry is not None else gate.approved_calls
        approved.bind(gate)
        gate.approved_calls = approved
    except BaseException:
        if gate is not None:
            gate.journal.close()
        for client in clients:
            if client is not None:
                client.kill()
        raise
    clients = [client for client in clients if client is not None]
    OPEN_GATES[str(journal)] = (gate, clients)

    async def approve(message: str, call: ToolCall, view: ToolCallView,
                      history: list[ChatMessage]) -> Approval:
        reasons = []
        try:
            if sentinel_active():
                reasons.append(SENTINEL_REASON)
        except Exception as exc:  # noqa: BLE001 - a check that fails counts as an active sentinel
            reasons.append("rejected: the sentinel check failed (%s: %s), so the call is taken as one a sentinel "
                           "monitor might change after approval" % (exc.__class__.__name__, exc))
        token = None
        if not isinstance(call.id, str) or not call.id:  # framework identities must be new and nonempty
            reasons.append(EMPTY_ID_REASON)
        else:
            token = approved.claim(call.id)  # only this claim token can register the approval
            if token is None:
                approved.revoke(call.id)
                reasons.append(REPEATED_ID_REASON % (call.id,))
        policy_refusal = "; ".join(reasons) or None
        arguments = copy.deepcopy(call.arguments)  # journal the call as given; never change it
        content = {"call_id": call.id, "tool_call_id": call.id, "function": call.function,
                   "arguments": arguments}
        try:
            decision = await anyio.to_thread.run_sync(lambda: gate.decide(content, policy_refusal=policy_refusal))
        except GateCrashed as exc:
            return Approval(decision="reject", metadata={"outcome": "crashed"},
                            explanation="the gate stopped after a failed journal write, so no call runs: %s" % exc)
        metadata: Dict[str, Any] = {"record_fp": decision.fp, "outcome": decision.outcome}
        if decision.catch_up_error is not None:
            metadata["catch_up_error"] = decision.catch_up_error
        if decision.stamp:
            metadata["witness"] = decision.witness
            metadata["witness_index"] = decision.stamp.get("index")
        if decision.approved and not approved.add(decision.record, token=token):
            metadata["outcome"] = "revoked"  # another call took this id while it was decided
            return Approval(decision="reject", metadata=metadata, explanation=REVOKED_REASON % (call.id,))
        return Approval(decision="approve" if decision.approved else "reject",
                        explanation=decision.reason, metadata=metadata)

    return approve


class CloseGatesError(Exception):
    """close_gates() attempted every close and witness stop. `reports` maps
    journal paths to returned CloseReports; `errors` maps each failed journal
    path to a list of operation, client and error details."""

    def __init__(self, reports: Dict[str, CloseReport], errors: Dict[str, List[Dict[str, Any]]]):
        super().__init__("%d of %d gates failed to close cleanly: %s" % (
            len(errors), len(set(reports) | set(errors)),
            "; ".join("%s: %s" % (k, ", ".join("%s %s" % (f["operation"], f["error"]) for f in v))
                      for k, v in errors.items())))
        self.reports, self.errors = reports, errors


def close_gates(grace_seconds: float = 0.0) -> Dict[str, CloseReport]:
    """Close every gate this process opened (after up to grace_seconds for
    second stamps and catch-up), stop their witness processes, and return each
    gate's CloseReport by journal path. Every gate is closed even if some fail;
    then, if any failed, CloseGatesError carries every report and every error."""
    reports: Dict[str, CloseReport] = {}
    errors: Dict[str, List[Dict[str, Any]]] = {}
    for key, (gate, clients) in list(OPEN_GATES.items()):
        failures: List[Dict[str, Any]] = []  # every error of this gate, with its operation and client
        try:
            reports[key] = gate.close(grace_seconds)
        except Exception as exc:  # noqa: BLE001 - collected, and raised together below
            failures.append({"operation": "close", "client": None, "error": exc})
        finally:
            for client in clients:
                try:
                    client.stop()
                except Exception as exc:  # noqa: BLE001
                    failures.append({"operation": "stop", "client": getattr(client, "witness_id", None),
                                     "error": exc})
            OPEN_GATES.pop(key, None)
        if failures:
            errors[key] = failures
    if errors:
        raise CloseGatesError(reports, errors)
    return reports
