"""Version 2 effects bind each execution to an approved record and exact action.

  {"call_id": str, "exec_id": 32 hex, "record_fp": 64 hex, "function": str,
   "args_sha256": 64 hex, "wall_ns": int}

`record_fp` is the fingerprint of the approved record this execution used,
`exec_id` is new for every execution, and `function` and `args_sha256` (sha256
of the canonical JSON of the arguments) let the checker compare the effect with
the record's content. The binding uses the framework's execution identity,
plus the exact function and arguments. In Inspect this identity is the tool
call's own id; in the bench it is the call_id of the record write() returned.
Model arguments never
supply this identity. Each gate owns its own ApprovedCalls registry.

What a record's action is, for that comparison (`record_action`):
  an Inspect record   its `function` and its `arguments`;
  a bench record      its `action_kind` (the handover's action) and its
                      `handover`, the thing the courier delivers.

An execution without an approval for its exact identity writes an unbound
line, so an unused approval for an identical action cannot conceal it.
"""
import copy
import os
import threading
import time
from typing import Any, Dict, Optional, Tuple

from witnessed_gate.common import canon_bytes, sha256_hex

EFFECT_FORMAT = 2
EFFECT_FIELDS = ("call_id", "exec_id", "record_fp", "function", "args_sha256", "wall_ns")


def args_sha256(arguments: Any) -> str:
    """sha256 of the canonical JSON of a call's arguments."""
    return sha256_hex(canon_bytes(arguments))


def new_exec_id() -> str:
    """A new execution id: 16 random bytes, as 32 hex characters."""
    return os.urandom(16).hex()


def record_action(record: Dict[str, Any]) -> Tuple[Optional[str], Any]:
    """The function and arguments a record stands for (see the module's docstring)."""
    if isinstance(record.get("function"), str) and "arguments" in record:
        return record["function"], record["arguments"]
    return record.get("action_kind"), record.get("handover")


def effect_line(record: Dict[str, Any], wall_ns: Optional[int] = None) -> Dict[str, Any]:
    """The effects line for one execution of an approved record."""
    if not isinstance(record, dict) or not isinstance(record.get("fp"), str):
        raise ValueError("an effects line is built from a record the gate returned, with its fp")
    function, arguments = record_action(record)
    call_id = record.get("call_id")
    return {"call_id": call_id if isinstance(call_id, str) else "", "exec_id": new_exec_id(),
            "record_fp": record["fp"], "function": function, "args_sha256": args_sha256(arguments),
            "wall_ns": time.time_ns() if wall_ns is None else wall_ns}


def unbound_effect_line(function: str, arguments: Any) -> Dict[str, Any]:
    """The line of an execution that no approved record covers."""
    return {"call_id": "", "exec_id": new_exec_id(), "record_fp": None, "function": function,
            "args_sha256": args_sha256(arguments), "wall_ns": time.time_ns()}


class ApprovedCalls:
    """One gate's approvals, consumed once by exact framework call identity."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._owner = None
        self._waiting: Dict[str, Dict[str, Any]] = {}
        self._seen = set()         # identities approved
        self._claimed = {}         # identity -> its claim token
        self._revoked = set()      # identities revoked for good: nothing registers under them again

    def bind(self, owner) -> None:
        with self._lock:
            if self._owner is not None and self._owner is not owner:
                raise ValueError("an approval registry belongs to only one gate")
            self._owner = owner

    def add(self, record: Dict[str, Any], token: Optional[object] = None) -> bool:
        """Register an approval. False, with nothing registered, when its identity
        was revoked, or its claim's matching token is missing or incorrect.
        Unclaimed bench identities may still register without a token."""
        identity = record.get("call_id")
        if not isinstance(identity, str) or not identity:
            raise ValueError("an approved record needs its framework call_id")
        with self._lock:
            if identity in self._revoked:
                return False
            if ((identity in self._claimed or token is not None)
                    and self._claimed.get(identity) is not token):
                return False
            if identity in self._seen:
                raise ValueError("a framework call_id cannot be approved twice in one gate")
            self._seen.add(identity)
            self._waiting[identity] = copy.deepcopy(record)
            return True

    def claim(self, identity: str) -> Optional[object]:
        """Claim a framework call identity for one approval: a token, or None if
        it was presented, approved or revoked before in this registry. Only the
        token's holder can register an approval under it."""
        with self._lock:
            if (not isinstance(identity, str) or not identity or identity in self._claimed
                    or identity in self._seen or identity in self._revoked):
                return None
            token = object()
            self._claimed[identity] = token
            return token

    def seen(self, identity: str) -> bool:
        """Whether this identity was presented or approved before."""
        with self._lock:
            return identity in self._claimed or identity in self._seen or identity in self._revoked

    def revoke(self, identity: str) -> Optional[Dict[str, Any]]:
        """Withdraw the approval waiting under this identity, and invalidate the
        identity for good: no approval registers under it afterwards, not even
        one whose decision was still pending."""
        with self._lock:
            self._revoked.add(identity)
            self._claimed.pop(identity, None)
            return self._waiting.pop(identity, None)

    def take(self, function: str, arguments: Any, *, execution_id: Optional[str]) -> Optional[Dict[str, Any]]:
        with self._lock:
            rec = self._waiting.get(execution_id)
            if rec is None:
                return None
            expected_function, expected_args = record_action(rec)
            if expected_function != function or args_sha256(expected_args) != args_sha256(arguments):
                return None
            return self._waiting.pop(execution_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._waiting)


def effect_for_call(function: str, arguments: Any, registry: ApprovedCalls, *,
                    execution_id: Optional[str]) -> Dict[str, Any]:
    """Bind only the approval for this framework identity and exact action."""
    rec = registry.take(function, arguments, execution_id=execution_id)
    if rec is not None:
        return effect_line(rec)
    line = unbound_effect_line(function, arguments)
    line["call_id"] = execution_id if isinstance(execution_id, str) else ""
    return line
