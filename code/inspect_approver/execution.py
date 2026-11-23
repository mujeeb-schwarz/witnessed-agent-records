"""Read execution identity from Inspect's per-sample execution observer.

Install before tools run. Inspect passes call.id to track_tool_call around
approval and execution, including concurrent calls. No model argument or
approval queue supplies the identity. These are private APIs of 0.3.291.
"""
from contextlib import contextmanager
from contextvars import ContextVar

_call_id = ContextVar("witnessed_gate_inspect_call_id", default=None)


def current_call_id():
    return _call_id.get()


class IdentityObserver:
    def __init__(self, delegate):
        self.delegate = delegate

    @contextmanager
    def track_tool_call(self, tool_call_id, event=None):
        token = _call_id.set(tool_call_id)
        try:
            with self.delegate.track_tool_call(tool_call_id, event):
                yield
        finally:
            _call_id.reset(token)

    def track_model_event(self, event):
        return self.delegate.track_model_event(event)


def install_execution_identity():
    from inspect_ai.log._samples import sample_active
    sample = sample_active()
    if sample is None:
        raise RuntimeError("execution identity must be installed in an Inspect sample")
    if not isinstance(sample.execution_observer, IdentityObserver):
        sample.execution_observer = IdentityObserver(sample.execution_observer)
