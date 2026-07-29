# Don't-Lie integration API

`dontlie.integrations` is a dependency-light bridge from model, tool, approval,
and denial events to the existing signed `Receipt` shape. It implements a
framework-neutral event envelope, callback, decorator, and context manager. It
does not implement or monkey-patch LangGraph, CrewAI, OpenAI, Anthropic, or MCP
SDKs; `examples/clients.py` shows explicit wiring at application boundaries.

## Recording

```python
from dontlie.integrations import ActionEvent, ActionRecorder, correlation_scope

recorder = ActionRecorder()
with correlation_scope("run-42"):
    with recorder.action("tool", "calculator", {"expression": "2+2"}) as event:
        event["output"] = 4

recorder.record(ActionEvent(
    action="denial",
    name="shell.delete",
    input={"path": "/important"},
    output={"approved": False},
    correlation_id="run-42",
))
```

`ActionEvent.as_dict()` emits a CloudEvents-shaped envelope with `specversion`,
`type`, `id`, `source`, `time`, `subject`, and `data`. Pass that mapping to
`ActionRecorder.callback()` across an MCP notification handler, queue consumer,
or framework callback. This is transport-compatible JSON, not a registered MCP
method or SDK plugin.

## Receipt mapping

- `name` becomes `Receipt.model`.
- serialized `input` and `output` become `prompt` and `response`.
- `integration`, action kind, and custom tags become signed receipt tags.
- action, status, correlation ID, event timestamp, and metadata are stored under
  signed `extra.integration`.

## Failure semantics

The default `failure_mode="raise"` wraps vault/signing failures in
`RecordingError`. Decorators and context managers always re-raise the original
application exception after attempting to record a failed action; failed-action
receipts contain only the exception type, not its message. Set
`failure_mode="return_none"` when telemetry must be best-effort: callback and
recording failures then return `None`. This mode can lose audit events, so the
application should count or surface `None` results.

## Correlation IDs

Supply an existing trace/run ID or use `correlation_scope()`. Nested recording in
the same context shares that ID; without a scope each event receives a random
UUID. Correlation IDs are searchable metadata, not authentication tokens, and
must not contain secrets.

## Privacy

Common credential keys are recursively replaced with `[REDACTED]` by default.
This is a narrow safety net, not data-loss prevention: prompts, outputs, tool
arguments, metadata values, and uncommon credential names may contain personal
or confidential data. Minimize payloads before recording and set explicit
retention/access controls on the local vault. `redact=False` should only be used
when upstream sanitization is demonstrably enforced. Signed receipts prove
local record integrity, not model truth, provider provenance, or user consent.
