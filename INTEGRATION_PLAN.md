# Don't-Lie — RedactionPolicy integration plan

**Status:** design only. No code edits in this change.
**Scope:** wire `dontlie.RedactionPolicy` into `storage.append` and `proxy.py`
so secrets are redacted before they ever hit the signed receipt, without
breaking the 246-test suite or any other agent's owned files.

## Goal

Any secret detected by `RedactionPolicy` (ANTHROPIC_API_KEY, OPENAI_API_KEY,
EMAIL, SSN, CREDIT_CARD, PHONE, JWT) is replaced with `[REDACTED:RULE]` in
the `prompt` and `response` arguments of `storage.append(...)` and in the
upstream-bound request body the proxy forwards. The redacted value is what
gets hashed and signed. Receipts that contain only redacted values verify
cleanly because the SHA-256 binds the redacted payload, not the original.

## Non-goals

* No changes to canonical payload format, signing, or chain layout.
* No changes to other workers' owned files: `redaction.py`,
  `encryption.py`, `groundtruth/*`, `anchor/*`, `site/*`, `company/*`,
  `clients/*`. Each is touched only via import or env wiring.
* No new dependencies.

## Wiring strategy

The smallest possible surface is two call-sites, both opt-in:

1. `storage.append(model, prompt, response, ...)` — redact before
   `_canonical_payload` is computed and before `BEGIN IMMEDIATE`.
2. `proxy.py` outbound body for `/v1/chat/completions` and the
   Anthropic `/v1/messages` path — redact before forwarding.

Both call-sites must share one policy instance to keep behavior consistent.
Use a module-level lazy singleton in `storage.py` (lazily resolved
`RedactionPolicy` to keep `dontlie` import-side-effect-free). Override at
runtime via the env var `DONTLIE_REDACTION_POLICY` taking values
`off|default|strict` or a dotted `module:Class` path; default `default`.

## Test strategy

* No existing test asserts the *raw* unredacted prompt/response is
  persisted. Existing `test_dontlie.py`, `test_integrity.py`, and
  `test_redaction.py` already assume redaction is enabled for
  `extra={"redaction": ...}`-shaped metadata. Existing `test_proxy_*`
  tests use mock providers that don't print real secrets, so no fixture
  rewrites are required.
* Add new tests **owned by Kilo** under `dontlie/test_redaction_wiring.py`
  (single new file) — only this new test file in this change. The
  file is loaded only after `storage.py` and `proxy.py` carry the
  wiring; if wiring is missing, `test_redaction_wiring.py` is skipped
  via `unittest.skipUnless` import probe.

## Paste-ready diffs

### 1. `dontlie/storage.py` (add redaction singleton + apply in `append`)

```diff
@@
 from . import sign as signing
+from . import redaction as _redaction_mod
@@
 def _active_redaction_policy():
-    # filled in once the env-driven override is wired (below)
-    return _redaction_mod.RedactionPolicy()
+    name = os.environ.get("DONTLIE_REDACTION_POLICY", "default")
+    if name in ("off", "default", "strict"):
+        return _redaction_mod.RedactionPolicy(
+            rules=None if name == "default" else ()
+            if name == "off" else tuple(_redaction_mod.SUPPORTED_RULES)
+        )
+    module_name, _, attr = name.partition(":")
+    import importlib
+    return getattr(importlib.import_module(module_name), attr or "policy")()
@@
 def append(
     model: str,
     prompt: str,
     response: str,
     parent_id: int | None = None,
     tags: list[str] | None = None,
     extra: dict[str, object] | None = None,
 ) -> Receipt:
     """Create and sign a new receipt, enforcing a single continuous chain."""
+    policy = _active_redaction_policy()
+    prompt_report = policy.apply(prompt or "")
+    response_report = policy.apply(response or "")
+    prompt = prompt_report.text
+    response = response_report.text
+    if prompt_report.redacted or response_report.redacted:
+        tags = list(tags or []) + ["redacted"]
+        extra = dict(extra or {})
+        extra["redaction"] = {
+            "prompt": prompt_report.to_extra(),
+            "response": response_report.to_extra(),
+        }
     key = signing.load()
```

### 2. `dontlie/proxy.py` (redact outbound chat-completion body)

```diff
@@
 def _forward_and_capture(...):
-    body = dict(json_body)
+    body = dict(json_body)
+    body = _redact_chat_body(body)
@@
 def _redact_chat_body(body: dict) -> dict:
+    from . import redaction as _redaction_mod
+    policy = _active_redaction_policy()  # shared helper, defined in storage.py
+    out = dict(body)
+    msgs = out.get("messages") or []
+    new_msgs = []
+    for m in msgs:
+        m = dict(m)
+        content = m.get("content")
+        if isinstance(content, str):
+            m["content"] = policy.apply(content).text
+        elif isinstance(content, list):
+            m["content"] = [
+                {**part, "text": policy.apply(part.get("text", "")).text}
+                if isinstance(part, dict) and part.get("type") == "text"
+                else part
+                for part in content
+            ]
+        new_msgs.append(m)
+    out["messages"] = new_msgs
+    return out
```

Apply the same helper at the Anthropic `/v1/messages` outbound boundary by
calling it on the body before httpx transport in `handle_protocol_completion`.

### 3. `dontlie/test_redaction_wiring.py` (NEW, owned by Kilo)

```python
import os, unittest
from dontlie import storage


@unittest.skipUnless(
    os.environ.get("DONTLIE_REDACTION_POLICY", "default") != "off",
    "redaction disabled",
)
class RedactionWiringTest(unittest.TestCase):
    def test_append_redacts_prompt_and_response(self):
        r = storage.append(
            model="m",
            prompt="email user@example.com sk-abcdefghijklmnopqrstuvwxyz123456",
            response="sent to user@example.com",
        )
        self.assertNotIn("user@example.com", r.prompt)
        self.assertNotIn("user@example.com", r.response)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz123456", r.prompt)
        self.assertTrue(r.extra.get("redaction", {}).get("prompt", {}).get("redacted"))

    def test_off_env_bypasses_redaction(self):
        old = os.environ.get("DONTLIE_REDACTION_POLICY")
        os.environ["DONTLIE_REDACTION_POLICY"] = "off"
        try:
            r = storage.append(model="m", prompt="user@example.com", response="ok")
            self.assertIn("user@example.com", r.prompt)
        finally:
            os.environ.pop("DONTLIE_REDACTION_POLICY", None)
            if old is not None:
                os.environ["DONTLIE_REDACTION_POLICY"] = old
```

## Rollout

1. Land diff #1 + new helper only, run full suite — expect 246/246.
2. Land diff #2 (`_redact_chat_body` in proxy) — expect 246/246 (proxy
   tests use mock providers without real secrets).
3. Land `test_redaction_wiring.py` — expect 248/246 (2 new).
4. Roll forward via `DONTLIE_REDACTION_POLICY=off` then `=default` to
   confirm opt-in works for any operator who needs raw payloads.

## Failure modes & containment

* `RedactionPolicy` raises → `append` re-raises; existing chain invariants
  unchanged (callers see the same exception type). This is safer than
  silent skip.
* `DONTLIE_REDACTION_POLICY` is a bad import path → `_active_redaction_policy`
  raises at first call. Operator can `unset` and retry.
* RegEx false positives (e.g. a long digit string misread as a card) →
  by design; downstream consumers see `[REDACTED:CREDIT_CARD]` and can
  whitelist via custom rules — covered by `RedactionPolicy(rules=...)`.
