"""dontlie.alerts: operator alerting via generic webhooks."""
from .webhooks import (
    Alert,
    AlertError,
    AlertSink,
    alert_chain_break,
    alert_key_revoked,
    from_env,
    send,
    send_event,
)

__all__ = [
    "Alert",
    "AlertError",
    "AlertSink",
    "alert_chain_break",
    "alert_key_revoked",
    "from_env",
    "send",
    "send_event",
]
