"""Multi-user vault with role-based access control.

A team vault has multiple users with roles. The bundle / receipt surface
is unchanged: only who can issue actions like export, revoke, or share
a verification link is restricted.

Roles
=====

- ``admin``  — full control: invite users, revoke keys, delete receipts.
- ``auditor`` — read everything, run verification, export bundles.
- ``operator`` — append receipts, rotate vault keys, share bundles.
- ``viewer``  — read-only.

Permissions
===========

Each action is encoded as ``<resource>:<verb>``. The mapping:

| Action | admin | auditor | operator | viewer |
|---|---|---|---|---|
| receipt:read | ✓ | ✓ | ✓ | ✓ |
| receipt:append | ✓ | — | ✓ | — |
| receipt:export | ✓ | ✓ | ✓ | — |
| receipt:delete | ✓ | — | — | — |
| key:revoke | ✓ | — | ✓ | — |
| key:rotate | ✓ | — | ✓ | — |
| user:invite | ✓ | — | — | — |
| user:list | ✓ | ✓ | ✓ | — |
| audit:read | ✓ | ✓ | — | — |

The audit log is append-only. Every successful permission check is
recorded with the user, action, target, and timestamp.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROLES = ("admin", "auditor", "operator", "viewer")
ACTIONS = (
    "receipt:read",
    "receipt:append",
    "receipt:export",
    "receipt:delete",
    "key:revoke",
    "key:rotate",
    "user:invite",
    "user:list",
    "audit:read",
)

# role -> set of actions
ROLE_GRANTS: dict[str, frozenset[str]] = {
    "admin": frozenset(ACTIONS),
    "auditor": frozenset({"receipt:read", "receipt:export", "user:list", "audit:read"}),
    "operator": frozenset({
        "receipt:read", "receipt:append", "receipt:export",
        "key:revoke", "key:rotate", "user:list",
    }),
    "viewer": frozenset({"receipt:read"}),
}


class AuthError(Exception):
    """Raised on any authorization failure."""


class UserExistsError(AuthError):
    """Raised when adding a user that already exists."""


class UnknownRoleError(AuthError):
    """Raised when assigning a role that doesn't exist."""


class UnknownUserError(AuthError):
    """Raised when an action is taken by an unknown user."""


@dataclass(frozen=True)
class User:
    user_id: str
    email: str
    role: str
    api_key: str
    created_at: str

    def allows(self, action: str) -> bool:
        if action not in ACTIONS:
            raise AuthError(f"unknown action: {action!r}")
        return action in ROLE_GRANTS[self.role]


@dataclass
class AuditEntry:
    timestamp: str
    user_id: str
    action: str
    target: str
    outcome: str
    properties: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "action": self.action,
            "target": self.target,
            "outcome": self.outcome,
            "properties": dict(self.properties),
        }


class TeamVault:
    """In-memory team vault with role-based access and an audit log."""

    def __init__(self) -> None:
        self.users: dict[str, User] = {}
        self.audit: list[AuditEntry] = []

    @staticmethod
    def _hash_key(api_key: str) -> str:
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

    def add_user(self, email: str, role: str, *, user_id: str | None = None) -> tuple[User, str]:
        if role not in ROLES:
            raise UnknownRoleError(f"unknown role: {role!r}")
        for user in self.users.values():
            if user.email.lower() == email.lower():
                raise UserExistsError(f"user already exists: {email}")
        api_key = f"dlk_{secrets.token_urlsafe(32)}"
        record = User(
            user_id=user_id or secrets.token_hex(8),
            email=email,
            role=role,
            api_key=self._hash_key(api_key),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.users[record.user_id] = record
        return record, api_key

    def authenticate(self, api_key: str) -> User:
        digest = self._hash_key(api_key)
        for user in self.users.values():
            if hmac.compare_digest(user.api_key, digest):
                return user
        raise UnknownUserError("invalid api key")

    def authorize(self, user: User, action: str, target: str = "") -> None:
        if not user.allows(action):
            self._log(user, action, target, "denied")
            raise AuthError(f"role {user.role!r} cannot perform {action!r}")
        self._log(user, action, target, "ok")

    def _log(self, user: User, action: str, target: str, outcome: str, **properties: object) -> None:
        self.audit.append(
            AuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                user_id=user.user_id,
                action=action,
                target=target,
                outcome=outcome,
                properties=dict(properties),
            )
        )

    def audit_log(self, *, for_user: User | None = None) -> list[dict]:
        if for_user is not None:
            self.authorize(for_user, "audit:read")
        return [entry.to_dict() for entry in self.audit]


def persistence_path() -> Path:
    """Resolve the persistence path from env or default to ./team-vault.json."""
    config = os.environ.get("DONTLIE_TEAM_VAULT_PATH", "team-vault.json")
    return Path(config)


def save(team: TeamVault, path: Path | None = None) -> None:
    path = path or persistence_path()
    payload = {
        "users": [
            {
                "user_id": u.user_id,
                "email": u.email,
                "role": u.role,
                "api_key_hash": u.api_key,
                "created_at": u.created_at,
            }
            for u in team.users.values()
        ],
        "audit": [entry.to_dict() for entry in team.audit],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load(path: Path | None = None) -> TeamVault:
    path = path or persistence_path()
    if not path.exists():
        return TeamVault()
    payload = json.loads(path.read_text(encoding="utf-8"))
    team = TeamVault()
    for entry in payload.get("users", []):
        user = User(
            user_id=entry["user_id"],
            email=entry["email"],
            role=entry["role"],
            api_key=entry["api_key_hash"],
            created_at=entry["created_at"],
        )
        team.users[user.user_id] = user
    return team


__all__ = [
    "ACTIONS",
    "ROLES",
    "ROLE_GRANTS",
    "AuditEntry",
    "AuthError",
    "TeamVault",
    "UnknownRoleError",
    "UnknownUserError",
    "User",
    "UserExistsError",
    "load",
    "persistence_path",
    "save",
]
