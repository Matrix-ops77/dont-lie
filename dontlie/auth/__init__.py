"""Multi-user vault with role-based access and append-only audit log.

See :mod:`dontlie.auth.users` for the full API.
"""

from .users import (
    ACTIONS,
    ROLES,
    ROLE_GRANTS,
    AuthError,
    AuditEntry,
    TeamVault,
    UnknownRoleError,
    UnknownUserError,
    User,
    UserExistsError,
    load,
    persistence_path,
    save,
)

__all__ = [
    "ACTIONS",
    "ROLES",
    "ROLE_GRANTS",
    "AuthError",
    "AuditEntry",
    "TeamVault",
    "UnknownRoleError",
    "UnknownUserError",
    "User",
    "UserExistsError",
    "load",
    "persistence_path",
    "save",
]
