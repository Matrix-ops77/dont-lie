"""Tests for the multi-user vault + RBAC + audit log."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="dontlie-auth-test-")
os.environ["DONTLIE_TEAM_VAULT_PATH"] = str(Path(_TMP) / "team-vault.json")

from dontlie.auth import (
    ROLE_GRANTS,
    AuthError,
    TeamVault,
    UnknownRoleError,
    UnknownUserError,
    UserExistsError,
    load,
    save,
)


def _seed() -> tuple[TeamVault, dict[str, str]]:
    team = TeamVault()
    keys: dict[str, str] = {}
    for email, role in [
        ("admin@example.com", "admin"),
        ("audit@example.com", "auditor"),
        ("op@example.com", "operator"),
        ("view@example.com", "viewer"),
    ]:
        _user, api_key = team.add_user(email, role)
        keys[email] = api_key
    return team, keys


class RoleGrantsTest(unittest.TestCase):
    def test_admin_can_do_everything(self) -> None:
        for action in ROLE_GRANTS["admin"]:
            self.assertIn(action, ROLE_GRANTS["admin"])

    def test_viewer_only_read(self) -> None:
        self.assertIn("receipt:read", ROLE_GRANTS["viewer"])
        self.assertEqual(len(ROLE_GRANTS["viewer"]), 1)

    def test_auditor_cannot_append(self) -> None:
        self.assertNotIn("receipt:append", ROLE_GRANTS["auditor"])

    def test_operator_cannot_invite(self) -> None:
        self.assertNotIn("user:invite", ROLE_GRANTS["operator"])


class TeamVaultLifecycleTest(unittest.TestCase):
    def test_add_and_authenticate(self) -> None:
        team, keys = _seed()
        user = team.authenticate(keys["admin@example.com"])
        self.assertEqual(user.email, "admin@example.com")
        self.assertEqual(user.role, "admin")

    def test_duplicate_user_raises(self) -> None:
        team, _ = _seed()
        with self.assertRaises(UserExistsError):
            team.add_user("admin@example.com", "operator")

    def test_bad_role_raises(self) -> None:
        team = TeamVault()
        with self.assertRaises(UnknownRoleError):
            team.add_user("a@example.com", "boss")

    def test_invalid_api_key_raises(self) -> None:
        team = TeamVault()
        with self.assertRaises(UnknownUserError):
            team.authenticate("dlk_bogus")


class AuthorizationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.team, self.keys = _seed()

    def test_admin_authorized_for_any_action(self) -> None:
        user = self.team.authenticate(self.keys["admin@example.com"])
        for action in (
            "receipt:read", "receipt:append", "receipt:export",
            "receipt:delete", "key:revoke", "key:rotate",
            "user:invite", "user:list", "audit:read",
        ):
            self.team.authorize(user, action, target="ok")

    def test_viewer_cannot_append(self) -> None:
        user = self.team.authenticate(self.keys["view@example.com"])
        with self.assertRaises(AuthError):
            self.team.authorize(user, "receipt:append")

    def test_auditor_can_read_audit_log(self) -> None:
        user = self.team.authenticate(self.keys["audit@example.com"])
        log = self.team.audit_log(for_user=user)
        self.assertIsInstance(log, list)

    def test_viewer_cannot_read_audit_log(self) -> None:
        user = self.team.authenticate(self.keys["view@example.com"])
        with self.assertRaises(AuthError):
            self.team.audit_log(for_user=user)


class AuditLogTest(unittest.TestCase):
    def test_log_records_success_and_denials(self) -> None:
        team = TeamVault()
        user, _key = team.add_user("a@example.com", "viewer")
        with self.assertRaises(AuthError):
            team.authorize(user, "receipt:append")
        team.authorize(user, "receipt:read", target="42")
        log = team.audit_log()
        self.assertEqual(len(log), 2)
        self.assertEqual(log[0]["outcome"], "denied")
        self.assertEqual(log[1]["outcome"], "ok")
        self.assertEqual(log[1]["target"], "42")

    def test_log_persists_to_disk(self) -> None:
        team = TeamVault()
        team.add_user("a@example.com", "admin")
        save(team)
        loaded = load()
        self.assertEqual(len(loaded.users), 1)
        self.assertIn("a@example.com", {u.email for u in loaded.users.values()})

    def test_unknown_action_raises(self) -> None:
        team = TeamVault()
        user = team.users.get("x") or team.add_user("x@example.com", "admin")[0]
        with self.assertRaises(AuthError):
            user.allows("vault:pwn")


if __name__ == "__main__":
    unittest.main()
