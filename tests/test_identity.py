from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cooperation_assurance.api import JsonApplication
from cooperation_assurance.clock import FrozenClock
from cooperation_assurance.errors import Conflict, Forbidden, InvalidState, Unauthorized, ValidationFailed
from cooperation_assurance.service import AssuranceService
from cooperation_assurance.storage import connect


ADMIN_PASSWORD = "admin-pass-0001"
USER_PASSWORD = "user-pass-0001"


class IdentityChainTests(unittest.TestCase):
    """首次初始化、日常开户、角色调整、停用与凭据校验的领域规则。"""

    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 10, 4, 8, 0, tzinfo=timezone.utc))
        self.service = AssuranceService(self.connection, self.clock)
        self.service.bootstrap_admin("admin", "初始化管理员", ADMIN_PASSWORD)

    def tearDown(self) -> None:
        self.connection.close()

    def _denials(self) -> list[dict]:
        rows = self.connection.execute(
            "SELECT payload_json FROM audit_events WHERE event_type='auth.denied' ORDER BY event_id"
        ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def test_bootstrap_records_authorization_source(self) -> None:
        directory = self.service.user_directory("admin")
        self.assertEqual(len(directory), 1)
        self.assertEqual(directory[0]["authorized_by"], "admin")
        self.assertEqual(directory[0]["role_version"], 1)
        events = [e for e in self.service.access_audit("admin") if e["event_type"] == "user.bootstrapped"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["payload"]["source"], "bootstrap")

    def test_repeated_bootstrap_never_overwrites_existing_users(self) -> None:
        self.service.create_user("admin", "approver-1", "审批人", "approver", USER_PASSWORD)
        with self.assertRaises(Conflict):
            self.service.bootstrap_admin("admin-2", "重复初始化", ADMIN_PASSWORD)
        with self.assertRaises(Conflict):
            self.service.bootstrap_admin("approver-1", "抢占已有账号", ADMIN_PASSWORD)
        row = self.connection.execute(
            "SELECT role,display_name FROM users WHERE user_id='approver-1'"
        ).fetchone()
        self.assertEqual((row["role"], row["display_name"]), ("approver", "审批人"))
        admins = self.connection.execute("SELECT count(*) FROM users WHERE role='admin'").fetchone()[0]
        self.assertEqual(admins, 1)

    def test_failed_bootstrap_leaves_no_fragments(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.bootstrap_admin("admin-2", "短口令", "short")
        with self.assertRaises(ValidationFailed):
            self.service.bootstrap_admin(" ", "空编号", ADMIN_PASSWORD)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM users").fetchone()[0], 1)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM user_credentials").fetchone()[0], 1)

    def test_daily_account_creation_requires_admin(self) -> None:
        self.service.create_user("admin", "operator-1", "操作员", "operator", USER_PASSWORD)
        with self.assertRaises(Forbidden):
            self.service.create_user("operator-1", "approver-1", "审批人", "approver", USER_PASSWORD)
        self.assertEqual(self._denials()[-1]["reason"], "permission_denied")
        # 失败不留账号、凭据或开户审计
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM users WHERE user_id='approver-1'").fetchone()[0], 0
        )
        self.assertEqual(self.connection.execute("SELECT count(*) FROM user_credentials").fetchone()[0], 2)
        created = self.connection.execute(
            "SELECT count(*) FROM audit_events WHERE event_type='user.created'"
        ).fetchone()[0]
        self.assertEqual(created, 1)

    def test_created_account_carries_authorizer_and_can_login(self) -> None:
        created = self.service.create_user("admin", "approver-1", "审批人", "approver", USER_PASSWORD)
        self.assertEqual(created["authorized_by"], "admin")
        self.assertEqual(created["role_version"], 1)
        session = self.service.login("approver-1", USER_PASSWORD)
        principal = self.service.authenticate(session["token"])
        self.assertEqual(principal["role"], "approver")

    def test_duplicate_account_creation_is_conflict_without_fragments(self) -> None:
        self.service.create_user("admin", "approver-1", "审批人", "approver", USER_PASSWORD)
        with self.assertRaises(Conflict):
            self.service.create_user("admin", "approver-1", "重复开户", "auditor", USER_PASSWORD)
        row = self.connection.execute(
            "SELECT display_name,role FROM users WHERE user_id='approver-1'"
        ).fetchone()
        self.assertEqual((row["display_name"], row["role"]), ("审批人", "approver"))
        self.assertEqual(self.connection.execute("SELECT count(*) FROM user_credentials").fetchone()[0], 2)

    def test_invalid_role_or_password_leaves_no_partial_account(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.create_user("admin", "u-bad", "非法角色", "superuser", USER_PASSWORD)
        with self.assertRaises(ValidationFailed):
            self.service.create_user("admin", "u-short", "短口令", "operator", "short")
        self.assertEqual(self.connection.execute("SELECT count(*) FROM users").fetchone()[0], 1)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM user_credentials").fetchone()[0], 1)

    def test_role_change_bumps_version_and_records_both_versions(self) -> None:
        self.service.create_user("admin", "stat-1", "统计员", "statistician", USER_PASSWORD)
        changed = self.service.change_role("admin", "stat-1", "approver", 1)
        self.assertEqual(changed["role_version"], 2)
        events = [e for e in self.service.access_audit("admin") if e["event_type"] == "user.role_changed"]
        self.assertEqual(events[0]["payload"]["from_role_version"], 1)
        self.assertEqual(events[0]["payload"]["to_role_version"], 2)
        # 旧角色立即失效，新角色立即生效
        with self.assertRaises(Forbidden):
            self.service._require("stat-1", "analysis.run")

    def test_stale_role_version_is_rejected(self) -> None:
        self.service.create_user("admin", "stat-1", "统计员", "statistician", USER_PASSWORD)
        self.service.change_role("admin", "stat-1", "approver", 1)
        with self.assertRaises(Conflict):
            self.service.change_role("admin", "stat-1", "auditor", 1)
        row = self.connection.execute("SELECT role,role_version FROM users WHERE user_id='stat-1'").fetchone()
        self.assertEqual((row["role"], row["role_version"]), ("approver", 2))

    def test_concurrent_role_changes_form_single_conclusion(self) -> None:
        self.service.create_user("admin", "stat-1", "统计员", "statistician", USER_PASSWORD)
        outcomes = []
        for role in ("approver", "auditor"):
            try:
                self.service.change_role("admin", "stat-1", role, 1)
                outcomes.append("ok")
            except Conflict:
                outcomes.append("conflict")
        self.assertEqual(outcomes.count("ok"), 1)
        self.assertEqual(outcomes.count("conflict"), 1)
        row = self.connection.execute("SELECT role_version FROM users WHERE user_id='stat-1'").fetchone()
        self.assertEqual(row["role_version"], 2)

    def test_last_active_admin_cannot_be_demoted_or_deactivated(self) -> None:
        with self.assertRaises(Conflict):
            self.service.change_role("admin", "admin", "auditor", 1)
        with self.assertRaises(ValidationFailed):
            self.service.deactivate_user("admin", "admin")
        self.service.create_user("admin", "admin-2", "第二管理员", "admin", USER_PASSWORD)
        self.service.deactivate_user("admin", "admin-2")
        with self.assertRaises(Conflict):
            self.service.change_role("admin", "admin", "auditor", 1)

    def test_deactivate_revokes_sessions_and_blocks_login(self) -> None:
        self.service.create_user("admin", "approver-1", "审批人", "approver", USER_PASSWORD)
        session = self.service.login("approver-1", USER_PASSWORD)
        result = self.service.deactivate_user("admin", "approver-1")
        self.assertFalse(result["active"])
        with self.assertRaises(Unauthorized):
            self.service.authenticate(session["token"])
        with self.assertRaises(Unauthorized):
            self.service.login("approver-1", USER_PASSWORD)
        reasons = [d["reason"] for d in self._denials()]
        self.assertIn("session_revoked", reasons)
        self.assertIn("user_deactivated", reasons)

    def test_concurrent_deactivation_forms_single_conclusion(self) -> None:
        self.service.create_user("admin", "approver-1", "审批人", "approver", USER_PASSWORD)
        self.service.deactivate_user("admin", "approver-1")
        with self.assertRaises(Conflict):
            self.service.deactivate_user("admin", "approver-1")

    def test_deactivated_user_keeps_history_and_cannot_change_role(self) -> None:
        self.service.create_user("admin", "approver-1", "审批人", "approver", USER_PASSWORD)
        self.service.deactivate_user("admin", "approver-1")
        with self.assertRaises(InvalidState):
            self.service.change_role("admin", "approver-1", "auditor", 1)
        detail = self.service.user_detail("admin", "approver-1")
        self.assertEqual(detail["authorized_by"], "admin")
        self.assertEqual(detail["active"], 0)

    def test_login_failures_leave_no_session(self) -> None:
        self.service.create_user("admin", "approver-1", "审批人", "approver", USER_PASSWORD)
        with self.assertRaises(Unauthorized):
            self.service.login("approver-1", "wrong-password")
        with self.assertRaises(Unauthorized):
            self.service.login("ghost", USER_PASSWORD)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM auth_sessions").fetchone()[0], 0)
        reasons = [d["reason"] for d in self._denials()]
        self.assertEqual(reasons, ["bad_password", "unknown_user"])

    def test_missing_forged_and_expired_credentials_are_rejected(self) -> None:
        self.service.create_user("admin", "approver-1", "审批人", "approver", USER_PASSWORD)
        session = self.service.login("approver-1", USER_PASSWORD)
        with self.assertRaises(Unauthorized):
            self.service.authenticate("")
        with self.assertRaises(Unauthorized):
            self.service.authenticate("forged-token")
        self.clock.advance(hours=9)
        with self.assertRaises(Unauthorized):
            self.service.authenticate(session["token"])
        reasons = [d["reason"] for d in self._denials()]
        self.assertEqual(reasons, ["missing_credentials", "unknown_token", "session_expired"])

    def test_password_reset_revokes_existing_sessions(self) -> None:
        self.service.create_user("admin", "approver-1", "审批人", "approver", USER_PASSWORD)
        session = self.service.login("approver-1", USER_PASSWORD)
        self.service.reset_password("admin", "approver-1", "new-password-1")
        with self.assertRaises(Unauthorized):
            self.service.authenticate(session["token"])
        with self.assertRaises(Unauthorized):
            self.service.login("approver-1", USER_PASSWORD)
        self.assertEqual(self.service.login("approver-1", "new-password-1")["user_id"], "approver-1")

    def test_security_views_expose_authorizer_version_and_denial_reasons(self) -> None:
        self.service.create_user("admin", "approver-1", "审批人", "approver", USER_PASSWORD)
        self.service.create_user("admin", "auditor-1", "审计员", "auditor", USER_PASSWORD)
        with self.assertRaises(Unauthorized):
            self.service.authenticate("forged-token")
        directory = self.service.user_directory("auditor-1")
        by_id = {row["user_id"]: row for row in directory}
        self.assertEqual(by_id["approver-1"]["authorized_by"], "admin")
        self.assertEqual(by_id["approver-1"]["role_version"], 1)
        events = self.service.access_audit("auditor-1")
        denial_reasons = [e["payload"]["reason"] for e in events if e["event_type"] == "auth.denied"]
        self.assertIn("unknown_token", denial_reasons)
        with self.assertRaises(Forbidden):
            self.service.user_directory("approver-1")
        with self.assertRaises(Forbidden):
            self.service.access_audit("approver-1")


class IdentityPersistenceTests(unittest.TestCase):
    """服务重启后权限状态与身份链历史保持一致。"""

    def test_restart_preserves_roles_sessions_and_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "identity.sqlite3"
            connection = connect(database)
            service = AssuranceService(connection)
            service.bootstrap_admin("admin", "初始化管理员", ADMIN_PASSWORD)
            service.create_user("admin", "approver-1", "审批人", "approver", USER_PASSWORD)
            service.change_role("admin", "approver-1", "auditor", 1)
            session = service.login("approver-1", USER_PASSWORD)
            connection.close()

            reopened = connect(database)
            try:
                restored = AssuranceService(reopened)
                principal = restored.authenticate(session["token"])
                self.assertEqual(principal["role"], "auditor")
                detail = restored.user_detail("admin", "approver-1")
                self.assertEqual(detail["role_version"], 2)
                self.assertEqual(detail["authorized_by"], "admin")
                events = restored.access_audit("admin")
                self.assertTrue(any(e["event_type"] == "user.role_changed" for e in events))
                with self.assertRaises(Unauthorized):
                    restored.login("approver-1", "wrong-password")
            finally:
                reopened.close()

    def test_legacy_v2_database_is_migrated_without_losing_users(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "legacy.sqlite3"
            connection = connect(database)
            connection.executescript(
                """CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO schema_meta VALUES('schema_version','2');
                CREATE TABLE users (
                    user_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('operator','statistician','approver','auditor')),
                    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1))
                );
                INSERT INTO users(user_id,display_name,role) VALUES('legacy-op','历史操作员','operator');"""
            )
            connection.close()

            migrated = connect(database)
            try:
                service = AssuranceService(migrated)
                service.bootstrap_admin("admin", "初始化管理员", ADMIN_PASSWORD)
                detail = service.user_detail("admin", "legacy-op")
                self.assertEqual(detail["role_version"], 1)
                self.assertIsNone(detail["authorized_by"])
                # 历史账号没有凭据，重置口令后可以登录
                with self.assertRaises(Unauthorized):
                    service.login("legacy-op", USER_PASSWORD)
                service.reset_password("admin", "legacy-op", USER_PASSWORD)
                self.assertEqual(service.login("legacy-op", USER_PASSWORD)["role"], "operator")
                version = migrated.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()[0]
                self.assertEqual(version, "3")
            finally:
                migrated.close()


class IdentityApiTests(unittest.TestCase):
    """通过 HTTP 边界验证：无凭据拿不到业务角色，并发开户只有唯一结论。"""

    def setUp(self) -> None:
        self.connection = connect(":memory:")
        self.app = JsonApplication(AssuranceService(self.connection))
        self.app.handle(
            "POST",
            "/users/bootstrap",
            body=json.dumps(
                {"user_id": "admin", "display_name": "初始化管理员", "password": ADMIN_PASSWORD}
            ).encode(),
        )
        token = self.app.handle(
            "POST", "/session", body=json.dumps({"user_id": "admin", "password": ADMIN_PASSWORD}).encode()
        ).body["token"]
        self.admin_headers = {"Authorization": f"Bearer {token}"}

    def tearDown(self) -> None:
        self.connection.close()

    def test_business_routes_reject_missing_and_forged_credentials(self) -> None:
        payload = json.dumps(
            {"program_id": "p1", "program_name": "项目", "lead_organization": "机构"}
        ).encode()
        missing = self.app.handle("POST", "/cooperation_programs", body=payload)
        self.assertEqual(missing.status, 401)
        forged = self.app.handle(
            "POST", "/cooperation_programs", headers={"Authorization": "Bearer forged"}, body=payload
        )
        self.assertEqual(forged.status, 401)
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM cooperation_programs").fetchone()[0], 0
        )
        audit = self.app.handle("GET", "/audit/access", headers=self.admin_headers)
        reasons = [e["payload"]["reason"] for e in audit.body["events"] if e["event_type"] == "auth.denied"]
        self.assertEqual(reasons, ["missing_credentials", "unknown_token"])

    def test_non_admin_token_cannot_open_accounts(self) -> None:
        self.app.handle(
            "POST",
            "/users",
            headers=self.admin_headers,
            body=json.dumps(
                {"user_id": "op-1", "display_name": "操作员", "role": "operator", "password": USER_PASSWORD}
            ).encode(),
        )
        token = self.app.handle(
            "POST", "/session", body=json.dumps({"user_id": "op-1", "password": USER_PASSWORD}).encode()
        ).body["token"]
        response = self.app.handle(
            "POST",
            "/users",
            headers={"Authorization": f"Bearer {token}"},
            body=json.dumps(
                {"user_id": "ap-1", "display_name": "审批人", "role": "approver", "password": USER_PASSWORD}
            ).encode(),
        )
        self.assertEqual(response.status, 403)
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM users WHERE user_id='ap-1'").fetchone()[0], 0
        )

    def test_concurrent_account_creation_forms_single_conclusion(self) -> None:
        payload = json.dumps(
            {"user_id": "ap-1", "display_name": "审批人", "role": "approver", "password": USER_PASSWORD}
        ).encode()
        statuses: list[int] = []

        def worker() -> None:
            response = self.app.handle("POST", "/users", headers=self.admin_headers, body=payload)
            statuses.append(response.status)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(409), 7)
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM users WHERE user_id='ap-1'").fetchone()[0], 1
        )
        self.assertEqual(self.connection.execute("SELECT count(*) FROM user_credentials").fetchone()[0], 2)

    def test_role_change_and_deactivate_via_api(self) -> None:
        created = self.app.handle(
            "POST",
            "/users",
            headers=self.admin_headers,
            body=json.dumps(
                {"user_id": "stat-1", "display_name": "统计员", "role": "statistician", "password": USER_PASSWORD}
            ).encode(),
        )
        self.assertEqual(created.status, 201)
        changed = self.app.handle(
            "POST",
            "/users/stat-1/role",
            headers=self.admin_headers,
            body=json.dumps({"role": "approver", "expected_role_version": 1}).encode(),
        )
        self.assertEqual(changed.status, 200)
        self.assertEqual(changed.body["role_version"], 2)
        stale = self.app.handle(
            "POST",
            "/users/stat-1/role",
            headers=self.admin_headers,
            body=json.dumps({"role": "auditor", "expected_role_version": 1}).encode(),
        )
        self.assertEqual(stale.status, 409)
        token = self.app.handle(
            "POST", "/session", body=json.dumps({"user_id": "stat-1", "password": USER_PASSWORD}).encode()
        ).body["token"]
        deactivated = self.app.handle("POST", "/users/stat-1/deactivate", headers=self.admin_headers)
        self.assertEqual(deactivated.status, 200)
        reused = self.app.handle("GET", "/users", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(reused.status, 401)
        detail = self.app.handle("GET", "/users/stat-1", headers=self.admin_headers)
        self.assertEqual(detail.body["authorized_by"], "admin")
        self.assertEqual(detail.body["active"], 0)


if __name__ == "__main__":
    unittest.main()
