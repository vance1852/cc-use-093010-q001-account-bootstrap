"""身份建立链路的安全回归测试。

覆盖：未登录/伪造/过期/停用凭据、首次引导唯一性、开户与角色调整边界、
并发唯一结论、失败原子性、授权审计可见性、重启一致性与 v2 迁移。
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cooperation_assurance.api import JsonApplication
from cooperation_assurance.errors import (
    Conflict,
    Forbidden,
    InvalidState,
    MissingCredentials,
    TokenExpired,
    Unauthorized,
)
from cooperation_assurance.service import AssuranceService
from cooperation_assurance.storage import connect
from cooperation_assurance.clock import FrozenClock


ADMIN_PW = "bootstrap-pass-1"
USER_PW = "onboarding-pass-1"


class IdentityTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 10, 4, 8, 0, tzinfo=timezone.utc))
        self.service = AssuranceService(self.connection, self.clock)
        self.service.bootstrap_administrator("admin", ADMIN_PW, "管理员")
        self.admin = self.service.login("admin", ADMIN_PW)["token"]
        self.app = JsonApplication(self.service)

    def tearDown(self) -> None:
        self.connection.close()

    def create(self, user_id: str, role: str, password: str = USER_PW, token=None) -> dict:
        return self.service.create_account(
            token or self.admin, user_id, f"{user_id}-名称", role, password, f"开户 {role}"
        )

    def login(self, user_id: str, password: str = USER_PW) -> str:
        return self.service.login(user_id, password)["token"]


class UnauthenticatedTests(IdentityTestBase):
    def test_account_creation_without_token_is_rejected_and_leaves_nothing(self) -> None:
        response = self.app.handle(
            "POST", "/accounts",
            body=json.dumps({"user_id": "x", "display_name": "审批人", "role": "approver",
                             "password": USER_PW, "reason": "无凭据开户"}).encode(),
        )
        self.assertEqual(response.status, 401)
        self.assertEqual(self.connection.execute(
            "SELECT count(*) FROM users WHERE user_id='x'").fetchone()[0], 0)
        self.assertEqual(self.connection.execute(
            "SELECT count(*) FROM user_role_history WHERE user_id='x'").fetchone()[0], 0)
        # 拒绝原因必须可审计。
        event = self.connection.execute(
            "SELECT reason_code,result FROM auth_events WHERE event_type='request.denied' "
            "ORDER BY event_id DESC LIMIT 1").fetchone()
        self.assertEqual(event["reason_code"], "missing_token")
        self.assertEqual(event["result"], "denied")

    def test_forged_and_garbage_tokens_are_rejected(self) -> None:
        for token in ("forged-token", "", "Bearer abc", "a" * 40):
            with self.assertRaises(MissingCredentials):
                self.service.list_accounts(token)
        # 错误的 scheme 不被承认。
        response = self.app.handle(
            "POST", "/accounts", headers={"Authorization": "Basic YWRtaW46"},
            body=json.dumps({"user_id": "y", "display_name": "n", "role": "auditor",
                             "password": USER_PW, "reason": "r"}).encode(),
        )
        self.assertEqual(response.status, 401)

    def test_legacy_actor_header_grants_nothing(self) -> None:
        response = self.app.handle(
            "POST", "/decisions", headers={"X-Actor-Id": "admin"},
            body=json.dumps({"batch_id": "b", "analysis_id": 1,
                             "decision": "approved", "reason": "x"}).encode(),
        )
        self.assertEqual(response.status, 401)

    def test_business_endpoints_require_real_session(self) -> None:
        with self.assertRaises(MissingCredentials):
            self.service.register_program(None, "p1", "项目", "机构")


class LoginBoundaryTests(IdentityTestBase):
    def test_wrong_password_creates_no_session_and_is_audited(self) -> None:
        self.create("op", "operator")
        with self.assertRaises(MissingCredentials):
            self.service.login("op", "wrong-password-x")
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM sessions s JOIN users u ON u.user_id=s.user_id "
                                    "WHERE u.user_id='op'").fetchone()[0], 0)
        event = self.connection.execute(
            "SELECT reason_code FROM auth_events WHERE event_type='login.denied'").fetchone()
        self.assertEqual(event["reason_code"], "invalid_credentials")

    def test_unknown_account_login_is_denied(self) -> None:
        with self.assertRaises(MissingCredentials):
            self.service.login("nobody", USER_PW)

    def test_short_password_rejected_at_creation(self) -> None:
        from cooperation_assurance.errors import ValidationFailed
        with self.assertRaises(ValidationFailed):
            self.create("weak", "operator", password="short")


class BootstrapTests(IdentityTestBase):
    def test_repeated_bootstrap_never_overwrites(self) -> None:
        with self.assertRaises(Conflict):
            self.service.bootstrap_administrator("admin2", ADMIN_PW, "第二管理员")
        # 原管理员口令仍可用，人员未被覆盖。
        token = self.service.login("admin", ADMIN_PW)["token"]
        accounts = self.service.list_accounts(token)
        self.assertEqual([a["user_id"] for a in accounts], ["admin"])
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM users WHERE role='administrator'").fetchone()[0], 1)

    def test_no_network_route_can_bootstrap(self) -> None:
        for path in ("/bootstrap", "/bootstrap-admin", "/init", "/users"):
            response = self.app.handle(
                "POST", path,
                body=json.dumps({"user_id": "z", "password": ADMIN_PW}).encode(),
            )
            self.assertEqual(response.status, 404, path)


class AccountManagementBoundaryTests(IdentityTestBase):
    def test_only_administrator_opens_accounts(self) -> None:
        self.create("op", "operator")
        op_token = self.login("op")
        with self.assertRaises(Forbidden):
            self.service.create_account(op_token, "evil", "伪造审批人", "approver", USER_PW, "越权")
        self.assertIsNone(self.connection.execute(
            "SELECT 1 FROM users WHERE user_id='evil'").fetchone())

    def test_administrator_cannot_participate_in_decisions(self) -> None:
        # 管理员角色不包含 decision.write，开户者不能自己当审批人。
        with self.assertRaises(Forbidden):
            self.service._require(self.admin, "decision.write")

    def test_create_duplicate_account_is_atomic_conflict(self) -> None:
        self.create("op", "operator")
        with self.assertRaises(Conflict):
            self.create("op", "operator")
        # 冲突不能产生重复历史或授权碎片。
        self.assertEqual(self.connection.execute(
            "SELECT count(*) FROM user_role_history WHERE user_id='op'").fetchone()[0], 1)
        self.assertEqual(self.connection.execute(
            "SELECT count(*) FROM auth_events WHERE event_type='user.created' AND user_id='op'"
        ).fetchone()[0], 1)

    def test_created_account_records_authorizer_and_version(self) -> None:
        view = self.create("ap", "approver")
        self.assertEqual(view["role"], "approver")
        self.assertEqual(view["role_version"], 1)
        self.assertEqual(view["created_by"], "admin")
        detail = self.service.account_detail(self.admin, "ap")
        self.assertEqual(detail["role_history"][0]["granted_by"], "admin")
        self.assertEqual(detail["role_history"][0]["change_type"], "created")


class RoleChangeTests(IdentityTestBase):
    def test_role_change_increments_version_and_preserves_history(self) -> None:
        self.create("u", "operator")
        changed = self.service.change_role(self.admin, "u", "approver", "转岗审批")
        self.assertEqual(changed["role"], "approver")
        self.assertEqual(changed["role_version"], 2)
        history = self.service.account_detail(self.admin, "u")["role_history"]
        self.assertEqual([(h["role_version"], h["role"], h["change_type"], h["granted_by"]) for h in history],
                         [(1, "operator", "created", "admin"), (2, "approver", "role_changed", "admin")])

    def test_existing_session_immediately_assumes_new_role(self) -> None:
        self.create("u", "statistician")
        token = self.login("u")
        # 原本可以封存（由服务层权限映射判定），降级为操作员后立即失效。
        self.service.change_role(self.admin, "u", "operator", "降级")
        with self.assertRaises(Forbidden):
            self.service._require(token, "batch.seal")
        # 令牌仍然可登录为新角色，角色版本随会话实时读取。
        principal = self.service.identity.authenticate(token)
        self.assertEqual((principal.role, principal.role_version), ("operator", 2))

    def test_role_change_requires_reason_and_rejects_self_change(self) -> None:
        from cooperation_assurance.errors import ValidationFailed
        self.create("admin2", "administrator")
        admin2 = self.login("admin2")
        with self.assertRaises(ValidationFailed):
            self.service.change_role(self.admin, "admin2", "auditor", "  ")
        with self.assertRaises(Forbidden):
            self.service.change_role(admin2, "admin2", "auditor", "自我提权")

    def test_optimistic_version_guard_rejects_stale_concurrent_write(self) -> None:
        self.create("u", "operator")
        self.service.change_role(self.admin, "u", "approver", "第一次调整")
        with self.assertRaises(Conflict):
            self.service.change_role(self.admin, "u", "auditor", "过期版本", expected_role_version=1)
        # 基于最新版本可以成功。
        view = self.service.change_role(self.admin, "u", "auditor", "最新版本", expected_role_version=2)
        self.assertEqual(view["role_version"], 3)

    def test_last_active_administrator_cannot_be_demoted(self) -> None:
        # 唯一管理员试图降级自己：自我变更保护先拦截；无论哪条守卫，
        # 系统都必须仍保留一位可登录的在用管理员。
        with self.assertRaises((Forbidden, InvalidState)):
            self.service.change_role(self.admin, "admin", "auditor", "降级唯一管理员")
        self.assertTrue(self.service.has_administrator())
        # 原管理员会话仍可执行管理操作。
        self.assertTrue(self.service.list_accounts(self.admin))


class DeactivationTests(IdentityTestBase):
    def test_deactivation_revokes_sessions_and_blocks_decisions(self) -> None:
        self.create("ap", "approver")
        token = self.login("ap")
        self.service.deactivate_account(self.admin, "ap", "离职停用")
        with self.assertRaises(Unauthorized):
            self.service.identity.authenticate(token)
        # 旧令牌参与评估决定必须失败。
        with self.assertRaises(Unauthorized):
            self.service.decide(token, "b", 1, "approved", "x")
        # 会话被标记撤销。
        self.assertIsNotNone(self.connection.execute(
            "SELECT revoked_at FROM sessions s JOIN users u ON u.user_id=s.user_id WHERE u.user_id='ap'"
        ).fetchone()["revoked_at"])
        # 停用后口令登录也被拒绝。
        with self.assertRaises(MissingCredentials):
            self.login("ap")

    def test_deactivation_is_versioned_and_cannot_target_self(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.deactivate_account(self.admin, "admin", "自停用")
        self.create("u", "operator")
        view = self.service.deactivate_account(self.admin, "u", "违规停用")
        self.assertEqual(view["active"], False)
        self.assertEqual(view["role_version"], 2)
        history = self.service.account_detail(self.admin, "u")["role_history"]
        self.assertEqual(history[-1]["change_type"], "deactivated")
        # 重复停用是明确失败，不制造新版本或碎片。
        with self.assertRaises(InvalidState):
            self.service.deactivate_account(self.admin, "u", "再次停用")
        self.assertEqual(self.connection.execute(
            "SELECT max(role_version) FROM user_role_history WHERE user_id='u'").fetchone()[0], 2)

    def test_last_administrator_cannot_be_deactivated(self) -> None:
        with self.assertRaises((Forbidden, InvalidState)):
            self.service.deactivate_account(self.admin, "admin", "停用唯一管理员")
        self.assertTrue(self.service.has_administrator())


class ExpiryTests(IdentityTestBase):
    def test_expired_token_is_rejected_and_audited(self) -> None:
        self.create("u", "operator")
        token = self.login("u")
        self.clock.advance(hours=8, seconds=1)
        with self.assertRaises(TokenExpired):
            self.service.identity.authenticate(token)
        event = self.connection.execute(
            "SELECT reason_code FROM auth_events WHERE event_type='request.denied' "
            "ORDER BY event_id DESC LIMIT 1").fetchone()
        self.assertEqual(event["reason_code"], "token_expired")

    def test_logout_revokes_token(self) -> None:
        self.create("u", "operator")
        token = self.login("u")
        self.service.logout(token)
        with self.assertRaises(Unauthorized):
            self.service.identity.authenticate(token)


class AuthorizationVisibilityTests(IdentityTestBase):
    def test_auditor_sees_authorizer_version_and_reasons(self) -> None:
        self.create("u", "approver")
        self.service.change_role(self.admin, "u", "auditor", "岗位轮换")
        token = self.login("u")
        events = self.service.authorization_events(token)
        codes = {e["reason_code"] for e in events}
        # 授权来源（granted_by 通过账户历史）、角色版本、拒绝原因三类都可取。
        self.assertIn("account_created", codes)
        self.assertIn("role_changed", codes)
        self.assertTrue(all(e["role_version"] is not None for e in events if "login" not in e["event_type"]))

    def test_auditor_cannot_manage_accounts(self) -> None:
        self.create("au", "auditor")
        token = self.login("au")
        with self.assertRaises(Forbidden):
            self.service.create_account(token, "x", "x", "operator", USER_PW, "审计员开户")
        # 但审计员能看到账户清单。
        self.assertTrue(self.service.list_accounts(token))

    def test_operator_cannot_read_authorization_events(self) -> None:
        self.create("op", "operator")
        token = self.login("op")
        with self.assertRaises(Forbidden):
            self.service.authorization_events(token)


class ConcurrencyTests(unittest.TestCase):
    """文件库上的多连接并发：同一账号的竞争请求必须只形成一个结论。"""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "identity.sqlite3"
        first = AssuranceService(connect(self.path))
        first.bootstrap_administrator("admin", ADMIN_PW, "管理员")
        admin = first.login("admin", ADMIN_PW)["token"]
        first.create_account(admin, "victim", "目标账号", "operator", USER_PW, "并发测试开户")
        first.connection.close()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def _worker(self, action, errors, results, barrier) -> None:
        service = AssuranceService(connect(self.path))
        admin = service.login("admin", ADMIN_PW)["token"]
        barrier.wait()
        try:
            if action == "deactivate":
                results[action] = service.deactivate_account(admin, "victim", "并发停用")
            elif action == "promote":
                results[action] = service.change_role(admin, "victim", "approver", "并发转岗")
            elif action == "create":
                results[action] = service.create_account(
                    admin, "twin", "并发账号", "auditor", USER_PW, "并发开户")
        except Exception as exc:  # noqa: BLE001 - 并发下仅一方应成功
            errors[action] = type(exc).__name__
        finally:
            service.connection.close()

    def _run_pair(self, action_a: str, action_b: str) -> tuple[dict, dict]:
        errors: dict[str, str] = {}
        results: dict[str, dict] = {}
        barrier = threading.Barrier(2)
        threads = [
            threading.Thread(target=self._worker, args=(action_a, errors, results, barrier)),
            threading.Thread(target=self._worker, args=(action_b, errors, results, barrier)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return results, errors

    def test_role_change_and_deactivation_on_same_account_have_single_outcome(self) -> None:
        results, errors = self._run_pair("deactivate", "promote")
        self.assertEqual(len(results) + len(errors), 2)
        connection = connect(self.path)
        try:
            row = connection.execute(
                "SELECT role,role_version,active FROM users WHERE user_id='victim'").fetchone()
            history = connection.execute(
                "SELECT role_version,change_type,role FROM user_role_history "
                "WHERE user_id='victim' ORDER BY role_version").fetchall()
        finally:
            connection.close()
        # 不变量：版本号严格连续、每个版本只有一条结论，没有分叉或碎片。
        versions = [h["role_version"] for h in history]
        self.assertEqual(versions, list(range(1, len(versions) + 1)))
        self.assertEqual(len(versions), len(set(versions)))
        self.assertEqual(row["role_version"], versions[-1])
        # 最终状态必须与最后一条历史自洽。
        last = history[-1]
        if last["change_type"] == "deactivated":
            self.assertEqual(row["active"], 0)
        else:
            self.assertEqual((row["active"], row["role"]), (1, "approver"))
        # 停用一旦先生效，随后的转岗必须被拒绝且不产生新版本。
        if "deactivate" in results and "promote" in errors:
            self.assertEqual(len(versions), 2)

    def test_concurrent_creation_of_same_user_single_winner(self) -> None:
        # 两个连接同时开同一个编号，只有一个能成功，库内只留一套记录。
        def create(error_box, barrier) -> None:
            service = AssuranceService(connect(self.path))
            admin = service.login("admin", ADMIN_PW)["token"]
            barrier.wait()
            try:
                service.create_account(admin, "dup", "重复账号", "auditor", USER_PW, "重复开户")
            except Conflict:
                error_box.append("conflict")
            finally:
                service.connection.close()

        errors: list[str] = []
        barrier = threading.Barrier(2)
        threads = [threading.Thread(target=create, args=(errors, barrier)) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(errors), ["conflict"])
        connection = connect(self.path)
        try:
            self.assertEqual(connection.execute(
                "SELECT count(*) FROM users WHERE user_id='dup'").fetchone()[0], 1)
            self.assertEqual(connection.execute(
                "SELECT count(*) FROM user_role_history WHERE user_id='dup'").fetchone()[0], 1)
        finally:
            connection.close()

    def test_same_identity_concurrent_requests_share_one_role_version(self) -> None:
        # 同一管理员的两个并发角色调整：恰好一个生效，另一个以版本冲突结束。
        results, errors = self._run_pair("promote", "promote")
        self.assertEqual(len(results), 1)
        self.assertEqual(errors.get("promote"), "Conflict")
        connection = connect(self.path)
        try:
            row = connection.execute("SELECT role_version FROM users WHERE user_id='victim'").fetchone()
            self.assertEqual(row["role_version"], 2)
        finally:
            connection.close()


class RestartPersistenceTests(unittest.TestCase):
    def test_permissions_and_history_survive_restart(self) -> None:
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "restart.sqlite3"
        service = AssuranceService(connect(path))
        service.bootstrap_administrator("admin", ADMIN_PW, "管理员")
        admin = service.login("admin", ADMIN_PW)["token"]
        service.create_account(admin, "ap", "审批人", "approver", USER_PW, "上线开户")
        token = service.login("ap", USER_PW)["token"]
        service.change_role(admin, "ap", "auditor", "轮岗")
        service.connection.close()

        restarted = AssuranceService(connect(path))
        # 角色版本/授权历史/会话仍在；旧会话按新版本（auditor）鉴权。
        principal = restarted.identity.authenticate(token)
        self.assertEqual((principal.role, principal.role_version), ("auditor", 2))
        detail = restarted.account_detail(
            restarted.login("admin", ADMIN_PW)["token"], "ap")
        self.assertEqual([h["granted_by"] for h in detail["role_history"]], ["admin", "admin"])
        events = restarted.authorization_events(
            restarted.login("admin", ADMIN_PW)["token"], "ap")
        self.assertIn("role_changed", {e["reason_code"] for e in events})
        # 伪造令牌在重启后依旧无效。
        with self.assertRaises(MissingCredentials):
            restarted.identity.authenticate("forged")
        restarted.connection.close()
        directory.cleanup()


class V2MigrationTests(unittest.TestCase):
    def test_legacy_uncredentialed_accounts_are_deactivated_with_history(self) -> None:
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "legacy.sqlite3"
        connection = connect(path)
        # 直接建一个 v2 形态的 users 表（无凭据、无版本列）。
        connection.execute(
            "CREATE TABLE users(user_id TEXT PRIMARY KEY,display_name TEXT NOT NULL,"
            "role TEXT NOT NULL CHECK (role IN ('operator','statistician','approver','auditor')),"
            "active INTEGER NOT NULL DEFAULT 1)")
        connection.execute("INSERT INTO users VALUES('old-ap','老审批人','approver',1)")
        connection.commit()
        connection.close()

        service = AssuranceService(connect(path))
        # 旧账号无法登录（无凭据且被停用），必须由新管理员重新开户。
        self.assertTrue(service.has_administrator() is False)
        row = service.connection.execute(
            "SELECT active,role_version FROM users WHERE user_id='old-ap'").fetchone()
        self.assertEqual(row["active"], 0)
        history = service.connection.execute(
            "SELECT change_type,granted_by FROM user_role_history WHERE user_id='old-ap'").fetchone()
        self.assertEqual(history["granted_by"], "system:migration")
        with self.assertRaises(MissingCredentials):
            service.login("old-ap", "anything-at-all-123")
        service.bootstrap_administrator("admin", ADMIN_PW, "管理员")
        service.connection.close()
        directory.cleanup()


if __name__ == "__main__":
    unittest.main()
