from __future__ import annotations

import json
import sqlite3
import unittest

from cooperation_assurance.api import JsonApplication
from cooperation_assurance.errors import Conflict
from cooperation_assurance.service import AssuranceService


ADMIN_PASSWORD = "admin-pass-0000"
USER_PASSWORD = "auditor-pass-00"


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.service = AssuranceService(self.connection)
        self.app = JsonApplication(self.service)
        self.service.bootstrap_administrator("admin", ADMIN_PASSWORD, "管理员")
        login = self.app.handle(
            "POST", "/auth/login",
            body=json.dumps({"user_id": "admin", "password": ADMIN_PASSWORD}).encode(),
        )
        self.admin_token = login.body["token"]
        self.admin_headers = {"Authorization": f"Bearer {self.admin_token}"}

    def tearDown(self) -> None:
        self.connection.close()

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_json_error_shape(self) -> None:
        response = self.app.handle("POST", "/accounts", body=b"not-json")
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_unauthenticated_account_creation_is_rejected(self) -> None:
        payload = json.dumps(
            {"user_id": "u1", "display_name": "审计员", "role": "auditor",
             "password": USER_PASSWORD, "reason": "测试"}
        ).encode()
        response = self.app.handle("POST", "/accounts", body=payload)
        self.assertEqual(response.status, 401)
        self.assertEqual(response.body["error"]["code"], "unauthorized")
        # 拒绝不能留下账号或会话。
        self.assertEqual(self.connection.execute("SELECT count(*) FROM users WHERE user_id='u1'").fetchone()[0], 0)
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM sessions s JOIN users u ON u.user_id=s.user_id WHERE u.user_id='u1'"
            ).fetchone()[0],
            0,
        )

    def test_account_route_requires_administrator(self) -> None:
        # 管理员先开一个操作员账户。
        payload = json.dumps(
            {"user_id": "op1", "display_name": "操作员", "role": "operator",
             "password": USER_PASSWORD, "reason": "执行机构接入"}
        ).encode()
        created = self.app.handle("POST", "/accounts", headers=self.admin_headers, body=payload)
        self.assertEqual(created.status, 201)
        self.assertEqual(created.body["role"], "operator")
        self.assertEqual(created.body["role_version"], 1)
        self.assertEqual(created.body["created_by"], "admin")

        # 操作员登录后不能开户，即使他知道开户接口。
        login = self.app.handle(
            "POST", "/auth/login",
            body=json.dumps({"user_id": "op1", "password": USER_PASSWORD}).encode(),
        )
        op_headers = {"Authorization": f"Bearer {login.body['token']}"}
        forged = json.dumps(
            {"user_id": "evil", "display_name": "伪造审批人", "role": "approver",
             "password": USER_PASSWORD, "reason": "越权"}
        ).encode()
        denied = self.app.handle("POST", "/accounts", headers=op_headers, body=forged)
        self.assertEqual(denied.status, 403)
        self.assertEqual(denied.body["error"]["code"], "forbidden")
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM users WHERE user_id='evil'").fetchone()[0], 0
        )

    def test_forged_actor_header_is_not_identity(self) -> None:
        # 旧版本靠 X-Actor-Id 即可冒充任何人；现在该头不再被承认。
        response = self.app.handle(
            "POST", "/cooperation_programs",
            headers={"X-Actor-Id": "admin"},
            body=json.dumps({"program_id": "p", "program_name": "n", "lead_organization": "o"}).encode(),
        )
        self.assertEqual(response.status, 401)

    def test_repeated_bootstrap_does_not_overwrite(self) -> None:
        with self.assertRaises(Conflict):
            self.service.bootstrap_administrator("admin2", ADMIN_PASSWORD, "第二管理员")
        status = self.app.handle("GET", "/bootstrap-status")
        self.assertEqual(status.body["initialized"], True)


if __name__ == "__main__":
    unittest.main()
