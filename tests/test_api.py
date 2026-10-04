from __future__ import annotations

import json
import sqlite3
import unittest

from cooperation_assurance.api import JsonApplication
from cooperation_assurance.service import AssuranceService


ADMIN_PASSWORD = "admin-pass-0001"
USER_PASSWORD = "user-pass-0001"


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(AssuranceService(self.connection))

    def tearDown(self) -> None:
        self.connection.close()

    def _bootstrap(self) -> None:
        response = self.app.handle(
            "POST",
            "/users/bootstrap",
            body=json.dumps(
                {"user_id": "admin", "display_name": "初始化管理员", "password": ADMIN_PASSWORD}
            ).encode(),
        )
        assert response.status == 201, response.body

    def _token(self, user_id: str = "admin", password: str = ADMIN_PASSWORD) -> str:
        response = self.app.handle(
            "POST", "/session", body=json.dumps({"user_id": user_id, "password": password}).encode()
        )
        assert response.status == 200, response.body
        return response.body["token"]

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_json_error_shape(self) -> None:
        response = self.app.handle("POST", "/users", body=b"not-json")
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_user_route_rejects_anonymous_account_creation(self) -> None:
        payload = json.dumps(
            {"user_id": "u1", "display_name": "审批人", "role": "approver", "password": USER_PASSWORD}
        ).encode()
        response = self.app.handle("POST", "/users", body=payload)
        self.assertEqual(response.status, 401)
        self.assertEqual(response.body["error"]["code"], "unauthorized")
        count = self.connection.execute("SELECT count(*) FROM users").fetchone()[0]
        self.assertEqual(count, 0)

    def test_user_route_rejects_forged_token(self) -> None:
        self._bootstrap()
        payload = json.dumps(
            {"user_id": "u1", "display_name": "审批人", "role": "approver", "password": USER_PASSWORD}
        ).encode()
        response = self.app.handle(
            "POST", "/users", headers={"Authorization": "Bearer forged-token"}, body=payload
        )
        self.assertEqual(response.status, 401)
        count = self.connection.execute("SELECT count(*) FROM users WHERE user_id='u1'").fetchone()[0]
        self.assertEqual(count, 0)

    def test_user_route(self) -> None:
        self._bootstrap()
        token = self._token()
        payload = json.dumps(
            {"user_id": "u1", "display_name": "操作员", "role": "operator", "password": USER_PASSWORD}
        ).encode()
        response = self.app.handle(
            "POST", "/users", headers={"Authorization": f"Bearer {token}"}, body=payload
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(response.body["role"], "operator")
        self.assertEqual(response.body["authorized_by"], "admin")
        self.assertEqual(response.body["role_version"], 1)

    def test_bootstrap_is_one_shot(self) -> None:
        self._bootstrap()
        response = self.app.handle(
            "POST",
            "/users/bootstrap",
            body=json.dumps(
                {"user_id": "admin-2", "display_name": "重复初始化", "password": ADMIN_PASSWORD}
            ).encode(),
        )
        self.assertEqual(response.status, 409)
        row = self.connection.execute("SELECT count(*) FROM users WHERE role='admin'").fetchone()[0]
        self.assertEqual(row, 1)


if __name__ == "__main__":
    unittest.main()
