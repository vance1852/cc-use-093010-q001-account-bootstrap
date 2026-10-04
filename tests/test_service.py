from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cooperation_assurance.clock import FrozenClock
from cooperation_assurance.errors import Conflict, Forbidden
from cooperation_assurance.jsonio import load_json
from cooperation_assurance.service import AssuranceService


ROOT = Path(__file__).resolve().parents[1]

ADMIN_PASSWORD = "admin-pass-0000"
USER_PASSWORD = "user-pass-00000"


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = AssuranceService(self.connection, self.clock)
        self.service.bootstrap_administrator("admin", ADMIN_PASSWORD, "管理员")
        self.admin = self.service.login("admin", ADMIN_PASSWORD)["token"]
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("auditor", "auditor"),
        ):
            self.service.create_account(
                self.admin, user_id, user_id, role, USER_PASSWORD, f"测试开户 {role}"
            )
        self.tokens = {
            user_id: self.service.login(user_id, USER_PASSWORD)["token"]
            for user_id in ("operator", "stat", "approver", "auditor")
        }
        self.protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.service.register_program(self.tokens["operator"], "program-a", "跨境数据服务项目", "牵头机构")
        self.service.register_evidence_revision(self.tokens["operator"], "evidence_revision-a", "program-a", "1.0", "b" * 64)
        self.service.publish_protocol(self.tokens["stat"], self.protocol)
        self.service.create_batch(self.tokens["operator"], "batch-a", "demo-cooperation-v1", 1, "evidence_revision-a")
        self.service.start_batch(self.tokens["operator"], "batch-a", 1)

    def tearDown(self) -> None:
        self.connection.close()

    def test_complete_workflow(self) -> None:
        imported = self.service.import_observations(self.tokens["operator"], "batch-a", "key-1", self.rows)
        self.assertEqual(imported["inserted"], 6)
        self.service.seal_batch(self.tokens["stat"], "batch-a", 2)
        job = self.service.claim_job("worker", 30)
        analysis = self.service.complete_job("worker", job["job_id"], self.tokens["stat"])
        self.service.decide(self.tokens["approver"], "batch-a", analysis["analysis_id"], "approved", "满足规则")
        report = self.service.report(self.tokens["auditor"], "batch-a")
        self.assertEqual(report["batch"]["state"], "decided")
        self.assertEqual(report["analysis"]["result"]["conclusion"], "pass")

    def test_idempotent_replay_and_conflict(self) -> None:
        first = self.service.import_observations(self.tokens["operator"], "batch-a", "key-1", self.rows)
        second = self.service.import_observations(self.tokens["operator"], "batch-a", "key-1", self.rows)
        self.assertEqual(first, second)
        changed = [dict(item) for item in self.rows]
        changed[0] = dict(changed[0])
        changed[0]["metrics"] = dict(changed[0]["metrics"])
        changed[0]["metrics"]["review_latency_hours"] = "99"
        with self.assertRaises(Conflict):
            self.service.import_observations(self.tokens["operator"], "batch-a", "key-1", changed)
        count = self.connection.execute("SELECT count(*) FROM observations").fetchone()[0]
        self.assertEqual(count, 6)

    def test_import_rolls_back_when_one_source_row_duplicates(self) -> None:
        self.service.import_observations(self.tokens["operator"], "batch-a", "key-1", self.rows[:1])
        with self.assertRaises(Conflict):
            self.service.import_observations(self.tokens["operator"], "batch-a", "key-2", self.rows[:2])
        count = self.connection.execute("SELECT count(*) FROM observations").fetchone()[0]
        self.assertEqual(count, 1)

    def test_role_separation(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.seal_batch(self.tokens["operator"], "batch-a", 2)
        with self.assertRaises(Forbidden):
            self.service.report(self.tokens["operator"], "batch-a")

    def test_exclusion_review_and_revoke_leave_history(self) -> None:
        self.service.import_observations(self.tokens["operator"], "batch-a", "key-1", self.rows)
        observation_id = self.connection.execute(
            "SELECT observation_id FROM observations ORDER BY observation_id LIMIT 1"
        ).fetchone()[0]
        requested = self.service.request_exclusion(self.tokens["operator"], observation_id, "现场记录失效")
        reviewed = self.service.review_exclusion(self.tokens["stat"], requested["exclusion_id"], True, "证据充分")
        self.assertEqual(reviewed["status"], "approved")
        revoked = self.service.revoke_exclusion(self.tokens["operator"], requested["exclusion_id"], "已找回原始记录")
        self.assertEqual(revoked["status"], "revoked")
        events = self.connection.execute(
            "SELECT event_type FROM audit_events WHERE entity_type='observation' AND entity_id=? ORDER BY event_id",
            (str(observation_id),),
        ).fetchall()
        self.assertEqual([row[0] for row in events], ["exclusion.requested", "exclusion.revoked"])

    def test_failed_job_returns_to_queue_after_delay(self) -> None:
        self.service.import_observations(self.tokens["operator"], "batch-a", "key-1", self.rows)
        self.service.seal_batch(self.tokens["stat"], "batch-a", 2)
        job = self.service.claim_job("worker-a", 10)
        failed = self.service.fail_job("worker-a", job["job_id"], "临时计算失败", retry_seconds=5)
        self.assertEqual(failed["state"], "queued")
        self.assertIsNone(self.service.claim_job("worker-b", 10))
        self.clock.advance(seconds=5)
        retried = self.service.claim_job("worker-b", 10)
        self.assertEqual(retried["job_id"], job["job_id"])
        self.assertEqual(retried["attempts"], 2)

    def test_lease_can_be_reclaimed_after_expiry(self) -> None:
        self.service.import_observations(self.tokens["operator"], "batch-a", "key-1", self.rows)
        self.service.seal_batch(self.tokens["stat"], "batch-a", 2)
        first = self.service.claim_job("worker-a", 10)
        self.clock.advance(seconds=11)
        second = self.service.claim_job("worker-b", 10)
        self.assertEqual(first["job_id"], second["job_id"])
        self.assertEqual(second["lease_owner"], "worker-b")
        with self.assertRaises(Exception):
            self.service.complete_job("worker-a", first["job_id"], self.tokens["stat"])


if __name__ == "__main__":
    unittest.main()
