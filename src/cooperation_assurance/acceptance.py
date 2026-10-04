"""完整产品流程的离线验收入口。"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .jsonio import load_json
from .service import AssuranceService
from .storage import connect, inspect_schema


BOOTSTRAP_PASSWORD = "bootstrap-pass-2026"
ACCOUNT_PASSWORD = "onboarding-pass-2026"


def run(workspace: Path) -> dict[str, object]:
    fixtures = workspace / "fixtures"
    protocol = load_json(fixtures / "demo_protocol.json")
    observation_rows = [
        json.loads(line)
        for line in (fixtures / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    with tempfile.TemporaryDirectory(prefix="cooperation-assurance-") as temporary:
        database = Path(temporary) / "foundation.sqlite3"
        connection = connect(database)
        try:
            service = AssuranceService(connection)
            # 首次管理员只能由本地引导建立，且只能成功一次。
            service.bootstrap_administrator("admin-1", BOOTSTRAP_PASSWORD, "平台管理员")
            admin = service.login("admin-1", BOOTSTRAP_PASSWORD)["token"]
            accounts = (
                ("operator-1", "测试操作员", "operator"),
                ("stat-1", "统计负责人", "statistician"),
                ("approver-1", "分析准入审批人", "approver"),
                ("auditor-1", "审计人员", "auditor"),
            )
            for user_id, display_name, role in accounts:
                service.create_account(
                    admin, user_id, display_name, role, ACCOUNT_PASSWORD, "离线验收开户"
                )
            tokens = {
                user_id: service.login(user_id, ACCOUNT_PASSWORD)["token"]
                for user_id, _, _ in accounts
            }
            service.register_program(tokens["operator-1"], "program-a", "跨境数据服务合作项目", "示例牵头机构")
            service.register_evidence_revision(tokens["operator-1"], "evidence_revision-a1", "program-a", "1.0.0", "a" * 64)
            service.publish_protocol(tokens["stat-1"], protocol)
            service.create_batch(tokens["operator-1"], "batch-demo", protocol["protocol_id"], protocol["version"], "evidence_revision-a1")
            service.start_batch(tokens["operator-1"], "batch-demo", 1)
            imported = service.import_observations(
                tokens["operator-1"], "batch-demo", "demo-import-1", observation_rows
            )
            service.seal_batch(tokens["stat-1"], "batch-demo", 2)
            job = service.claim_job("worker-1", lease_seconds=60)
            if job is None:
                raise RuntimeError("未能领取分析任务")
            analysis = service.complete_job("worker-1", job["job_id"], tokens["stat-1"])
            decision_value = "approved" if analysis["result"]["conclusion"] == "pass" else "rejected"
            service.decide(
                tokens["approver-1"], "batch-demo", analysis["analysis_id"], decision_value, "离线验收决定"
            )
            report = service.report(tokens["auditor-1"], "batch-demo")
            auth_events = service.authorization_events(tokens["auditor-1"])
            schema = inspect_schema(connection)
        finally:
            connection.close()
    if schema["missing_tables"] or schema["schema_version"] != "3":
        raise RuntimeError("SQLite 基础结构检查失败")
    return {
        "status": "ok",
        "protocol": f"{protocol['protocol_id']}@{protocol['version']}",
        "observation_count": imported["inserted"],
        "analysis_id": analysis["analysis_id"],
        "input_sha256": analysis["input_sha256"],
        "conclusion": analysis["result"]["conclusion"],
        "decision": report["decision"]["decision"],
        "event_count": len(report["events"]),
        "auth_event_count": len(auth_events),
        "schema": schema,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="执行校准数据基础工具的离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = run(args.workspace.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
