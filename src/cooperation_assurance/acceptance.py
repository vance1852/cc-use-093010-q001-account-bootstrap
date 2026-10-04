"""完整产品流程的离线验收入口。"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .jsonio import load_json
from .service import AssuranceService
from .storage import connect, inspect_schema


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
            service.bootstrap_admin("admin-1", "初始化管理员", "admin-pass-0001")
            service.create_user("admin-1", "operator-1", "测试操作员", "operator", "operator-pass-1")
            service.create_user("admin-1", "stat-1", "统计负责人", "statistician", "stat-pass-0001")
            service.create_user("admin-1", "approver-1", "分析准入审批人", "approver", "approver-pass-1")
            service.create_user("admin-1", "auditor-1", "审计人员", "auditor", "auditor-pass-01")
            service.register_program("operator-1", "program-a", "跨境数据服务合作项目", "示例牵头机构")
            service.register_evidence_revision("operator-1", "evidence_revision-a1", "program-a", "1.0.0", "a" * 64)
            service.publish_protocol("stat-1", protocol)
            service.create_batch("operator-1", "batch-demo", protocol["protocol_id"], protocol["version"], "evidence_revision-a1")
            service.start_batch("operator-1", "batch-demo", 1)
            imported = service.import_observations(
                "operator-1", "batch-demo", "demo-import-1", observation_rows
            )
            service.seal_batch("stat-1", "batch-demo", 2)
            job = service.claim_job("worker-1", lease_seconds=60)
            if job is None:
                raise RuntimeError("未能领取分析任务")
            analysis = service.complete_job("worker-1", job["job_id"], "stat-1")
            decision_value = "approved" if analysis["result"]["conclusion"] == "pass" else "rejected"
            service.decide(
                "approver-1", "batch-demo", analysis["analysis_id"], decision_value, "离线验收决定"
            )
            report = service.report("auditor-1", "batch-demo")
            schema = inspect_schema(connection)
        finally:
            connection.close()
        # 模拟服务重启：重新打开同一数据库，权限状态与身份链历史必须保持一致。
        restarted = connect(database)
        try:
            restored = AssuranceService(restarted)
            session = restored.login("auditor-1", "auditor-pass-01")
            principal = restored.authenticate(session["token"])
            directory = restored.user_directory("admin-1")
            identity_events = restored.access_audit("auditor-1")
        finally:
            restarted.close()
    if schema["missing_tables"] or schema["schema_version"] != "3":
        raise RuntimeError("SQLite 基础结构检查失败")
    if principal["user_id"] != "auditor-1" or len(directory) != 5 or not identity_events:
        raise RuntimeError("重启后权限状态与身份链历史不一致")
    return {
        "status": "ok",
        "protocol": f"{protocol['protocol_id']}@{protocol['version']}",
        "observation_count": imported["inserted"],
        "analysis_id": analysis["analysis_id"],
        "input_sha256": analysis["input_sha256"],
        "conclusion": analysis["result"]["conclusion"],
        "decision": report["decision"]["decision"],
        "event_count": len(report["events"]),
        "user_count": len(directory),
        "identity_event_count": len(identity_events),
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
