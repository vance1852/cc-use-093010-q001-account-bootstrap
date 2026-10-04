"""无第三方依赖的 HTTP JSON 接口。

身份边界：
- 唯一不需要凭据的写接口是 POST /auth/login；账户引导只能在服务进程本地完成；
- 业务接口一律要求 Authorization: Bearer <登录令牌>；
- /accounts 的写操作要求 administrator；授权事件与账户视图要求审计权限。
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from .errors import ServiceError, Unauthorized, ValidationFailed
from .service import AssuranceService
from .storage import connect


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Mapping[str, Any]


class ThreadLocalService:
    """为每个 HTTP 工作线程提供独立连接与服务实例。

    SQLite 连接不能跨线程使用，而多线程服务器会并发处理请求；
    各线程打开自己的连接、共享同一个数据库文件，写入由
    BEGIN IMMEDIATE + busy_timeout 串行化，结论与内存/单线程模式一致。
    """

    def __init__(self, database: str | Path) -> None:
        self._database = str(database)
        self._local = threading.local()
        self._connections: list[sqlite3.Connection] = []
        self._lock = threading.Lock()

    def _service(self) -> AssuranceService:
        service = getattr(self._local, "service", None)
        if service is None:
            connection = connect(self._database)
            service = AssuranceService(connection)
            self._local.service = service
            with self._lock:
                self._connections.append(connection)
        return service

    def __getattr__(self, name: str) -> Any:
        return getattr(self._service(), name)

    def close(self) -> None:
        with self._lock:
            for connection in self._connections:
                connection.close()
            self._connections.clear()


class JsonApplication:
    """将 HTTP 路由映射到领域服务，便于无网络单元测试。"""

    def __init__(self, service: AssuranceService) -> None:
        self.service = service

    @staticmethod
    def _token(headers: Mapping[str, str]) -> str | None:
        """提取 Bearer 令牌；其他方案名或空值按缺失凭据处理。"""

        authorization = headers.get("authorization", "").strip()
        if not authorization:
            return None
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return None
        return token.strip()

    @staticmethod
    def _json(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationFailed("请求体必须是 UTF-8 JSON 对象") from exc
        if not isinstance(value, dict):
            raise ValidationFailed("请求体必须是 JSON 对象")
        return value

    @staticmethod
    def _route(method: str, path: str, parts: list[str]) -> tuple[str | None, str] | None:
        """把受保护路由映射为 (所需权限, 动作)；None 权限表示工作进程接口。

        路由识别不依赖请求体，因此可以在解析业务参数之前先完成鉴权，
        保证凭据缺失/伪造时一律先得到 401，而不会因缺字段提前 422。
        """

        table: dict[tuple[str, str], tuple[str | None, str]] = {
            ("POST", "/accounts"): ("account.manage", "account.create"),
            ("GET", "/accounts"): ("audit.read", "account.list"),
            ("POST", "/cooperation_programs"): ("catalog.write", "program.create"),
            ("POST", "/evidence_revisions"): ("catalog.write", "evidence.create"),
            ("POST", "/protocols"): ("protocol.publish", "protocol.publish"),
            ("POST", "/batches"): ("batch.create", "batch.create"),
            ("POST", "/exclusions"): ("exclusion.request", "exclusion.request"),
            ("POST", "/jobs/claim"): (None, "job.claim"),
            ("POST", "/jobs/fail"): (None, "job.fail"),
            ("POST", "/decisions"): ("decision.write", "decision.create"),
        }
        if (method, path) in table:
            return table[(method, path)]
        if method == "GET" and path == "/authorization-events":
            return ("audit.read", "auth.events")
        if len(parts) == 2 and parts[0] == "accounts":
            if method == "GET":
                return ("audit.read", "account.detail")
        if len(parts) == 3 and parts[0] == "accounts":
            if method == "POST" and parts[2] == "roles":
                return ("account.manage", "account.role")
            if method == "POST" and parts[2] == "deactivation":
                return ("account.manage", "account.deactivate")
        if len(parts) == 3 and parts[0] == "batches":
            permission = {
                "start": "batch.start",
                "observations": "observation.import",
                "seal": "batch.seal",
            }.get(parts[2])
            if method == "POST" and permission:
                return (permission, f"batch.{parts[2]}")
            if method == "GET" and parts[2] == "report":
                return ("report.read", "batch.report")
        if len(parts) == 3 and parts[0] == "exclusions":
            permission = {"review": "exclusion.review", "revoke": "exclusion.revoke"}.get(parts[2])
            if method == "POST" and permission:
                return (permission, f"exclusion.{parts[2]}")
        if len(parts) == 3 and parts[0] == "jobs" and method == "POST" and parts[2] == "complete":
            return ("analysis.run", "job.complete")
        return None

    def handle(
        self, method: str, target: str, headers: Mapping[str, str] | None = None, body: bytes = b""
    ) -> Response:
        normalized_headers = {key.lower(): value for key, value in (headers or {}).items()}
        parsed = urlparse(target)
        path = parsed.path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        query = parse_qs(parsed.query)
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}

            # -- 无需业务凭据的入口 --
            if method == "GET" and path == "/bootstrap-status":
                return Response(200, {"initialized": self.service.has_administrator()})
            if method == "POST" and path == "/auth/login":
                return Response(200, self.service.login(payload["user_id"], payload["password"]))
            if method == "POST" and path == "/auth/logout":
                self.service.logout(self._token(normalized_headers))
                return Response(200, {"status": "logged_out"})

            route = self._route(method, path, parts)
            if route is None:
                return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})
            permission, action = route
            token = self._token(normalized_headers)
            if permission is not None:
                # 先认证鉴权，再解析动作参数：凭据问题一律先返回 401/403。
                self.service.identity.require_permission(token, permission)

            return self._dispatch(action, parts, query, normalized_headers, payload, token)
        except Unauthorized:
            # 不回显具体原因，避免帮助伪造者；详细原因已写入授权事件。
            return Response(401, {"error": {"code": "unauthorized", "message": "凭据缺失、无效或已过期"}})
        except ServiceError as exc:
            return Response(exc.status, {"error": {"code": exc.code, "message": str(exc)}})
        except (KeyError, TypeError, ValueError) as exc:
            return Response(422, {"error": {"code": "invalid_request", "message": str(exc)}})

    def _dispatch(
        self, action: str, parts: list[str], query, headers, payload: dict[str, Any], token: str | None
    ) -> Response:
        service = self.service
        status = 200

        if action == "account.create":
            result = service.create_account(
                token, payload["user_id"], payload["display_name"], payload["role"],
                payload["password"], payload.get("reason", ""),
            )
            status = 201
        elif action == "account.list":
            result = {"accounts": service.list_accounts(token)}
        elif action == "account.detail":
            result = service.account_detail(token, parts[1])
        elif action == "account.role":
            expected = payload.get("expected_role_version")
            result = service.change_role(
                token, parts[1], payload["role"], payload.get("reason", ""),
                int(expected) if expected is not None else None,
            )
        elif action == "account.deactivate":
            expected = payload.get("expected_role_version")
            result = service.deactivate_account(
                token, parts[1], payload.get("reason", ""),
                int(expected) if expected is not None else None,
            )
        elif action == "auth.events":
            result = {"events": service.authorization_events(token, query.get("user_id", [None])[0])}
        elif action == "program.create":
            result = service.register_program(
                token, payload["program_id"], payload["program_name"], payload["lead_organization"]
            )
            status = 201
        elif action == "evidence.create":
            result = service.register_evidence_revision(
                token, payload["evidence_revision_id"], payload["program_id"],
                payload["version"], payload["content_sha256"],
            )
            status = 201
        elif action == "protocol.publish":
            result = service.publish_protocol(token, payload)
            status = 201
        elif action == "batch.create":
            result = service.create_batch(
                token, payload["batch_id"], payload["protocol_id"],
                int(payload["protocol_version"]), payload["evidence_revision_id"],
            )
            status = 201
        elif action == "batch.start":
            result = service.start_batch(token, parts[1], int(payload["expected_revision"]))
        elif action == "batch.observations":
            key = headers.get("idempotency-key", "").strip()
            if not key:
                raise ValidationFailed("缺少 Idempotency-Key")
            result = service.import_observations(token, parts[1], key, payload.get("observations", []))
        elif action == "batch.seal":
            result = service.seal_batch(token, parts[1], int(payload["expected_revision"]))
        elif action == "batch.report":
            result = service.report(token, parts[1])
        elif action == "exclusion.request":
            result = service.request_exclusion(token, int(payload["observation_id"]), payload["reason"])
            status = 201
        elif action == "exclusion.review":
            result = service.review_exclusion(
                token, int(parts[1]), bool(payload["approve"]), payload.get("note", "")
            )
        elif action == "exclusion.revoke":
            result = service.revoke_exclusion(token, int(parts[1]), payload["reason"])
        elif action == "job.claim":
            result = {"job": service.claim_job(payload["worker_id"], int(payload.get("lease_seconds", 60)))}
        elif action == "job.complete":
            result = service.complete_job(payload["worker_id"], int(parts[1]), token)
        elif action == "job.fail":
            result = service.fail_job(
                payload["worker_id"], int(parts[1]), payload["error"],
                int(payload.get("retry_seconds", 0)),
            )
        elif action == "decision.create":
            result = service.decide(
                token, payload["batch_id"], int(payload["analysis_id"]),
                payload["decision"], payload["reason"],
            )
            status = 201
        else:  # pragma: no cover - 路由表与分发应保持一致
            return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})
        return Response(status, result)


def make_handler(application: JsonApplication):
    class Handler(BaseHTTPRequestHandler):
        server_version = "RobotTrials/1"

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            response = application.handle(self.command, self.path, dict(self.headers.items()), body)
            encoded = json.dumps(response.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            if response.status == 401:
                self.send_header("WWW-Authenticate", "Bearer")
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动合作项目状态与结项评估准入 HTTP 服务")
    parser.add_argument("--database", type=Path, default=Path("cooperation_assurance.sqlite3"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--bootstrap-admin",
        help="仅在库中尚无管理员时本地建立首位管理员，格式 编号:显示名称:口令，不经过网络",
    )
    args = parser.parse_args(argv)
    if args.bootstrap_admin:
        try:
            user_id, display_name, password = args.bootstrap_admin.split(":", 2)
        except ValueError:
            parser.error("--bootstrap-admin 格式必须是 编号:显示名称:口令")
        # 引导在主线程用独立连接完成，随即关闭；之后各工作线程各自连库。
        bootstrap_connection = connect(args.database)
        try:
            bootstrap_service = AssuranceService(bootstrap_connection)
            result = bootstrap_service.bootstrap_administrator(user_id, password, display_name)
        finally:
            bootstrap_connection.close()
        print(json.dumps({"bootstrap": result}, ensure_ascii=False))

    service = ThreadLocalService(args.database)
    application = JsonApplication(service)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(application))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        service.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
