"""统计分析准入服务的领域用例。"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Iterable, Mapping

from .analysis import ALGORITHM_VERSION, analyze
from .clock import SystemClock, isoformat
from .contracts import Observation, Protocol, ValidationError
from .errors import Conflict, Forbidden, InvalidState, NotFound, Unauthorized, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


ROLE_PERMISSIONS = {
    "operator": {
        "catalog.write", "batch.create", "batch.start", "observation.import",
        "exclusion.request", "exclusion.revoke",
    },
    "statistician": {"protocol.publish", "batch.seal", "exclusion.review", "analysis.run"},
    "approver": {"decision.write"},
    "auditor": {"report.read", "audit.read", "user.read"},
    "admin": {"user.read", "user.create", "user.role", "user.password", "user.deactivate", "audit.read"},
}

SESSION_TTL = timedelta(hours=8)
MIN_PASSWORD_LENGTH = 8
USER_PUBLIC_COLUMNS = "user_id,display_name,role,active,role_version,authorized_by,created_at,updated_at"


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 80_000).hex()


class AssuranceService:
    """在单个 SQLite 连接上提供全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, role, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            self._record_denial(user_id, "permission_denied", {"permission": permission, "role": user["role"]})
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(payload), self._now()),
        )

    def _record_denial(self, entity_id: str, reason: str, detail: Mapping[str, Any] | None = None) -> None:
        """记录一次访问拒绝；只写审计，不改变任何业务状态。"""

        payload = {"reason": reason}
        if detail:
            payload.update(detail)
        self._audit("auth", entity_id, "auth.denied", entity_id, payload)

    @staticmethod
    def _validate_password(password: str) -> None:
        if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
            raise ValidationFailed(f"口令长度至少 {MIN_PASSWORD_LENGTH} 位")

    def _store_credentials(self, user_id: str, password: str) -> None:
        salt = secrets.token_hex(16)
        self.connection.execute(
            "INSERT INTO user_credentials(user_id,salt,password_hash,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(user_id) DO UPDATE SET salt=excluded.salt,password_hash=excluded.password_hash,"
            "updated_at=excluded.updated_at",
            (user_id, salt, _hash_password(password, salt), self._now()),
        )

    def _active_admin_count(self) -> int:
        return self.connection.execute(
            "SELECT count(*) FROM users WHERE role='admin' AND active=1"
        ).fetchone()[0]

    def bootstrap_admin(self, user_id: str, display_name: str, password: str) -> dict[str, Any]:
        """首次初始化管理员。

        仅当没有在管管理员时可用；用户编号被占用或已初始化都会拒绝，
        任何情况下都不覆盖已有人员。授权来源记录为账号自身（初始化自举）。
        """

        user_id = user_id.strip()
        display_name = display_name.strip()
        if not user_id or not display_name:
            raise ValidationFailed("用户编号和名称不能为空")
        self._validate_password(password)
        try:
            with transaction(self.connection, immediate=True):
                if self._active_admin_count():
                    raise Conflict("管理员已初始化，不能重复初始化")
                now = self._now()
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,role,active,role_version,authorized_by,created_at,updated_at) "
                    "VALUES(?,?,?,1,1,?,?,?)",
                    (user_id, display_name, "admin", user_id, now, now),
                )
                self._store_credentials(user_id, password)
                self._audit(
                    "user", user_id, "user.bootstrapped", user_id,
                    {"role": "admin", "role_version": 1, "source": "bootstrap"},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id, "role": "admin", "role_version": 1, "authorized_by": user_id}

    def create_user(self, actor_id: str, user_id: str, display_name: str, role: str, password: str) -> dict[str, Any]:
        """日常开户：只有在管管理员可以开立账号，授权者写入记录与审计。"""

        actor = self._require(actor_id, "user.create")
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        user_id = user_id.strip()
        display_name = display_name.strip()
        if not user_id or not display_name:
            raise ValidationFailed("用户编号和名称不能为空")
        self._validate_password(password)
        try:
            with transaction(self.connection, immediate=True):
                now = self._now()
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,role,active,role_version,authorized_by,created_at,updated_at) "
                    "VALUES(?,?,?,1,1,?,?,?)",
                    (user_id, display_name, role, actor["user_id"], now, now),
                )
                self._store_credentials(user_id, password)
                self._audit("user", user_id, "user.created", actor["user_id"], {"role": role, "role_version": 1})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id, "role": role, "role_version": 1, "authorized_by": actor["user_id"]}

    def change_role(self, actor_id: str, user_id: str, role: str, expected_role_version: int) -> dict[str, Any]:
        """角色调整：管理员按当前角色版本变更；版本不匹配说明存在并发修改。"""

        actor = self._require(actor_id, "user.role")
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
            if row is None:
                raise NotFound(f"用户不存在: {user_id}")
            if not row["active"]:
                raise InvalidState("用户已停用，不能调整角色")
            if row["role"] == role:
                raise ValidationFailed("角色未变化")
            if row["role"] == "admin" and role != "admin" and self._active_admin_count() <= 1:
                raise Conflict("至少保留一名在管管理员")
            cursor = self.connection.execute(
                "UPDATE users SET role=?,role_version=role_version+1,updated_at=? "
                "WHERE user_id=? AND role_version=? AND active=1",
                (role, self._now(), user_id, expected_role_version),
            )
            if cursor.rowcount != 1:
                raise Conflict("角色版本已变化，请读取最新版本后重试")
            new_version = expected_role_version + 1
            self._audit(
                "user", user_id, "user.role_changed", actor["user_id"],
                {
                    "from_role": row["role"], "to_role": role,
                    "from_role_version": row["role_version"], "to_role_version": new_version,
                },
            )
        return {"user_id": user_id, "role": role, "role_version": new_version, "authorized_by": actor["user_id"]}

    def reset_password(self, actor_id: str, user_id: str, password: str) -> dict[str, Any]:
        """管理员重置口令；重置后该账号全部旧会话失效。"""

        actor = self._require(actor_id, "user.password")
        self._validate_password(password)
        with transaction(self.connection, immediate=True):
            if not self.connection.execute("SELECT 1 FROM users WHERE user_id=?", (user_id,)).fetchone():
                raise NotFound(f"用户不存在: {user_id}")
            self._store_credentials(user_id, password)
            self.connection.execute("UPDATE auth_sessions SET active=0 WHERE user_id=?", (user_id,))
            self._audit("user", user_id, "user.password_reset", actor["user_id"], {})
        return {"user_id": user_id, "password_reset": True}

    def deactivate_user(self, actor_id: str, user_id: str) -> dict[str, Any]:
        """停用账号：同一事务内吊销全部会话，失败不留可登录会话。"""

        actor = self._require(actor_id, "user.deactivate")
        if actor["user_id"] == user_id:
            raise ValidationFailed("不能停用当前登录账号")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
            if row is None:
                raise NotFound(f"用户不存在: {user_id}")
            if row["role"] == "admin" and self._active_admin_count() <= 1:
                raise Conflict("至少保留一名在管管理员")
            cursor = self.connection.execute(
                "UPDATE users SET active=0,updated_at=? WHERE user_id=? AND active=1",
                (self._now(), user_id),
            )
            if cursor.rowcount != 1:
                raise Conflict("用户已停用")
            self.connection.execute("UPDATE auth_sessions SET active=0 WHERE user_id=?", (user_id,))
            self._audit(
                "user", user_id, "user.deactivated", actor["user_id"],
                {"role": row["role"], "role_version": row["role_version"]},
            )
        return {"user_id": user_id, "active": False, "role_version": row["role_version"]}

    def login(self, user_id: str, password: str) -> dict[str, Any]:
        """口令登录：验证通过才写入会话；失败只留拒绝审计，不留会话。"""

        row = self.connection.execute(
            "SELECT u.user_id,u.role,u.active,c.salt,c.password_hash FROM users u "
            "LEFT JOIN user_credentials c ON c.user_id=u.user_id WHERE u.user_id=?",
            (user_id,),
        ).fetchone()
        if row is None:
            self._record_denial(user_id, "unknown_user")
            raise Unauthorized("账号或口令不正确")
        if not row["active"]:
            self._record_denial(user_id, "user_deactivated")
            raise Unauthorized("用户已停用")
        if row["password_hash"] is None or not hmac.compare_digest(
            _hash_password(password, row["salt"]), row["password_hash"]
        ):
            self._record_denial(user_id, "bad_password")
            raise Unauthorized("账号或口令不正确")
        token = secrets.token_urlsafe(32)
        expires_at = isoformat(self.clock.now() + SESSION_TTL)
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "INSERT INTO auth_sessions(token,user_id,created_at,expires_at,active) VALUES(?,?,?,?,1)",
                (token, user_id, self._now(), expires_at),
            )
            self._audit("auth", user_id, "auth.session_issued", user_id, {"expires_at": expires_at})
        return {"token": token, "user_id": user_id, "role": row["role"], "expires_at": expires_at}

    def authenticate(self, token: str) -> sqlite3.Row:
        """解析 Bearer 凭据；缺失、伪造、吊销或过期的凭据一律拒绝并记录原因。"""

        token = (token or "").strip()
        if not token:
            self._record_denial("anonymous", "missing_credentials")
            raise Unauthorized("缺少访问凭据")
        row = self.connection.execute(
            "SELECT u.user_id,u.display_name,u.role,u.active,u.role_version,"
            "s.active AS session_active,s.expires_at "
            "FROM auth_sessions s JOIN users u ON u.user_id=s.user_id WHERE s.token=?",
            (token,),
        ).fetchone()
        if row is None:
            fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
            self._record_denial("anonymous", "unknown_token", {"token_fingerprint": fingerprint})
            raise Unauthorized("凭据无效")
        if not row["session_active"]:
            self._record_denial(row["user_id"], "session_revoked")
            raise Unauthorized("会话已失效")
        if datetime.fromisoformat(row["expires_at"]) <= self.clock.now():
            self._record_denial(row["user_id"], "session_expired")
            raise Unauthorized("会话已过期")
        if not row["active"]:
            self._record_denial(row["user_id"], "user_deactivated")
            raise Unauthorized("用户已停用")
        return row

    def user_directory(self, actor_id: str) -> list[dict[str, Any]]:
        """账号目录：向安全人员展示授权者与角色版本。"""

        self._require(actor_id, "user.read")
        rows = self.connection.execute(
            f"SELECT {USER_PUBLIC_COLUMNS} FROM users ORDER BY user_id"
        ).fetchall()
        return [dict(row) for row in rows]

    def user_detail(self, actor_id: str, user_id: str) -> dict[str, Any]:
        self._require(actor_id, "user.read")
        row = self.connection.execute(
            f"SELECT {USER_PUBLIC_COLUMNS} FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        return dict(row)

    def access_audit(self, actor_id: str) -> list[dict[str, Any]]:
        """身份链审计：开户、角色调整、停用与全部访问拒绝记录。"""

        self._require(actor_id, "audit.read")
        rows = self.connection.execute(
            "SELECT event_id,entity_type,entity_id,event_type,actor_id,payload_json,created_at "
            "FROM audit_events WHERE entity_type IN ('auth','user') ORDER BY event_id",
        ).fetchall()
        return [dict(row) | {"payload": json.loads(row["payload_json"])} for row in rows]

    def register_program(
        self, actor_id: str, program_id: str, program_name: str, lead_organization: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO cooperation_programs(program_id,program_name,lead_organization,created_at) VALUES(?,?,?,?)",
                    (program_id, program_name, lead_organization, self._now()),
                )
                self._audit("asset", program_id, "asset.registered", actor_id, {"program_name": program_name})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"跨境合作项目已存在: {program_id}") from exc
        return {"program_id": program_id, "program_name": program_name, "lead_organization": lead_organization}

    def register_evidence_revision(
        self, actor_id: str, evidence_revision_id: str, program_id: str, version: str, content_sha256: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        if len(content_sha256) != 64:
            raise ValidationFailed("证据版本摘要必须是 64 位 SHA-256")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO evidence_revisions(evidence_revision_id,program_id,version,content_sha256,created_at) VALUES(?,?,?,?,?)",
                    (evidence_revision_id, program_id, version, content_sha256.lower(), self._now()),
                )
                self._audit("evidence_revision", evidence_revision_id, "evidence_revision.registered", actor_id, {"program_id": program_id, "version": version})
        except sqlite3.IntegrityError as exc:
            raise Conflict("证据版本编号、版本或摘要冲突") from exc
        return {"evidence_revision_id": evidence_revision_id, "program_id": program_id, "version": version}

    def publish_protocol(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "protocol.publish")
        try:
            protocol = Protocol.from_dict(raw)
        except ValidationError as exc:
            raise ValidationFailed(str(exc)) from exc
        text = canonical_json(raw)
        digest = content_digest([raw])
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO protocol_catalog(protocol_id,version,title,task_family,canonical_json,content_sha256,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        protocol.protocol_id,
                        protocol.version,
                        protocol.title,
                        protocol.task_family,
                        text,
                        digest,
                        self._now(),
                    ),
                )
                identity = f"{protocol.protocol_id}@{protocol.version}"
                self._audit("protocol", identity, "protocol.published", actor_id, {"sha256": digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("协议版本或内容摘要已经存在") from exc
        return {"protocol_id": protocol.protocol_id, "version": protocol.version, "sha256": digest}

    def _protocol(self, protocol_id: str, version: int) -> tuple[Protocol, str]:
        row = self.connection.execute(
            "SELECT canonical_json,content_sha256 FROM protocol_catalog WHERE protocol_id=? AND version=?",
            (protocol_id, version),
        ).fetchone()
        if row is None:
            raise NotFound("协议版本不存在")
        return Protocol.from_dict(json.loads(row["canonical_json"])), row["content_sha256"]

    def create_batch(
        self,
        actor_id: str,
        batch_id: str,
        protocol_id: str,
        protocol_version: int,
        evidence_revision_id: str,
    ) -> dict[str, Any]:
        self._require(actor_id, "batch.create")
        self._protocol(protocol_id, protocol_version)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO batches(batch_id,protocol_id,protocol_version,evidence_revision_id,state,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (batch_id, protocol_id, protocol_version, evidence_revision_id, "draft", actor_id, self._now()),
                )
                self._audit("batch", batch_id, "batch.created", actor_id, {"evidence_revision_id": evidence_revision_id})
        except sqlite3.IntegrityError as exc:
            raise Conflict("批次编号冲突或证据版本不存在") from exc
        return self.get_batch(batch_id)

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            raise NotFound("批次不存在")
        return dict(row)

    def start_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.start")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE batches SET state='running',revision=revision+1,started_at=? "
                "WHERE batch_id=? AND state='draft' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次不是当前草稿版本")
            self._audit("batch", batch_id, "batch.started", actor_id, {"from_revision": expected_revision})
        return self.get_batch(batch_id)

    def _idempotent_response(self, scope: str, key: str, request_digest: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT request_sha256,response_json FROM idempotency_keys WHERE scope=? AND key=?",
            (scope, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_digest:
            raise Conflict("同一幂等键对应了不同请求内容")
        return json.loads(row["response_json"])

    def import_observations(
        self,
        actor_id: str,
        batch_id: str,
        idempotency_key: str,
        raw_rows: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        self._require(actor_id, "observation.import")
        rows = tuple(raw_rows)
        if not rows:
            raise ValidationFailed("测点数组不能为空")
        request_digest = content_digest(rows)
        scope = f"observations:{batch_id}"
        existing = self._idempotent_response(scope, idempotency_key, request_digest)
        if existing is not None:
            return existing
        batch = self.get_batch(batch_id)
        if batch["state"] != "running":
            raise InvalidState("只有运行中的批次可以导入测点")
        protocol, _ = self._protocol(batch["protocol_id"], batch["protocol_version"])
        parsed: list[Observation] = []
        for raw in rows:
            try:
                item = Observation.from_dict(raw, protocol)
            except ValidationError as exc:
                raise ValidationFailed(str(exc)) from exc
            if item.program_id != self.connection.execute(
                "SELECT program_id FROM evidence_revisions WHERE evidence_revision_id=?", (batch["evidence_revision_id"],)
            ).fetchone()["program_id"]:
                raise ValidationFailed("测点跨境合作项目与批次证据版本不一致")
            parsed.append(item)
        response = {"batch_id": batch_id, "inserted": len(parsed), "request_sha256": request_digest}
        try:
            with transaction(self.connection, immediate=True):
                for item, raw in zip(parsed, rows):
                    self.connection.execute(
                        "INSERT INTO observations(batch_id,source_batch,source_row,program_id,stratum_key,observed_at," 
                        "metrics_json,content_sha256,imported_by,imported_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (
                            batch_id,
                            item.source_batch,
                            item.source_row,
                            item.program_id,
                            item.stratum_key,
                            item.observed_at,
                            canonical_json({key: format(value, "f") for key, value in item.metrics.items()}),
                            content_digest([raw]),
                            actor_id,
                            self._now(),
                        ),
                    )
                self.connection.execute(
                    "INSERT INTO idempotency_keys(scope,key,request_sha256,response_json,created_at) VALUES(?,?,?,?,?)",
                    (scope, idempotency_key, request_digest, canonical_json(response), self._now()),
                )
                self._audit("batch", batch_id, "observations.imported", actor_id, response)
        except sqlite3.IntegrityError as exc:
            raise Conflict("来源行重复或幂等键并发冲突") from exc
        return response

    def request_exclusion(self, actor_id: str, observation_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.request")
        observation = self.connection.execute(
            "SELECT observation_id,batch_id FROM observations WHERE observation_id=?", (observation_id,)
        ).fetchone()
        if observation is None:
            raise NotFound("测点不存在")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO exclusion_requests(observation_id,status,reason,requested_by,requested_at) "
                    "VALUES(?,?,?,?,?)",
                    (observation_id, "pending", reason, actor_id, self._now()),
                )
                exclusion_id = cursor.lastrowid
                self._audit("observation", str(observation_id), "exclusion.requested", actor_id, {"reason": reason})
        except sqlite3.IntegrityError as exc:
            raise Conflict("该测点已有待处理或生效排除") from exc
        return {"exclusion_id": exclusion_id, "status": "pending"}

    def review_exclusion(
        self, actor_id: str, exclusion_id: int, approve: bool, note: str
    ) -> dict[str, Any]:
        self._require(actor_id, "exclusion.review")
        row = self.connection.execute(
            "SELECT * FROM exclusion_requests WHERE exclusion_id=?", (exclusion_id,)
        ).fetchone()
        if row is None:
            raise NotFound("排除申请不存在")
        if row["status"] != "pending":
            raise InvalidState("排除申请已经处理")
        if row["requested_by"] == actor_id:
            raise Forbidden("申请人不能复核自己的排除申请")
        status = "approved" if approve else "rejected"
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE exclusion_requests SET status=?,reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE exclusion_id=? AND status='pending'",
                (status, actor_id, self._now(), note, exclusion_id),
            )
            self._audit("exclusion", str(exclusion_id), f"exclusion.{status}", actor_id, {"note": note})
        return {"exclusion_id": exclusion_id, "status": status}

    def revoke_exclusion(self, actor_id: str, exclusion_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.revoke")
        row = self.connection.execute(
            "SELECT e.*,o.batch_id FROM exclusion_requests e "
            "JOIN observations o ON o.observation_id=e.observation_id WHERE e.exclusion_id=?",
            (exclusion_id,),
        ).fetchone()
        if row is None:
            raise NotFound("排除记录不存在")
        if row["status"] != "approved":
            raise InvalidState("只有已批准的排除可以撤销")
        if row["requested_by"] != actor_id:
            raise Forbidden("只有原申请人可以撤销排除")
        batch = self.get_batch(row["batch_id"])
        if batch["state"] != "running":
            raise InvalidState("批次封存后不能改变排除状态")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE exclusion_requests SET status='revoked',review_note=?,reviewed_at=? "
                "WHERE exclusion_id=? AND status='approved'",
                (reason, self._now(), exclusion_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("排除状态已变化")
            self._audit(
                "observation",
                str(row["observation_id"]),
                "exclusion.revoked",
                actor_id,
                {"exclusion_id": exclusion_id, "reason": reason},
            )
        return {"exclusion_id": exclusion_id, "status": "revoked"}

    def seal_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.seal")
        with transaction(self.connection, immediate=True):
            pending = self.connection.execute(
                "SELECT count(*) FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
                "WHERE o.batch_id=? AND e.status='pending'", (batch_id,)
            ).fetchone()[0]
            if pending:
                raise InvalidState("仍有待复核的排除申请")
            cursor = self.connection.execute(
                "UPDATE batches SET state='sealed',revision=revision+1,sealed_at=? "
                "WHERE batch_id=? AND state='running' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次状态或版本已变化")
            new_revision = expected_revision + 1
            now = self._now()
            self.connection.execute(
                "INSERT INTO analysis_jobs(batch_id,batch_revision,state,available_at,created_at,updated_at) "
                "VALUES(?,?, 'queued', ?,?,?)",
                (batch_id, new_revision, now, now, now),
            )
            self._audit("batch", batch_id, "batch.sealed", actor_id, {"revision": new_revision})
        return self.get_batch(batch_id)

    def claim_job(self, worker_id: str, lease_seconds: int = 60) -> dict[str, Any] | None:
        if lease_seconds <= 0:
            raise ValidationFailed("租约时长必须大于零")
        now = self._now()
        expires = isoformat(self.clock.now() + timedelta(seconds=lease_seconds))
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT job_id FROM analysis_jobs WHERE "
                "(state='queued' AND available_at<=?) OR (state='leased' AND lease_expires_at<=?) "
                "ORDER BY available_at,job_id LIMIT 1",
                (now, now),
            ).fetchone()
            if row is None:
                return None
            self.connection.execute(
                "UPDATE analysis_jobs SET state='leased',attempts=attempts+1,lease_owner=?,lease_expires_at=?,updated_at=? "
                "WHERE job_id=?",
                (worker_id, expires, now, row["job_id"]),
            )
            claimed = self.connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (row["job_id"],)).fetchone()
        return dict(claimed)

    def _analysis_observations(self, batch_id: str, protocol: Protocol) -> tuple[Observation, ...]:
        rows = self.connection.execute(
            "SELECT o.*,e.reason AS excluded_reason FROM observations o "
            "LEFT JOIN exclusion_requests e ON e.observation_id=o.observation_id AND e.status='approved' "
            "WHERE o.batch_id=? ORDER BY o.observation_id",
            (batch_id,),
        ).fetchall()
        items: list[Observation] = []
        for row in rows:
            metrics = json.loads(row["metrics_json"])
            items.append(Observation(
                source_batch=row["source_batch"],
                source_row=row["source_row"],
                program_id=row["program_id"],
                protocol_id=protocol.protocol_id,
                protocol_version=protocol.version,
                stratum_key=row["stratum_key"],
                observed_at=row["observed_at"],
                metrics={key: Decimal(str(value)) for key, value in metrics.items()},
                excluded_reason=row["excluded_reason"],
            ))
        return tuple(items)

    def complete_job(self, worker_id: str, job_id: int, statistician_id: str) -> dict[str, Any]:
        self._require(statistician_id, "analysis.run")
        job = self.connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)).fetchone()
        if job is None:
            raise NotFound("分析任务不存在")
        if job["state"] != "leased" or job["lease_owner"] != worker_id:
            raise InvalidState("任务未由当前工作进程持有")
        if job["lease_expires_at"] <= self._now():
            raise InvalidState("任务租约已经过期")
        batch = self.get_batch(job["batch_id"])
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        observations = self._analysis_observations(batch["batch_id"], protocol)
        snapshot_rows = [
            {
                "source_batch": item.source_batch,
                "source_row": item.source_row,
                "stratum": item.stratum_key,
                "metrics": {key: format(value, "f") for key, value in item.metrics.items()},
                "excluded_reason": item.excluded_reason,
            }
            for item in observations
        ]
        input_digest = content_digest(snapshot_rows)
        result = analyze(protocol, observations)
        with transaction(self.connection, immediate=True):
            existing = self.connection.execute(
                "SELECT analysis_id,result_json FROM analyses WHERE batch_id=? AND batch_revision=? AND input_sha256=?",
                (batch["batch_id"], job["batch_revision"], input_digest),
            ).fetchone()
            if existing is None:
                cursor = self.connection.execute(
                    "INSERT INTO analyses(batch_id,batch_revision,protocol_sha256,input_sha256,algorithm_version,seed," 
                    "result_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        batch["batch_id"], job["batch_revision"], protocol_digest, input_digest,
                        ALGORITHM_VERSION, protocol.seed, canonical_json(result), statistician_id, self._now(),
                    ),
                )
                analysis_id = cursor.lastrowid
            else:
                analysis_id = existing["analysis_id"]
                result = json.loads(existing["result_json"])
            self.connection.execute(
                "UPDATE analysis_jobs SET state='succeeded',lease_owner=NULL,lease_expires_at=NULL,updated_at=? "
                "WHERE job_id=? AND state='leased' AND lease_owner=?",
                (self._now(), job_id, worker_id),
            )
            self.connection.execute(
                "UPDATE batches SET state='analyzed' WHERE batch_id=? AND state IN ('sealed','analyzing')",
                (batch["batch_id"],),
            )
            self._audit(
                "batch",
                batch["batch_id"],
                "analysis.completed",
                statistician_id,
                {"analysis_id": analysis_id, "input_sha256": input_digest},
            )
        return {"analysis_id": analysis_id, "input_sha256": input_digest, "result": result}

    def fail_job(self, worker_id: str, job_id: int, error: str, retry_seconds: int = 0) -> dict[str, Any]:
        available = isoformat(self.clock.now() + timedelta(seconds=retry_seconds))
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE analysis_jobs SET state='queued',available_at=?,lease_owner=NULL,lease_expires_at=NULL," 
                "last_error=?,updated_at=? WHERE job_id=? AND state='leased' AND lease_owner=?",
                (available, error[:1000], self._now(), job_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("任务未由当前工作进程持有")
        return {"job_id": job_id, "state": "queued", "available_at": available}

    def decide(
        self, actor_id: str, batch_id: str, analysis_id: int, decision: str, reason: str
    ) -> dict[str, Any]:
        self._require(actor_id, "decision.write")
        if decision not in {"needs_more_data", "approved", "rejected"}:
            raise ValidationFailed("未知分析准入决定")
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE analysis_id=? AND batch_id=?", (analysis_id, batch_id)
        ).fetchone()
        if analysis_row is None:
            raise NotFound("分析版本不存在")
        if analysis_row["created_by"] == actor_id:
            raise Forbidden("统计负责人不能批准自己的分析")
        batch = self.get_batch(batch_id)
        if batch["state"] != "analyzed" or batch["revision"] != analysis_row["batch_revision"]:
            raise InvalidState("分析不是批次当前可审批版本")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO decisions(batch_id,analysis_id,decision,reason,decided_by,decided_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (batch_id, analysis_id, decision, reason, actor_id, self._now()),
                )
                self.connection.execute("UPDATE batches SET state='decided' WHERE batch_id=?", (batch_id,))
                self._audit(
                    "batch",
                    batch_id,
                    "decision.recorded",
                    actor_id,
                    {"decision_id": cursor.lastrowid, "analysis_id": analysis_id, "decision": decision},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该分析版本已经形成决定") from exc
        return {"batch_id": batch_id, "analysis_id": analysis_id, "decision": decision}

    def report(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        user = self._user(actor_id)
        if user["role"] not in {"statistician", "approver", "auditor"}:
            self._record_denial(actor_id, "permission_denied", {"permission": "report.read", "role": user["role"]})
            raise Forbidden("当前角色不能读取完整报告")
        batch = self.get_batch(batch_id)
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE batch_id=? ORDER BY analysis_id DESC LIMIT 1", (batch_id,)
        ).fetchone()
        decision_row = None
        if analysis_row is not None:
            decision_row = self.connection.execute(
                "SELECT * FROM decisions WHERE analysis_id=?", (analysis_row["analysis_id"],)
            ).fetchone()
        exclusions = self.connection.execute(
            "SELECT e.exclusion_id,e.observation_id,e.status,e.reason,e.requested_by,e.reviewed_by "
            "FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
            "WHERE o.batch_id=? ORDER BY e.exclusion_id", (batch_id,)
        ).fetchall()
        events = self.connection.execute(
            "SELECT event_type,actor_id,payload_json,created_at FROM audit_events "
            "WHERE entity_type='batch' AND entity_id=? "
            "ORDER BY event_id", (batch_id,)
        ).fetchall()
        return {
            "batch": batch,
            "protocol": {
                "protocol_id": protocol.protocol_id,
                "version": protocol.version,
                "sha256": protocol_digest,
                "seed": protocol.seed,
                "bootstrap_samples": protocol.bootstrap_samples,
            },
            "analysis": None if analysis_row is None else {
                "analysis_id": analysis_row["analysis_id"],
                "input_sha256": analysis_row["input_sha256"],
                "algorithm_version": analysis_row["algorithm_version"],
                "created_by": analysis_row["created_by"],
                "result": json.loads(analysis_row["result_json"]),
            },
            "decision": None if decision_row is None else dict(decision_row),
            "exclusions": [dict(row) for row in exclusions],
            "events": [dict(row) | {"payload": json.loads(row["payload_json"])} for row in events],
        }
