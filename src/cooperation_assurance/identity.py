"""身份建立与鉴权层：凭据、会话、角色版本与授权事件。

设计边界：
- 首次管理员只能由进程本地引导（bootstrap_administrator），不经过网络接口；
- 日常开户、角色调整、停用都要求 administrator 的有效会话；
- 服务端只保存口令的 PBKDF2 哈希与会话令牌的 SHA-256 哈希；
- 每次授权判定都读取已提交的最新角色版本与停用状态，停用即时生效；
- 缺失、过期、伪造、撤销的凭据一律拒绝，拒绝原因写入 auth_events；
- 账户与角色的每次状态变化都在 user_role_history 留下不可覆盖的版本记录。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from .clock import SystemClock, isoformat
from .errors import (
    Conflict,
    Forbidden,
    InvalidState,
    MissingCredentials,
    NotFound,
    ServiceError,
    TokenExpired,
    TokenRevoked,
    ValidationFailed,
)
from .storage import transaction


PBKDF2_ITERATIONS = 120_000
SESSION_TTL = timedelta(hours=8)
MIN_PASSWORD_LENGTH = 12

BUSINESS_ROLES = ("operator", "statistician", "approver", "auditor")
ALL_ROLES = BUSINESS_ROLES + ("administrator",)

# 管理员独有的账户管理权限；业务权限按角色区分。
ADMIN_PERMISSION = "account.manage"

# 各角色可执行的业务/审计权限。管理员只掌握账户管理与只读审计，
# 不直接参与评估决定，保持开户与审批的职责分离。
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "operator": {
        "read", "catalog.write", "batch.create", "batch.start", "observation.import",
        "exclusion.request", "exclusion.revoke",
    },
    "statistician": {"read", "protocol.publish", "batch.seal", "exclusion.review", "analysis.run"},
    "approver": {"read", "decision.write"},
    "auditor": {"read", "report.read", "audit.read"},
    "administrator": {"read", "report.read", "audit.read", ADMIN_PERMISSION},
}


@dataclass(frozen=True, slots=True)
class Principal:
    """一次请求经过鉴权后确认的操作者身份。"""

    user_id: str
    role: str
    role_version: int
    session_token: str | None


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    ).hex()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class IdentityRegistry:
    """在 AssuranceService 的同一连接上管理账户、会话与授权事件。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()

    def _now(self) -> str:
        return isoformat(self.clock.now())

    # -- 授权事件 -------------------------------------------------------

    def _record_auth_event(
        self,
        event_type: str,
        *,
        result: str,
        reason_code: str,
        reason: str,
        user_id: str | None = None,
        actor_id: str | None = None,
        attempted_role: str | None = None,
        role_version: int | None = None,
        permission: str | None = None,
    ) -> None:
        self.connection.execute(
            "INSERT INTO auth_events(event_type,user_id,actor_id,attempted_role,role_version,"
            "permission,result,reason_code,reason,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                event_type, user_id, actor_id, attempted_role, role_version,
                permission, result, reason_code, reason, self._now(),
            ),
        )

    def _deny(
        self,
        reason_code: str,
        reason: str,
        *,
        exc_type: type[ServiceError],
        user_id: str | None = None,
        role_version: int | None = None,
        permission: str | None = None,
    ) -> None:
        """在独立事务里落一条 request.denied，再抛出对应异常。"""

        with transaction(self.connection, immediate=True):
            self._record_auth_event(
                "request.denied", user_id=user_id, role_version=role_version,
                permission=permission, result="denied",
                reason_code=reason_code, reason=reason,
            )
        raise exc_type(reason)

    # -- 首次管理员初始化 -----------------------------------------------

    def has_administrator(self) -> bool:
        return self.connection.execute(
            "SELECT 1 FROM users WHERE role='administrator' AND active=1 LIMIT 1"
        ).fetchone() is not None

    def bootstrap_administrator(
        self, user_id: str, password: str, display_name: str
    ) -> dict[str, Any]:
        """建立首位管理员；只允许在库中从无管理员时成功一次。

        重复引导不会覆盖已有人员、口令或角色版本。
        """

        user_id = (user_id or "").strip()
        display_name = (display_name or "").strip()
        self._validate_password(password)
        if not user_id or not display_name:
            raise ValidationFailed("管理员编号和名称不能为空")
        now = self._now()
        salt = secrets.token_hex(16)
        try:
            with transaction(self.connection, immediate=True):
                existing = self.connection.execute(
                    "SELECT user_id FROM users WHERE role='administrator'"
                ).fetchone()
                if existing is not None:
                    raise Conflict("管理员已经初始化，重复引导不会覆盖已有账户")
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,role,role_version,active,"
                    "password_salt,password_hash,created_by,created_at,updated_at) "
                    "VALUES(?,?,?,1,1,?,?, 'system:bootstrap',?,?)",
                    (user_id, display_name, "administrator", salt,
                     hash_password(password, salt), now, now),
                )
                self.connection.execute(
                    "INSERT INTO user_role_history(user_id,role_version,role,granted_by,"
                    "change_type,reason,created_at) VALUES(?,1,'administrator','system:bootstrap',"
                    "'created','首次管理员本地初始化',?)",
                    (user_id, now),
                )
                self._record_auth_event(
                    "admin.initialized", user_id=user_id, actor_id="system:bootstrap",
                    role_version=1, result="granted",
                    reason_code="bootstrap_ok", reason="首次管理员由本地引导建立",
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("管理员已经初始化或用户编号冲突") from exc
        return {
            "user_id": user_id, "display_name": display_name,
            "role": "administrator", "role_version": 1,
            "created_by": "system:bootstrap", "created_at": now,
        }

    # -- 会话 -----------------------------------------------------------

    def issue_session(self, user_id: str, password: str) -> tuple[str, dict[str, Any]]:
        """校验口令并签发会话；失败只落一条拒绝事件，绝不产生会话。"""

        user_id = (user_id or "").strip()
        row = self.connection.execute(
            "SELECT role,role_version,active,password_salt,password_hash "
            "FROM users WHERE user_id=?",
            (user_id,),
        ).fetchone()
        # 账号不存在时也做一次等长哈希比较，削弱用户枚举时序信号。
        salt = row["password_salt"] if row is not None and row["password_salt"] else "00" * 16
        candidate = hash_password(password or "", salt)
        valid = (
            row is not None
            and row["active"] == 1
            and row["password_hash"] is not None
            and hmac.compare_digest(candidate, row["password_hash"])
        )
        if not valid:
            with transaction(self.connection, immediate=True):
                self._record_auth_event(
                    "login.denied", user_id=user_id or None,
                    attempted_role=row["role"] if row is not None else None,
                    role_version=row["role_version"] if row is not None else None,
                    result="denied", reason_code="invalid_credentials",
                    reason="账号不存在、已停用或口令错误",
                )
            raise MissingCredentials("凭据无效或账号不可用")
        token = secrets.token_urlsafe(32)
        now = self.clock.now()
        issued_at = isoformat(now)
        expires_at = isoformat(now + SESSION_TTL)
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "INSERT INTO sessions(token_hash,user_id,issued_at,expires_at) VALUES(?,?,?,?)",
                (hash_token(token), user_id, issued_at, expires_at),
            )
            self._record_auth_event(
                "login.succeeded", user_id=user_id, actor_id=user_id,
                role_version=row["role_version"], result="granted",
                reason_code="login_ok", reason="口令校验通过，会话已签发",
            )
        return token, {
            "user_id": user_id,
            "role": row["role"],
            "role_version": row["role_version"],
            "issued_at": issued_at,
            "expires_at": expires_at,
        }

    def logout(self, token: str | None) -> None:
        if not token:
            return
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
                (self._now(), hash_token(token)),
            )

    def authenticate(self, token: str | None) -> Principal:
        """验证 Bearer 令牌；缺失、伪造、过期、撤销、停用一律拒绝并审计。"""

        if not token:
            self._deny("missing_token", "缺少 Authorization 凭据", exc_type=MissingCredentials)
        row = self.connection.execute(
            "SELECT u.user_id,u.role,u.role_version,u.active,"
            "s.revoked_at,s.expires_at "
            "FROM sessions s JOIN users u ON u.user_id=s.user_id "
            "WHERE s.token_hash=?",
            (hash_token(token),),
        ).fetchone()
        if row is None:
            self._deny("invalid_token", "会话不存在或凭据伪造", exc_type=MissingCredentials)
        if row["revoked_at"] is not None:
            self._deny("token_revoked", "会话已随账户停用或登出而撤销",
                       exc_type=TokenRevoked, user_id=row["user_id"],
                       role_version=row["role_version"])
        if row["active"] != 1:
            self._deny("account_deactivated", "账户已停用，会话不再有效",
                       exc_type=MissingCredentials, user_id=row["user_id"],
                       role_version=row["role_version"])
        if self._now() >= row["expires_at"]:
            self._deny("token_expired", "会话已过期", exc_type=TokenExpired,
                       user_id=row["user_id"], role_version=row["role_version"])
        return Principal(row["user_id"], row["role"], row["role_version"], token)

    def require_permission(self, token: str | None, permission: str) -> Principal:
        """认证 + 权限校验；管理员的账户管理权限与业务权限在此分流。"""

        principal = self.authenticate(token)
        if permission not in ROLE_PERMISSIONS.get(principal.role, set()):
            self._deny(
                "forbidden", f"角色 {principal.role} 无权执行 {permission}",
                exc_type=Forbidden, user_id=principal.user_id,
                role_version=principal.role_version, permission=permission,
            )
        return principal

    # -- 账户管理（均要求管理员会话） -----------------------------------

    @staticmethod
    def _validate_password(password: str) -> None:
        if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
            raise ValidationFailed(f"口令长度至少 {MIN_PASSWORD_LENGTH} 位")

    def _guard_not_last_administrator(self, user_id: str) -> None:
        count = self.connection.execute(
            "SELECT count(*) FROM users WHERE role='administrator' AND active=1"
        ).fetchone()[0]
        if count <= 1:
            raise InvalidState("不能降级或停用最后一位在用管理员，系统必须保留可管理入口")

    def create_account(
        self, admin_token: str | None, user_id: str, display_name: str, role: str,
        password: str, reason: str,
    ) -> dict[str, Any]:
        actor = self.require_permission(admin_token, ADMIN_PERMISSION)
        user_id = (user_id or "").strip()
        display_name = (display_name or "").strip()
        reason = (reason or "").strip()
        if role not in ALL_ROLES:
            raise ValidationFailed(f"未知角色: {role}")
        if not user_id or not display_name:
            raise ValidationFailed("用户编号和名称不能为空")
        if not reason:
            raise ValidationFailed("开户必须填写授权理由")
        self._validate_password(password)
        now = self._now()
        salt = secrets.token_hex(16)
        password_hash = hash_password(password, salt)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,role,role_version,active,"
                    "password_salt,password_hash,created_by,created_at,updated_at) "
                    "VALUES(?,?,?,1,1,?,?,?,?,?)",
                    (user_id, display_name, role, salt, password_hash,
                     actor.user_id, now, now),
                )
                self.connection.execute(
                    "INSERT INTO user_role_history(user_id,role_version,role,granted_by,"
                    "change_type,reason,created_at) VALUES(?,1,?,?,'created',?,?)",
                    (user_id, role, actor.user_id, reason, now),
                )
                self._record_auth_event(
                    "user.created", user_id=user_id, actor_id=actor.user_id,
                    attempted_role=role, role_version=1, result="granted",
                    reason_code="account_created", reason=reason,
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在或角色版本冲突: {user_id}") from exc
        return self._account_view(user_id)

    def change_role(
        self, admin_token: str | None, user_id: str, new_role: str, reason: str,
        expected_role_version: int | None = None,
    ) -> dict[str, Any]:
        actor = self.require_permission(admin_token, ADMIN_PERMISSION)
        user_id = (user_id or "").strip()
        reason = (reason or "").strip()
        if new_role not in ALL_ROLES:
            raise ValidationFailed(f"未知角色: {new_role}")
        if not reason:
            raise ValidationFailed("角色调整必须填写授权理由")
        if expected_role_version is not None and expected_role_version <= 0:
            raise ValidationFailed("期望角色版本必须为正整数")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT role,role_version,active FROM users WHERE user_id=?", (user_id,)
            ).fetchone()
            if row is None:
                raise NotFound(f"用户不存在: {user_id}")
            if row["active"] != 1:
                raise InvalidState("账户已停用，不能调整角色；如需恢复请重新开户")
            if actor.user_id == user_id:
                raise Forbidden("管理员不能变更自己的角色，避免越权或自锁")
            if expected_role_version is not None and row["role_version"] != expected_role_version:
                raise Conflict("角色版本已变化，请基于当前版本重试")
            if row["role"] == new_role:
                raise Conflict(f"账户已经是角色 {new_role}，无需调整")
            if row["role"] == "administrator" and new_role != "administrator":
                self._guard_not_last_administrator(user_id)
            base_version = (
                expected_role_version if expected_role_version is not None else row["role_version"]
            )
            next_version = base_version + 1
            now = self._now()
            cursor = self.connection.execute(
                "UPDATE users SET role=?,role_version=?,updated_at=? "
                "WHERE user_id=? AND active=1 AND role_version=?",
                (new_role, next_version, now, user_id, base_version),
            )
            if cursor.rowcount != 1:
                raise Conflict("角色版本已变化，请基于当前版本重试")
            self.connection.execute(
                "INSERT INTO user_role_history(user_id,role_version,role,granted_by,"
                "change_type,reason,created_at) VALUES(?,?,?,?, 'role_changed',?,?)",
                (user_id, next_version, new_role, actor.user_id, reason, now),
            )
            self._record_auth_event(
                "user.role_changed", user_id=user_id, actor_id=actor.user_id,
                attempted_role=new_role, role_version=next_version, result="granted",
                reason_code="role_changed", reason=reason,
            )
        return self._account_view(user_id)

    def deactivate_account(
        self, admin_token: str | None, user_id: str, reason: str,
        expected_role_version: int | None = None,
    ) -> dict[str, Any]:
        actor = self.require_permission(admin_token, ADMIN_PERMISSION)
        user_id = (user_id or "").strip()
        reason = (reason or "").strip()
        if not reason:
            raise ValidationFailed("停用必须填写授权理由")
        if expected_role_version is not None and expected_role_version <= 0:
            raise ValidationFailed("期望角色版本必须为正整数")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT role,role_version,active FROM users WHERE user_id=?", (user_id,)
            ).fetchone()
            if row is None:
                raise NotFound(f"用户不存在: {user_id}")
            if expected_role_version is not None and row["role_version"] != expected_role_version:
                raise Conflict("角色版本已变化，请基于当前版本重试")
            if row["active"] != 1:
                raise InvalidState("账户已经处于停用状态")
            if actor.user_id == user_id:
                raise Forbidden("管理员不能停用自己的账户")
            if row["role"] == "administrator":
                self._guard_not_last_administrator(user_id)
            base_version = (
                expected_role_version if expected_role_version is not None else row["role_version"]
            )
            next_version = base_version + 1
            now = self._now()
            cursor = self.connection.execute(
                "UPDATE users SET active=0,role_version=?,updated_at=? "
                "WHERE user_id=? AND active=1 AND role_version=?",
                (next_version, now, user_id, base_version),
            )
            if cursor.rowcount != 1:
                raise Conflict("账户状态已变化，请基于当前版本重试")
            # 撤销该账户全部未撤销会话，停用即时生效。
            self.connection.execute(
                "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
                (now, user_id),
            )
            self.connection.execute(
                "INSERT INTO user_role_history(user_id,role_version,role,granted_by,"
                "change_type,reason,created_at) VALUES(?,?,?,?, 'deactivated',?,?)",
                (user_id, next_version, row["role"], actor.user_id, reason, now),
            )
            self._record_auth_event(
                "user.deactivated", user_id=user_id, actor_id=actor.user_id,
                role_version=next_version, result="granted",
                reason_code="account_deactivated", reason=reason,
            )
        return self._account_view(user_id)

    # -- 只读视图（供 API/审计） ----------------------------------------

    def _account_view(self, user_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT user_id,display_name,role,role_version,active,created_by,created_at,updated_at "
            "FROM users WHERE user_id=?",
            (user_id,),
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        return dict(row) | {"active": bool(row["active"])}

    def list_accounts(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT user_id,display_name,role,role_version,active,created_by,created_at,updated_at "
            "FROM users ORDER BY created_at,user_id"
        ).fetchall()
        return [dict(row) | {"active": bool(row["active"])} for row in rows]

    def account_detail(self, user_id: str) -> dict[str, Any]:
        account = self._account_view(user_id)
        history = self.connection.execute(
            "SELECT role_version,role,granted_by,change_type,reason,created_at "
            "FROM user_role_history WHERE user_id=? ORDER BY role_version",
            (user_id,),
        ).fetchall()
        account["role_history"] = [dict(row) for row in history]
        return account

    def authorization_events(self, user_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = (
            "SELECT event_id,event_type,user_id,actor_id,attempted_role,role_version,"
            "permission,result,reason_code,reason,created_at FROM auth_events"
        )
        params: tuple[Any, ...] = ()
        if user_id:
            sql += " WHERE user_id=?"
            params = (user_id,)
        sql += " ORDER BY event_id DESC LIMIT ?"
        params += (limit,)
        return [dict(row) for row in self.connection.execute(sql, params).fetchall()]
