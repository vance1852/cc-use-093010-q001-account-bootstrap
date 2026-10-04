# 全球数字贸易合作运营平台

本项目是一套可离线运行的 Python 服务端平台，用于管理跨境数字合作中的资源流转、项目证据评估和统计资料质量。平台把运营节点、合作通道、资源申请、项目版本、分析决定、样本观测、权限和审计事件持久化到 SQLite，供秘书处、项目办公室、数据团队和审计人员协作使用。

## 目录

- src/trade_flow/：运营节点、合作通道、资源批次、额度申请、分配和情景分析；
- src/cooperation_assurance/：合作项目、证据版本、评估协议、观测导入、分析任务与准入决定；
- src/metric_quality/：统计样本批次、指标观测、质量分析、账号权限和审批；
- fixtures/：离线验收使用的评估协议与结构化观测；
- tests/：领域规则、错误边界、事务、权限、HTTP API 和命令行验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

    PYTHONPATH=src python3 -m unittest discover -s tests -v

## 构建检查

    python3 -m compileall -q src tests

## 离线验收

    PYTHONPATH=src python3 -m trade_flow.acceptance --workspace .
    PYTHONPATH=src python3 -m cooperation_assurance.acceptance --workspace .
    PYTHONPATH=src python3 -m metric_quality.acceptance

三条命令会在临时 SQLite 数据库中完成合作资源流转、项目证据评估和统计资料质量流程，不访问外部网络。

## HTTP 服务

    PYTHONPATH=src python3 -m trade_flow.api --database trade-flow.sqlite3 --host 127.0.0.1 --port 8080
    PYTHONPATH=src python3 -m cooperation_assurance.api --database cooperation-assurance.sqlite3 --host 127.0.0.1 --port 8081
    PYTHONPATH=src python3 -m metric_quality.api --database metric-quality.sqlite3 --host 127.0.0.1 --port 8082

服务提供 JSON 接口与健康检查。进程重启后可以继续读取 SQLite 中的业务状态和审计历史。

## 项目证据平台的身份与权限（cooperation_assurance）

证据平台不接受任何可由调用方自填的身份头，账户与业务请求一律凭登录令牌：

1. **首次管理员初始化（仅本地、仅一次）**：用 `--bootstrap-admin 编号:显示名称:口令`
   在启动进程时建立首位管理员；不存在任何网络开户/引导路由，重复引导不会覆盖已有人员。
   旧库（schema v2）中没有凭据与授权来源的账号在升级到 v3 后一律停用，并写入
   `system:migration` 角色历史，须由管理员重新开户。
2. **登录**：`POST /auth/login` 校验口令（PBKDF2-SHA256），返回服务端只存其哈希的
   Bearer 令牌（8 小时有效）。错误口令、未知账号、已停用账号一律 401，且不产生会话。
3. **日常开户 / 角色调整 / 停用**：`POST /accounts`、`POST /accounts/{id}/roles`、
   `POST /accounts/{id}/deactivation` 都要求 administrator 有效令牌和授权理由；
   管理员不持有评估决定权，开户与审批职责分离。角色调整与停用采用
   `expected_role_version` 乐观版本守卫，同账号并发写由 `BEGIN IMMEDIATE` 串行化，
   版本号严格递增、只有一个结论生效；停用会立即撤销该账号全部会话。
4. **业务请求**：除 `/health`、`/bootstrap-status`、`/auth/login` 外，所有接口都要求
   `Authorization: Bearer <令牌>`；缺失、伪造、过期、撤销的凭据一律先返回 401，
   再谈请求体校验。
5. **可复核**：`GET /accounts`、`GET /accounts/{id}`（含逐版本角色历史与授权者）和
   `GET /authorization-events` 向具备审计权限的角色展示授权者、角色版本与每次拒绝的
   原因码；所有身份与授权状态都持久化在 SQLite，重启后权限与历史保持一致。

