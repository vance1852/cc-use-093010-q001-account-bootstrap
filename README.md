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

## 身份与权限（项目证据平台）

`cooperation_assurance` 的开户与评估接口一律要求已认证身份，不再接受自报身份：

- `POST /users/bootstrap`：首次初始化管理员，仅当没有在管管理员时可用；重复初始化不会覆盖已有人员；
- `POST /session`：口令登录，返回 8 小时有效的 Bearer 会话令牌；
- `POST /users`、`POST /users/{id}/role`、`POST /users/{id}/password`、`POST /users/{id}/deactivate`：日常开户、角色调整、口令重置与停用，仅管理员可用；角色调整需携带当前 `role_version`，版本冲突返回 409；
- `GET /users`、`GET /users/{id}`：账号目录，展示授权者（`authorized_by`）与角色版本（`role_version`），管理员与审计员可读；
- `GET /audit/access`：身份链审计，包含开户、角色调整、停用与全部访问拒绝原因，管理员与审计员可读；
- 其余业务接口一律要求 `Authorization: Bearer <token>`，缺失、过期或伪造的凭据返回 401 并记入审计。
