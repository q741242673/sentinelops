# 更新记录

这个文件只记录已经进入版本候选的变化。开发过程和未合并计划仍以 GitHub PR 为准。

## 0.1.0-rc.1

首个公开的 Release Candidate，目标是验证 SentinelOps 的生产控制面和安全边界，而不是宣称已经
替代企业现有的事件平台。

主要能力：

- PostgreSQL 持久化事故、审批、操作意图、租约、审计链和外部锚点状态；
- 独立 Executor 执行 Kubernetes 写操作，并通过 fencing、幂等键和执行前检查防止重复写；
- Alertmanager、Prometheus、Loki、Tempo 和 Kubernetes 组成真实故障调查与恢复闭环；
- OIDC 人工审批、最小权限、HMAC 审计链、Ed25519 外部回执和锚点失效时 fail-closed；
- 双 API、双 Executor、多副本接管、进程崩溃、严格恢复验证和中文事故控制台；
- 确定性安全评估、真实模型只读评估、kind E2E、PostgreSQL 合同和持续故障压测。

升级与迁移：

- 数据库必须先运行 Alembic migration，当前 schema head 为
  `0008_anchor_unlock_workflow`；
- API、Executor、Migration Job 和 Anchor Publisher 必须使用同一镜像版本；
- 生产部署应把清单里的示例镜像替换为 RC 镜像的不可变 digest；
- 旧 SQLite 本地演示可以继续使用，但多副本生产模式必须使用 PostgreSQL。

已知边界：

- 前端仍定位为本地演示控制台，没有独立的生产部署和鉴权网关；
- 生产 OIDC、Secret、外部 Anchor、TLS 和长期存储需要接入企业现有服务；
- RC 首先验证 `linux/amd64`，暂不承诺多架构镜像；
- 远程模型评估单独手动运行，定时压测使用确定性 Provider，不产生模型费用；
- 当前 Release Candidate workflow 先生成候选制品和验收证据，不会自动发布 `latest`。
