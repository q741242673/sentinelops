# SentinelOps

一个能处理 Kubernetes 微服务告警的 AI 事故响应 Agent。

[![持续集成](https://github.com/q741242673/sentinelops/actions/workflows/ci.yml/badge.svg)](https://github.com/q741242673/sentinelops/actions/workflows/ci.yml)

收到告警后，SentinelOps 不会马上让模型猜答案。它先去查 Kubernetes、监控指标、日志、调用链和代码变更，再根据查到的内容决定下一步：自动修复、等待人工批准，或者因为证据不足而停止操作。

> 当前版本已经在本地 kind 集群中跑通告警、调查、OIDC 人工审批、独立 Executor 修复、严格恢复验证和外部审计锚定，并支持 PostgreSQL 持久化、多副本接管和异常时停止写入。接入公司的生产集群前，仍需替换为企业身份、Secret 和审计服务，并按实际权限重新验收。

## 它解决什么问题

微服务报警后，值班人员通常要在多个系统之间来回切换：

- 去 Kubernetes 看 Pod 是否健康、最近有没有发布；
- 去 Prometheus 看错误率和请求量；
- 去 Loki 搜错误日志；
- 去 Tempo 找出错的调用链；
- 去 Git 核对最近改了什么；
- 最后再决定是重启、回滚，还是继续排查。

SentinelOps 把这套过程连在一起。大模型负责分析，但不能直接控制集群；能不能修改集群、要不要人工审批、修复后算不算恢复，最后都由后端程序判断。

## 一次告警是怎么处理的

```mermaid
flowchart LR
    A["Alertmanager 推送告警"] --> B["收集集群和监控证据"]
    B --> C["Agent 分析可能原因"]
    C --> D{"证据够不够"}
    D -->|"不够"| E["继续补查只读信息"]
    E --> C
    D -->|"仍然不够"| F["停止写操作，交给人工"]
    D -->|"足够"| G["生成修复方案"]
    G --> H{"操作风险高不高"}
    H -->|"需要审批"| I["等待值班人员确认"]
    H -->|"允许自动执行"| J["调用受限工具修复"]
    I --> J
    J --> K["重新检查 Pod、测试请求、错误率、告警和新调用链"]
    K --> L["生成事故报告"]
```

简单说，就是下面 8 步：

1. Alertmanager 把告警推给 SentinelOps。
2. SentinelOps 查询 Kubernetes、Prometheus、Loki、Tempo 和 Git。
3. 后端给每次成功查询生成证据编号，Agent 分析根因时必须引用这些编号。
4. 如果证据不够，只继续查询，不修改集群；达到设定的补查次数后仍不够，就停止并交给人工。
5. 如果证据足够，Agent 只能从提前允许的修复工具里选择动作。
6. 回滚、扩容等高风险操作必须由人批准；批准会绑定当时的 Deployment 和 revision 快照。
7. 真正写入前会重新读取集群。审批期间如果发布了新版本、修改了副本数、当前版本的就绪副本发生变化、删除了健康证明或读取失败，旧审批立即失效，不执行写操作。
8. 执行后重新检查 Pod、测试请求、错误率、告警和新调用链。只有这些检查都通过，事故才会被标记为已恢复。

## 整体结构

```mermaid
flowchart TB
    UI["React 事故控制台"] <-->|"接口请求 + 后端实时推送（SSE）"| API["FastAPI 后端"]
    AM["Prometheus / Alertmanager"] -->|"Webhook"| API
    API --> AGENT["LangGraph Agent"]
    AGENT --> READ["只读证据工具"]
    READ --> K8S["Kubernetes"]
    READ --> PROM["Prometheus"]
    READ --> LOKI["Loki"]
    READ --> TEMPO["Tempo"]
    READ --> GIT["Git 变更记录"]
    AGENT --> POLICY["风险检查和人工审批"]
    POLICY --> PREFLIGHT["执行前重新读取集群"]
    PREFLIGHT --> CATALOG["Action Plugin 合同"]
    CATALOG --> QUEUE["PostgreSQL Action Intent 队列"]
    QUEUE --> EXECUTOR["独立 Executor"]
    EXECUTOR --> CONTRACT["不可变 SentinelRemediation"]
    CONTRACT --> CONTROLLER["Go Remediation Controller"]
    CONTROLLER --> WRITE["带版本条件的集群操作"]
    CONTROLLER -->|"Executor 崩溃后只读对账"| EXECUTOR
    AGENT --> PROPOSAL["不可变变更提案"]
    PROPOSAL --> OUTBOX["PostgreSQL GitOps Outbox"]
    OUTBOX --> PUBLISHER["独立 GitOps Publisher"]
    PUBLISHER --> GATEWAY["公司 GitOps Gateway / 代码变更请求"]
    WRITE --> K8S
    K8S --> VERIFY["恢复检查"]
    PROM --> VERIFY
    TEMPO --> VERIFY
    VERIFY --> API
```

项目分成七块：

- **前端控制台**：用 React 和 TypeScript 编写，实时显示 Agent 正在做什么、查了哪些证据、为什么暂停、最终是否恢复。
- **后端服务**：用 FastAPI 接收告警、管理事故状态、处理审批，并通过 SSE（后端主动推送）把新进度立即发给网页。
- **Agent 核心**：用 LangGraph 安排调查和修复步骤。配置 PostgreSQL 后，等待审批的生产事故会同时保存事故快照和 Agent 暂停点；后端重启后可以使用原审批继续。Agent 只把批准后的操作放入数据库队列，不直接调用 Kubernetes 写接口。
- **独立 Executor**：单独进程领取 Action Intent，把批准后的动作和执行快照写成不可修改的 `SentinelRemediation`。生产环境中它只能创建和读取这类请求，不能修改 Deployment。
- **Remediation Controller**：独立的 Go Controller 是生产链路中唯一能修改目标 Deployment 的组件。它只执行注册动作，写入前重新检查 UID、resourceVersion、generation、当前 ReplicaSet、审批摘要和过期时间。
- **独立 GitOps Publisher**：只领取已经过边界检查并保存到数据库的动态提案，再交给公司 GitOps Gateway 创建代码变更请求。API、Agent 和 Executor 都不持有代码仓库写权限。
- **集群与监控环境**：本地使用 kind 运行微服务、Prometheus、Alertmanager、Loki、Tempo 和 OpenTelemetry Collector。

## 前端演示

项目自带一个本地前端。启动完整本地环境后，可以直接运行三种 Demo，查看告警发生后 Agent 查了什么、做了什么，以及最后有没有恢复：

| 场景 | 会发生什么 | 预期结果 |
|---|---|---|
| 人工审批 | 发布一个会让库存请求间歇性失败的新版本 | Agent 找到故障版本并提出回滚，停在审批页面等待人工确认 |
| 自动修复 | 在库存服务进程中打开一个重启即可清除的故障 | Agent 确认证据后自动滚动重启，并检查服务是否恢复 |
| 复杂调查 | 制造一个需要继续查日志、指标和代码变更的故障 | Agent 会继续补查；证据足够就给出方案，仍有冲突就停止写操作并交给人工 |

网页不是写死的动画。它通过 SSE 接收后端进度，会显示：

- 当前执行到哪个步骤；
- 调用了哪个查询工具；
- 找到了哪些证据；
- Agent 给出的根因和置信度；
- 是否进行了补查；
- 为什么需要人工审批；
- 实际执行了什么集群操作；
- 用什么结果证明服务已经恢复。

## 大模型能做什么，不能做什么

SentinelOps 给大模型加了几条硬限制：

1. **没有证据就不能下结论**：模型引用的证据必须对应后端实际执行成功的查询；编号不存在、查询失败或来源不一致都会被拒绝。
2. **证据不足就不写集群**：达到设定的补查次数后仍不确定，就交给人工处理。
3. **模型不能随便调用命令**：系统没有把 Shell 交给模型，只开放少量提前定义好的工具。
4. **模型不能给自己提权**：审批规则由服务端控制，告警标签和模型回答都不能改变权限。
5. **高风险操作必须有人确认**：回滚和扩容默认停在人工审批门；每次审批都有独立编号和版本，只能使用一次。重复、冲突、过期或旧版本的决定都会被拒绝。
6. **模型不能宣布自己修好了**：恢复结果由 Pod 状态、测试请求、错误率、告警和新调用链一起判断。
7. **模型不能修改无关服务**：重启、回滚和扩缩容默认只能作用于当前告警对应的服务和 namespace，参数不合法时会在调用 Kubernetes 前被拒绝；回滚目标还必须带有服务端认可的明确健康标记。
8. **旧审批不能覆盖新状态**：批准后会重新查询 rollout history。新版本发布、副本配置变化，或同一版本的副本数、就绪副本数发生变化，都会让旧审批失效；通过后写操作仍会再次检查当前状态，并携带最新 resourceVersion，防止校验与写入之间的并发覆盖。
9. **MCP 只能读取证据**：MCP Server 不公开重启、回滚和扩缩容。所有集群写入必须经过 IncidentAgent 的规划、审批和执行前复查；普通工具入口也会拒绝写操作。
10. **写操作有持久身份**：配置数据库后，每个集群写操作会先保存不可变的 Action Intent，再生成同名的 `SentinelRemediation`。Controller 会把 action ID 写进 Deployment；Controller 在 API Server 接受写入后崩溃，也能依据这个标记恢复结果而不重复执行。
11. **重复告警只能创建一个事故**：多 API 副本通过 PostgreSQL 原子认领 `Alertmanager 来源 + fingerprint + startsAt`。resolved 后保留记录，迟到的旧 firing 不会重新开事故，上一轮 resolved 也不能关闭下一轮告警。
12. **外部请求不能伪造告警**：生产环境拒绝匿名 Webhook。原生 Alertmanager 可以使用 Bearer Token；经过签名网关时也可以使用覆盖时间戳和原始请求体的 HMAC-SHA256。重复认证头、过期签名、压缩体和超大请求都会在解析告警前被拒绝。
13. **Controller 只执行注册动作**：写操作必须有对应的 Action Plugin。插件由服务端声明参数、最低风险、目标字段、审批方式、恢复验证方式和执行快照要求；只在提示词里出现、临时加入工具白名单或缺少完整快照的动作都不能进入 Kubernetes 后端。

## 快速运行：不需要 Kubernetes 和模型 Key

适合先确认项目能跑起来。

第一次使用先下载仓库：

```bash
git clone https://github.com/q741242673/sentinelops.git
cd sentinelops
```

命令行演示只需要 Python 3.11+：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
sentinelops demo --scenario bad_rollout --approve
```

这条命令使用本地模拟数据，不会连接 Kubernetes，也不会调用收费模型。流程仍会先停在审批节点；`--approve` 会模拟值班人员点击同意，然后继续执行模拟回滚并输出事故报告。

启动本地网页：

```bash
make console
```

网页还需要 Node.js 22+。第一次运行时，脚本会自动安装 `web` 目录的前端依赖。不带额外配置时，后端使用模拟工具和固定规则，不会连接 Kubernetes 或收费模型。

打开 <http://127.0.0.1:5173>。

## 完整运行：kind + 监控系统 + 大模型

要求：

- Python 3.11+
- Node.js 22+
- Docker
- kind
- kubectl
- 一个兼容 OpenAI 请求格式的模型服务，以及它的地址、模型名称和 API Key

启动：

```bash
SENTINELOPS_MODEL_PROVIDER=openai_compatible \
SENTINELOPS_MODEL_NAME=deepseek-v4-flash \
SENTINELOPS_MODEL_BASE_URL=https://api.deepseek.com \
SENTINELOPS_MODEL_API_KEY=replace-me \
make console-live
```

脚本会自动完成这些事情：

1. 创建或复用本地 kind 集群；
2. 部署订单服务和库存服务；
3. 部署 Prometheus、Alertmanager、Loki、Tempo 和 OpenTelemetry Collector；
4. 启动持续测试流量；
5. 启动 FastAPI 后端和 React 前端。

打开 <http://127.0.0.1:5173>，选择一个场景开始即可。

停止网页后，默认保留 kind 集群，方便下次快速启动。彻底删除环境：

```bash
make console-live-down
```

## 更换模型

Agent 不绑定某一家模型供应商。模型服务的请求格式需要兼容 OpenAI 的 `/chat/completions` 接口，并能按照要求返回 JSON；DeepSeek、OpenAI、vLLM 或其他满足这个条件的服务都可以接入。

如果单独运行后端，可以把模型配置保存到 `.env`：

```bash
cp .env.example .env
```

填写：

```dotenv
SENTINELOPS_MODEL_PROVIDER=openai_compatible
SENTINELOPS_MODEL_NAME=your-model-name
SENTINELOPS_MODEL_BASE_URL=https://api.example.com/v1
SENTINELOPS_MODEL_API_KEY=replace-me
SENTINELOPS_MODEL_TIMEOUT_SECONDS=60
SENTINELOPS_MODEL_MAX_TOKENS=4096
```

运行 `make console-live` 时，请像上一节那样在命令前传入这四个变量；这样无论换哪一家服务，启动脚本都不会猜测你想用哪个模型。

远程模型的单次输出默认限制为 4096 Token，可以通过
`SENTINELOPS_MODEL_MAX_TOKENS` 调整到 256–32768。模型偶尔返回空内容时，Provider 会再请求一次；
第二次仍为空就安全失败，不会把空结果交给 Agent。

`rule_based` 是给本地离线测试和 CI 使用的固定规则实现，不应该当作生产环境里的大模型。

## 连接已有 Kubernetes 集群

本地运行时读取当前 kubeconfig；部署到 Pod 中时使用 ServiceAccount。

```dotenv
SENTINELOPS_TOOL_BACKEND=kubernetes
SENTINELOPS_KUBERNETES_NAMESPACE=sentinelops-demo
```

示例 RBAC：

```bash
kubectl apply -f deploy/rbac.yaml
```

这份 `deploy/rbac.yaml` 是本地开发时的直连示例：`sentinelops-agent` 只能读取 Pod、事件、日志和发布历史，
`sentinelops-executor` 可以调用受保护的写工具。生产清单使用更严格的 Controller 模式：Executor 只能创建和
查看不可变的 `SentinelRemediation`，只有 Go Controller 能修改 Deployment。模型本身拿不到任意 Shell、
Secret、写权限或特权 Pod 权限。

故障注入和环境重置接口默认不开放。`make console` 和 `make console-live` 会在本地脚本里显式开启；如果单独启动后端，只有隔离的演示环境才应设置 `SENTINELOPS_DEMO_ENABLED=true`，并且 Kubernetes namespace 必须与 `SENTINELOPS_DEMO_NAMESPACE` 完全一致。生产环境即使误开开关也会拒绝这些写入。

如果把 SentinelOps 作为 MCP Server 接给其他 Agent，它只会公开 Kubernetes、Prometheus、Loki 和 Tempo 的只读证据查询：

```bash
python -m pip install -e ".[mcp]"
sentinelops-mcp
```

MCP 不直接公开滚动重启、回滚或扩缩容。修复动作必须进入 SentinelOps 的事故流程，由服务端完成证据检查、风险审批和 fresh preflight 后才能调用 Kubernetes。

## Action Plugin：如何安全增加一种修复能力

SentinelOps 并不试图自动解决所有 Kubernetes 故障。生产 Controller 只执行服务端 Action Catalog 中已经注册的动作。目前注册了滚动重启、精确版本回滚和限定范围扩缩容。

一个新动作不能只加一段提示词或一个 Kubernetes 调用。它必须同时声明：

- 模型允许填写哪些参数，以及哪个参数是事故目标；
- 不能低报的最低风险；
- 是否必须人工审批；
- 是否可逆、是否具有破坏性；
- 执行前必须绑定哪些 Deployment 和 revision 快照；
- 执行后使用哪套恢复验证规则。

Agent 规划、审批前检查、写入前检查和独立 Executor 会读取同一份合同。动作没有注册、被禁用、目标不属于当前事故、参数被替换或快照字段不完整时，都会在调用 Kubernetes 之前停止。这样可以逐步增加修复覆盖面，但不会因为给模型开放任意 Shell 而失去安全边界。

## 集群内执行合同：SentinelRemediation

`deploy/production/crds/sentinelremediations.yaml` 定义了集群内 Controller 使用的 `SentinelRemediation` CRD。它不是一段让模型自由填写的 YAML，而是服务端从已经落库的 Action Intent 生成的一次性执行合同：

- 资源名必须等于 Action Intent 的 SHA-256 幂等摘要；
- `spec` 创建后不可修改，动作、目标、执行前快照、授权决定和 fence generation 会一起冻结；
- 动作只能来自当前 Action Plugin 目录，参数必须匹配重启、回滚或扩缩容合同；
- 目标固定到 Deployment 名称和 UID，前置快照固定到 resourceVersion、generation、当前 revision 和 ReplicaSet；
- 人工审批必须携带审批身份、版本和摘要，自动策略决定不能伪装成人工审批；
- Go Controller 只能通过独立的 `/status` 子资源写回执行阶段、前后 resourceVersion 和结果摘要；
- 成功、失败、拒绝、过期和取消等终态不能被改写，observed generation 也不能倒退。

`controller/` 已经实现独立的 Go Controller。它不会执行模型临时生成的命令，只认识重启、精确版本回滚和限定范围扩缩容三种注册动作。真正写 Deployment 前，它会再次核对目标 UID、resourceVersion、generation、当前 ReplicaSet、动作目录摘要、审批绑定和过期时间；任何一项变化都会把旧请求标成 `Stale` 或 `Rejected`。

写入时使用 Kubernetes 自带的 resourceVersion 冲突检查，并把 action ID、动作类型和 fence generation 一起写到 Deployment。即使 API Server 已经接受修改后 Controller 立刻崩溃，重启后的新副本也会从这个标记恢复结果，不会再次触发同一个动作。两个副本通过 Lease 选主，只有 leader 处理写入。

Executor 自己在提交合同后崩溃也不会丢掉已知结果。每个跨过写入分界的 Action Intent 都会同时进入一个数据库对账队列；替代 Executor 要先领取带 generation 的对账租约，然后只读取同名 `SentinelRemediation`，不会在恢复流程中补建缺失合同。只有 CR 的完整 `spec`、UID、generation、Controller 身份、Executed 条件和结果摘要都能与原 Action Intent 对上，数据库才会把 `dispatched/unknown` 收口为 `succeeded/failed`。CR 不存在、仍在执行、结构异常或不能证明是否写入时都会保持未知并继续交给人工。

在线等待会绑定创建时返回的 CR UID，发现同名资源被替换就停止；进程崩溃后的恢复无法和 Kubernetes 创建动作做跨系统原子提交，因此还依赖生产 RBAC 禁止 Executor 删除或修改 CR。若集群管理员可以删除后按相同 spec 重建同名 CR，需要再用准入策略和集群审计约束这类高权限操作，不能把公开摘要当成签名。

这里的 `Succeeded` 只表示“注册动作已被 Kubernetes 接受且结果可追踪”，不表示业务已经恢复。是否恢复仍由 Agent 的严格验证阶段根据主动请求、Prometheus、Alertmanager 和新 Trace 决定。

生产执行链已经切换完成：Executor 领取数据库中的 Action Intent 后，只创建和读取
`SentinelRemediation`；它的生产 RBAC 不再包含 Deployment 写权限。Go Controller 是生产清单中唯一的
Deployment 写入者。仓库中的本地开发模式仍可选择直连后端，方便离线测试，但生产启动门禁会拒绝这种配置。

真实 kind 闭环可以单独运行：

```bash
scripts/e2e-remediation-controller.sh
```

这项测试会使用真正的 Executor ServiceAccount 短期 Token 创建合同，等待 Controller 修改真实 Deployment，
再模拟 Executor 在回写数据库前崩溃，由替代 Executor 只读恢复 Controller 结果；最后由 API Server 证明
Executor 身份可以创建合同，但不能修改合同或 Deployment。

本地或生产集群需要先安装 CRD：

```bash
kubectl apply -f deploy/production/crds/sentinelremediations.yaml
```

`scripts/e2e-remediation-contract.sh` 会在真实 Kubernetes API Server 的临时隔离 namespace 中验证：合法合同可以创建、`spec` 篡改会被拒绝、已经写入的终态不能反向修改。普通 YAML 解析无法覆盖这些 CEL 规则，所以这项检查也被接入了 kind E2E。

Controller 自身可以单独检查：

```bash
cd controller
go test -race ./...
docker build -t sentinelops-remediation-controller:local .
```

## 动态变更提案：复杂故障走 GitOps，不让模型直接改集群

当标准 Action Plugin 无法处理故障，而且事故已经停止自动写入时，可以创建一个动态变更预览：

```bash
curl -X POST \
  http://localhost:8000/api/v1/incidents/INCIDENT_ID/change-proposals/preview \
  -H 'Content-Type: application/json' \
  -d '{
    "rationale": "人工调查确认需要提高 CPU request 并延长 readiness timeout",
    "operations": [
      {
        "field": "container.resources.requests.cpu",
        "container": "order-service",
        "value": "250m"
      },
      {
        "field": "container.readinessProbe.timeoutSeconds",
        "container": "order-service",
        "value": 3
      }
    ]
  }'
```

这一步只返回绑定当前 Deployment UID、resourceVersion、generation 和容器镜像的 diff、提案摘要哈希，以及后续可使用的 Strategic Merge Patch。响应固定带有 `executable=false`，不会创建 Action Intent，也不会调用 Kubernetes 写接口。

当前只允许调整已有容器的 CPU/内存 request、limit，以及已有 readiness/liveness probe 的少量数字参数。接口不接受任意 YAML 路径、Shell、`kubectl`、镜像、环境变量、Secret、RBAC、特权容器和删除操作；资源值还有 CPU、内存及 request/limit 关系上限。事故仍在自动处理、目标 namespace 不一致、容器不存在、修改无变化或快照读取失败时都会拒绝。

确认预览后，向不带 `/preview` 的地址提交同一份请求：

```bash
curl -X POST \
  http://localhost:8000/api/v1/incidents/INCIDENT_ID/change-proposals \
  -H 'Content-Type: application/json' \
  -d @proposal.json
```

服务端不会相信浏览器之前拿到的预览，而是重新读取 Deployment 并重新生成提案。提案正文、目标快照和 SHA-256 摘要会作为一份不可变记录，与 GitOps Outbox 和审计事件在同一个数据库事务中提交；重复提交同一份内容会返回同一个提案，不会创建两份代码变更。

独立进程 `sentinelops gitops-publisher` 使用短租约领取 Outbox。只有这个进程能读取 GitOps Token，它把固定格式的 patch 发给公司 GitOps Gateway，并要求 Gateway 返回同时绑定 `proposal_id` 和 `proposal_digest` 的代码变更地址与 commit revision。网络失败会有上限地退避重试；格式错误、摘要不一致或过期提案进入失败状态，不能伪装成已发布。

```dotenv
SENTINELOPS_GITOPS_GATEWAY_URL=https://gitops-gateway.example/v1/proposals
SENTINELOPS_GITOPS_BEARER_TOKEN_FILE=/var/run/secrets/sentinelops/gitops-token
```

Gateway 才负责使用 GitHub App、GitLab Project Token 或公司内部机器人创建分支和 PR/MR。SentinelOps API、Agent、Executor 都不需要仓库写凭据；GitOps 合并和实际部署仍由现有 CODEOWNERS、CI、策略检查和发布系统决定。这里实现的是可靠的提案提交通道，不是让大模型绕过评审直接应用 YAML。

仓库还带了一个可以直接运行的参考 GitHub Gateway。它会使用固定仓库、固定基础分支和固定目录，创建 `sentinelops/proposal-<proposal_id>` 分支，把完整提案保存为 JSON，然后创建 Draft PR。请求不能指定仓库、分支或文件路径；Gateway 也会重新计算摘要、检查有效期，并确认分支里只有这一份提案文件。相同提案重复投递会返回原来的 PR，不会反复建分支。

先准备两个互相独立的配置文件和 Secret：

```bash
mkdir -p .local/secrets
cp config/gitops-gateway.env.example .local/gitops-gateway.env
cp config/gitops-publisher.env.example .local/gitops-publisher.env
openssl rand -hex 32 > .local/secrets/gitops-token
```

把 GitHub App 的短期 installation token，或只对目标配置仓库生效的 fine-grained token，单独写入 `.local/secrets/gitops-github-token`。需要的仓库权限只有 Metadata 只读、Contents 读写和 Pull requests 读写。不要使用个人全仓库 Token，也不要把 GitHub Token 放进 Publisher 的配置文件。

修改 `.local/gitops-gateway.env` 里的目标仓库后启动：

```bash
sentinelops gitops-gateway \
  --env-file .local/gitops-gateway.env \
  --host 127.0.0.1 \
  --port 8020
```

另一个终端启动 Publisher：

```bash
sentinelops gitops-publisher \
  --env-file .local/gitops-publisher.env
```

参考 Gateway 只负责创建“提案 PR”，不会猜测每家公司配置仓库的目录结构，也不会直接改业务 Deployment YAML。实际公司接入时，可以让现有 GitOps Bot 读取提案 JSON 并生成对应配置变更，或者替换成公司自己的 Gateway。`deploy/gitops-gateway/reference.yaml` 提供了无 Kubernetes Token、只读根文件系统和只允许 Publisher 入站的部署参考；生产环境还需要在它前面接 TLS 或服务网格。

生产 OIDC 需要单独授予 `sentinelops.incident.propose`。该权限可以预览并提交受限提案，但不能批准标准修复、直接修改集群或合并代码变更。

## Kubernetes 生产部署基线

`deploy/production` 提供了一套可以按公司环境改造的控制面清单。它和本地 kind Demo 分开，不会改变 `make console-live` 的运行方式。

这套清单会：

- 在 `sentinelops-system` 运行两个 API、两个独立 Executor、两个 Remediation Controller、两个 GitOps Publisher 和两个审计锚定 Publisher；
- 让 API 使用只读 ServiceAccount；Executor 只能创建和查看不可变的 `SentinelRemediation`，没有 Deployment 写权限；
- 让 Controller 只读取 `SentinelRemediation` 和 ReplicaSet，只更新目标 Deployment 与执行状态，并使用 namespace 内 Lease 选主；
- 让 GitOps 与锚定 Publisher 都不挂载 Kubernetes Token，分别只访问数据库及自己的外部服务；
- 使用单独的数据库迁移 Job，迁移进程拿不到 Kubernetes 凭据；
- 把数据库地址、模型 Key、Webhook Token、审计 Key 和锚定 Token 作为只读 Secret 文件挂载；
- 使用非 root 用户、只读根文件系统、默认 seccomp、资源限制和最小 Linux capabilities；
- 为 API 配置 `/health`、`/ready`，为 Executor 配置本地心跳探针；
- 使用 PDB 和节点拓扑分散，减少维护节点时同时中断所有副本的风险；
- 默认拒绝访问 Executor，并只允许明确标记过的 namespace 访问 API 端口。

先安装集群级 CRD：

```bash
kubectl apply -f deploy/production/crds/sentinelremediations.yaml
```

再把下面这些示例值改成实际环境：

- `ghcr.io/your-org/sentinelops:0.1.0-rc.1`：替换为已经构建并最好固定到 digest 的镜像；
- `ghcr.io/your-org/sentinelops-remediation-controller:0.1.0-rc.1`：替换为 Controller 镜像并固定到 digest；
- `sentinelops-workloads`：替换为被管理服务所在的 namespace；
- `prod-cluster-a`：替换为这一套 Alertmanager 的稳定唯一标识；
- `https://replace-with-independent-audit-sink.example/v1/anchors`：替换为独立审计服务的 HTTPS 地址；
- ConfigMap 中的模型、Prometheus、Loki、Tempo 和主动探针地址。

先创建控制面基础资源：

```bash
kubectl apply -f deploy/production/base/prerequisites.yaml
```

Secret 不在仓库中提供模板，避免占位密码被误部署。把下面七个值分别保存成只包含一行内容的本地文件，再创建 Secret：

```bash
kubectl -n sentinelops-system create secret generic sentinelops-runtime \
  --from-file=database-url=./secrets/database-url \
  --from-file=audit-hmac-key=./secrets/audit-hmac-key \
  --from-file=audit-anchor-token=./secrets/audit-anchor-token \
  --from-file=audit-anchor-reconcile-token=./secrets/audit-anchor-reconcile-token \
  --from-file=gitops-token=./secrets/gitops-token \
  --from-file=webhook-bearer-token=./secrets/webhook-bearer-token \
  --from-file=model-api-key=./secrets/model-api-key
```

正式环境应由 External Secrets、Secrets Store CSI Driver 或公司的 Secret 平台创建同名 Secret，不要把这些文件提交到 Git。

然后把目标 namespace 的 Role 和 RoleBinding 改成实际名称并应用：

```bash
kubectl apply -f deploy/production/access/workload-rbac.yaml
```

数据库迁移必须先完成，不能把 Job 和 Deployment 一次性无序 `apply`。升级到包含
`0010_action_reconciliation_outbox` 的版本前，必须先把旧版本 Executor 缩容到 0，并确认没有仍在
执行的 Action Intent；旧 Executor 不会写入新对账表，若让它和迁移并发运行会产生无法自动恢复的
遗漏。PostgreSQL 迁移还会在回填和孤儿检查期间锁住 Action Intent 表，但这不能代替停止旧进程：

```bash
kubectl -n sentinelops-system scale deployment/sentinelops-executor --replicas=0
kubectl -n sentinelops-system delete job sentinelops-db-migrate --ignore-not-found
kubectl apply -f deploy/production/base/migration-job.yaml
kubectl -n sentinelops-system wait \
  --for=condition=complete job/sentinelops-db-migrate \
  --timeout=10m
```

迁移完成后再发布新版本服务（新 Executor Deployment 会恢复清单中声明的副本数）：

```bash
kubectl apply \
  -f deploy/production/base/remediation-controller-rbac.yaml \
  -f deploy/production/base/api.yaml \
  -f deploy/production/base/executor.yaml \
  -f deploy/production/base/remediation-controller.yaml \
  -f deploy/production/base/gitops-publisher.yaml \
  -f deploy/production/base/anchor-publisher.yaml \
  -f deploy/production/base/availability.yaml \
  -f deploy/production/base/network-policy.yaml
```

Alertmanager 或 Ingress 所在 namespace 需要显式获得 API 入口权限：

```bash
kubectl label namespace monitoring sentinelops.io/api-access=true
```

如果集群安装了 Prometheus Operator，可以再应用审计锚定监控：

```bash
kubectl label namespace monitoring sentinelops.io/metrics-access=true
kubectl apply \
  -f deploy/production/monitoring/audit-anchor-monitoring.yaml
```

这会每 15 秒读取 API 的 `/metrics`，监控待投递、dead letter、最老积压、最近送达时间、最近对账时间和持久化写闸门。两个 API 副本读取的是同一份数据库状态，因此告警规则统一使用 `max()`，不会把同一份积压重复相加。`PrometheusRule` 和 `ServiceMonitor` 依赖 Prometheus Operator CRD；没有安装时不要应用这份可选清单。

`/ready` 证明 API 已经启动且可以访问事故数据库，不代表模型、监控系统和 Kubernetes 里的目标服务都健康。Executor 和锚定 Publisher 的探针证明各自的领取循环仍在前进；如果进程卡住，心跳过期后 Pod 会退出 Ready 并由 Kubernetes 重启。外部审计服务临时不可用只会让 Outbox 保留待重试记录，不会回滚已经提交的事故处理。

示例 NetworkPolicy 只提交了可以跨环境成立的入站限制。Kubernetes API、PostgreSQL、监控系统、模型网关和外部审计服务的地址在不同公司并不一样，因此没有硬编码一套可能切断生产流量的通用 egress 规则。上线前应根据实际 Service、egress gateway 或 CIDR 再补出口白名单，并在策略启用后分别验证数据库、集群 API、监控、模型和锚定调用。

## 可校验的审计证据链

事故 timeline 主要服务前端展示，不等于权威审计记录。SentinelOps 另外维护每个事故独立的审计链，审批和 Action Intent 状态变化会与业务数据在同一个数据库事务中提交。审计写入失败时，批准或集群写任务也会一起回滚。

当前会记录：

- 事故 snapshot 和 Agent 时间线事件；
- 审批批准、拒绝和自动过期；
- Action Intent 的 prepared、queued、claimed 和 dispatched；
- Executor 的 succeeded、failed、unknown、cancelled 和过期回收；
- Executor owner、generation、attempt ID，以及结果和人工备注的摘要哈希。

每条记录包含连续序号、前一条记录的哈希、规范化 JSON 的 SHA-256，以及使用独立 Audit Key 计算的 HMAC-SHA256。生产 API 和 Executor 没有配置至少 32 字节的 Audit Key 与稳定 Key ID 时会拒绝运行：

```dotenv
SENTINELOPS_AUDIT_HMAC_KEY_FILE=/var/run/secrets/sentinelops/audit-hmac-key
SENTINELOPS_AUDIT_KEY_ID=prod-audit-v1
```

不要复用模型 Key、数据库密码或 Alertmanager Webhook Token。审计 Key 属于长期验证材料；当前版本还没有完成无中断密钥轮换，因此不要直接删除仍被历史记录引用的旧 Key。

离线校验指定事故：

```bash
sentinelops audit-verify --incident-id INCIDENT_ID
```

校验会检查事件内容、顺序、前序哈希、链头和 HMAC；发现修改、中间删除、尾部删除或错误密钥时返回非零状态。`0004_audit_chain` 迁移会为旧事故写入一条 `legacy.migration_checkpoint`，只证明“迁移当时数据库是什么状态”，不会假装过去不存在的审批和执行事件已经被可信记录。

每次追加审计事件时，SentinelOps 还会在同一个数据库事务里写入一条待投递的锚点。独立进程按事故顺序领取这些记录，重新校验本地整条链和对应事件，再把最小链头摘要发到外部：

```dotenv
SENTINELOPS_AUDIT_ANCHOR_URL=https://audit.example.com/v1/anchors
SENTINELOPS_AUDIT_ANCHOR_INVENTORY_URL=https://audit.example.com/v1/anchor-inventory
SENTINELOPS_AUDIT_ANCHOR_SOURCE_ID=prod-cluster-a
SENTINELOPS_AUDIT_ANCHOR_BEARER_TOKEN_FILE=/var/run/secrets/sentinelops/audit-anchor-token
SENTINELOPS_AUDIT_ANCHOR_RECONCILE_BEARER_TOKEN_FILE=/var/run/secrets/sentinelops/audit-anchor-reconcile-token
SENTINELOPS_AUDIT_ANCHOR_TRUSTED_RECEIVER_ID=company-audit-ledger
SENTINELOPS_AUDIT_ANCHOR_RECEIPT_PUBLIC_KEYS_FILE=/etc/sentinelops-anchor/receipt-public-keys.json
```

```bash
sentinelops anchor-publisher
```

投递采用确定性的 `anchor_id` 和同值 `Idempotency-Key`，因此接收端落盘后客户端即使超时，也可以安全重试。SentinelOps 不会把事故正文、日志或审批备注发出去，只发送 source、事故 ID、sequence、链头 hash、HMAC tag、Key ID 和前一锚点 ID。只有 `200/201`、JSON 类型、所有字段原样回显、请求摘要一致，并且 Ed25519 签名能被预配置公钥验证时才会记为送达；`202`、重定向、空响应、未知 Key 和字段不一致都不会被误当成成功。

外部接收端不是普通 Webhook，至少要做到：

- 以 `source_id + incident_id` 为一条只增不减的记录流；
- 相同 sequence 和 hash 返回同一 receipt，方便幂等重试；
- 相同 sequence 但 hash 不同、sequence 倒退或前一锚点不匹配时拒绝写入；
- 使用独立权限的追加式 SIEM、WORM/Object Lock 存储或专用审计服务保存记录；
- 锚定 Token 与 Audit HMAC Key、Webhook Secret 完全分开。

Publisher 还会定期读取接收端签名的完整链头清单，并和本地 Audit Head、Outbox 与已送达 receipt 反向核对。每次请求都会生成新的随机 challenge，接收端把 challenge 和生成时间一起写进 Ed25519 签名；旧清单即使被重放，也无法通过本次请求的校验。发现远端 sequence 高于本地、相同 sequence 的 hash 不同、已送达远端流消失，或远端存在但本地整条事故被删除时，会把数据库安全状态粘滞地改为 `integrity_blocked`。Executor 在真正派发 Kubernetes 写操作前会在同一事务检查这道闸门；锁定后仍可调查和查看证据，但不会继续自动修改集群。

第一次对账完成前写闸门保持关闭。短暂网络故障在最近一次成功对账仍处于 freshness 时间内只会标记 `degraded`；超过期限后也会停止新写操作。完整性锁不能靠下一次正常扫描自动解除，必须人工核对后处理。

代码还提供独立的严格核验：本地和远端事故集合及每个链头必须完全相同，Outbox 不能有 pending、claimed 或 dead letter，并且核验前后的本地快照哈希必须一致。它只会产生一次核验凭据，不会直接打开安全闸门，留给后续接入企业身份和双人审批的解锁流程使用。

仓库包含一个只用于本地验证协议的参考接收端。它必须使用与 SentinelOps 主库不同的数据库：

```bash
mkdir -p .local
python scripts/generate_anchor_keys.py \
  --key-id local-anchor-v1 \
  --private-key .local/anchor-private.pem \
  --public-keyring .local/anchor-public-keys.json

SENTINELOPS_ANCHOR_SERVICE_DATABASE_URL=sqlite+aiosqlite:///./anchor-ledger.db \
SENTINELOPS_ANCHOR_SERVICE_BEARER_TOKEN=replace-with-32-random-bytes \
SENTINELOPS_ANCHOR_SERVICE_INVENTORY_BEARER_TOKEN=replace-with-another-token \
SENTINELOPS_ANCHOR_SERVICE_SIGNING_PRIVATE_KEY_FILE=.local/anchor-private.pem \
SENTINELOPS_ANCHOR_SERVICE_SIGNING_KEY_ID=local-anchor-v1 \
sentinelops anchor-service
```

参考服务会拒绝 sequence 倒退、跳号、分叉和错误 predecessor；完全相同的重试返回第一次保存的同一份 receipt 和签名。生产环境应把它替换为独立权限的 PostgreSQL 审计服务、SIEM 或 WORM/Object Lock 存储，SQLite 示例不能当成不可篡改设施。写入 Token 和只读对账 Token 应使用不同权限。

`0005_audit_anchor_outbox` 会为已有事故的当前链头建立一个迁移检查点，而不是补造所有历史锚点；`0006_audit_anchor_security_gate` 增加持久化安全闸门；`0007_audit_anchor_observability` 为积压年龄查询增加组合索引；`0008_anchor_unlock_workflow` 保存双人解锁申请、追加式决策记录和审计清单代次；`0009_gitops_proposal_outbox` 保存不可变动态提案及其独立发布队列；`0010_action_reconciliation_outbox` 为跨过写入分界的操作保存带租约的 Controller 结果对账任务。

这里准确的说法是“篡改可检测，并可把已投递链头锚定到外部”，不是绝对不可篡改：

- HMAC 可以阻止只有数据库写权限、没有 Audit Key 的人静默重算记录；
- 如果攻击者同时控制 API/Executor 和 Audit Key，应用内校验无法独立证明真实性；
- 已成功投递的链头可以拿外部 receipt 对照；尚未投递的尾部仍有暴露窗口；
- 签名清单和反向对账可以发现一侧已锚定记录被删除；如果本地和外部存储被同时控制或同时删除，仍需要 WORM、Object Lock 或第三方透明日志；
- Ed25519 支持多个受信公钥，但当前不会自动分发新公钥。轮换必须先把新公钥加入所有 Publisher，再切换 Receiver 私钥，并保留验证历史 receipt 所需的旧公钥。

生产 API 必须配置企业 OIDC。SentinelOps 固定校验 issuer、audience 和 JWKS URL，只接受 RS256/ES256，要求 `exp`、`iat`、`iss`、`sub`，并拒绝 JWT Header 自带的 `jku/x5u`。能够审批的 Token 还必须带专用权限和可信的 `sentinelops_actor_type=human`，所以服务账号即使拿到同名角色也不能冒充人工审批。审计记录只保存 `SHA256(issuer + sub)` 的稳定标识，不保存原始 Token：

```dotenv
SENTINELOPS_OPERATOR_AUTH_MODE=oidc
SENTINELOPS_OIDC_ISSUER=https://identity.example.com
SENTINELOPS_OIDC_AUDIENCE=sentinelops-api
SENTINELOPS_OIDC_JWKS_URL=https://identity.example.com/.well-known/jwks.json
```

默认权限分别为 `sentinelops.incident.view`、`sentinelops.incident.create`、`sentinelops.incident.propose`、`sentinelops.incident.approve`、`sentinelops.anchor-unlock.request`、`sentinelops.anchor-unlock.approve` 和 `sentinelops.demo.operate`。生产环境关闭 OIDC、使用 HTTP issuer/JWKS，或缺少固定 audience 时会拒绝启动。Alertmanager Webhook 仍使用自己的 Bearer/HMAC 认证，不接受用户 OIDC Token 替代。本地演示可以保持 `SENTINELOPS_OPERATOR_AUTH_MODE=disabled`，此时审计身份会明确标记为 `unverified`，并且不能调用安全闸门解锁接口。

外部审计出现分叉后，解锁申请必须绑定当前 `integrity_blocked` 代次、变更单和有效期。申请人与批准人必须是两个不同的 OIDC 人类身份，两个角色使用不同权限；原始变更单、说明和审批备注只保存摘要。第二人批准后状态只会进入 `unlock_pending`，`write_blocked` 仍然为真，普通健康对账也不能开闸。

独立 Anchor Publisher 随后领取带 fencing generation 的短租约。领取动作本身也会进入 HMAC 审计链和 Outbox，因此只有申请、批准和领取记录都已送达外部账本后，新 challenge 的签名全量清单才可能通过严格对账。严格对账会核对完整 stream 集合、每条链的最新 head、本地链完整性、Outbox 已清空，并绑定数据库里的 inventory revision。最终事务要求安全代次、申请版本、租约 generation、租约时间和 inventory revision 全部未变，再用 CAS 把状态改成 `healthy`；期间多出任何审计或 Outbox 变化都会整笔回滚。审批接口本身永远不直接解除写封锁，也没有 force-unlock。

如果希望 Agent 自动提出回滚，发布流水线需要先完成就绪检查，再给这一次发布对应的 ReplicaSet 写入健康证明：

```bash
python3 scripts/attest_revision_health.py \
  --namespace sentinelops-demo \
  --deployment order-service \
  --verifier production-release-pipeline
```

证明会绑定 Deployment UID、ReplicaSet UID、revision、Pod 模板哈希、镜像引用、实际运行的镜像 ID、Git commit 和验证时间。它只写在这个 ReplicaSet 自己的 metadata 上，不会跟着 Deployment 模板传播到未来版本。证明缺失、被复制、字段不完整或与当前 revision 不一致时都会被当成未知状态，Agent 不会自动回滚到它。

生产环境建议使用不可变镜像 digest，并让独立的发布验证身份拥有写证明权限；Agent 自己只读这些证明。示例 RBAC 仍然没有给 Agent 修改 ReplicaSet 的权限。这里的可信边界是 Kubernetes 的 RBAC 和审计日志，并不是独立的数字签名；如果多个不可信主体都能修改 ReplicaSet annotation，应再接外部签名或准入控制，不能只依赖这组注解。

## 配置监控和代码变更证据

```dotenv
SENTINELOPS_PROMETHEUS_URL=http://127.0.0.1:9090
SENTINELOPS_LOKI_URL=http://127.0.0.1:3100
SENTINELOPS_TEMPO_URL=http://127.0.0.1:3200
SENTINELOPS_CHANGE_REPOSITORY_PATH=/absolute/path/to/sentinelops
SENTINELOPS_DIAGNOSIS_CONFIDENCE_THRESHOLD=0.8
SENTINELOPS_MAX_REFLECTION_ROUNDS=1
```

`SENTINELOPS_MAX_REFLECTION_ROUNDS` 控制最多补查几轮，默认是 1，可设置为 0～3。所有查询都有数量和时间范围限制。模型只能选择“还想查哪一类证据”，不能自己提交 Shell、文件路径、PromQL 或 LogQL 让系统直接执行。

演示环境会把 Git commit 写进 Kubernetes Deployment 的注解。后端读取当前版本和上一个版本的注解，再到配置好的仓库中核对这次提交改了什么，因此不会只凭告警文字猜测代码变更。

## 单独运行后端

如果希望事故和审批在后端重启后仍然存在，先配置 PostgreSQL：

```dotenv
SENTINELOPS_DATABASE_URL=postgresql+asyncpg://sentinelops:replace-me@127.0.0.1:5432/sentinelops
SENTINELOPS_DATABASE_OPERATION_TIMEOUT_SECONDS=15
SENTINELOPS_ALERTMANAGER_SOURCE_ID=prod-cluster-a
SENTINELOPS_ALERTMANAGER_WEBHOOK_AUTH_MODE=bearer
SENTINELOPS_ALERTMANAGER_WEBHOOK_BEARER_TOKEN=replace-with-at-least-32-random-bytes
SENTINELOPS_WORKER_LEASE_TTL_SECONDS=60
SENTINELOPS_WORKER_LEASE_HEARTBEAT_SECONDS=15
SENTINELOPS_WORKER_RECONCILIATION_INTERVAL_SECONDS=5
SENTINELOPS_EXECUTOR_MODE=external
SENTINELOPS_EXECUTOR_BACKEND=controller
SENTINELOPS_EXECUTOR_CLAIM_TTL_SECONDS=60
SENTINELOPS_EXECUTOR_RESULT_TIMEOUT_SECONDS=120
SENTINELOPS_EXECUTOR_MISSING_CONTRACT_GRACE_SECONDS=30
```

数据库 deadline 同时限制连接池等待、SQL 执行和锁等待，避免后台 Worker
因为一条没有上限的数据库调用长期卡住。Executor、GitOps Publisher 和审计锚点 Publisher
使用独立进程心跳；外部依赖异常时审计安全闸门仍会关闭，但 Kubernetes
不会因为一次慢调用反复重启仍然存活的进程。
只有在执行 fence 加宽限时间已经过去、而同名 Controller 合同仍然不存在时，对账任务才会进入
dead letter，Action Intent 保持 `unknown` 并升级人工，不会补建合同。合同仍在执行或 Kubernetes
临时不可访问时会继续重试；身份、spec、终态收据等不可变字段明确不可信时会立即停止自动收口。

先把数据库升级到当前版本并检查版本，再分别启动 API 和独立 Executor：

```bash
sentinelops db-init
sentinelops db-check
sentinelops serve
```

另一个终端：

```bash
sentinelops executor
```

需要把动态提案送入代码评审时，再在不持有 Kubernetes Token 的独立进程中启动：

```bash
sentinelops gitops-publisher
```

事故快照、时间线事件、审批状态、Worker Lease 和 Action Intent 会写入数据库；等待人工审批的
`production-default` 事故会保存 Agent 暂停点，服务重启后仍可使用原审批编号继续。
数据库使用版本号做原子更新，旧进程不能覆盖更新的事故状态，同一审批也只能消费一次。
审批超过有效期后会由后台自动标记为过期，撤销暂停点并升级人工，不会永久卡在等待状态。

写操作会经历 `prepared → queued → claimed → dispatched → succeeded/failed/unknown`。进程崩溃后，系统可以区分
“确认尚未派发”“可能已经派发”和“工具结果已经保存”：尚未派发的旧审批会失效并要求重新确认；
结果未知时禁止自动重试；结果已经保存时保留真实 ToolResult，并升级人工完成恢复验证。

Agent Lease 只负责授权入队；Executor 有自己的 owner、generation、attempt ID 和领取期限。
领取后、合同创建前崩溃可以安全地重新排队；一旦进入 `dispatched`，数据库仍按“外部写可能发生”
处理，超时后标记 `unknown`，不会交给另一个 Executor 猜测重放。合同创建后，Controller 会按 action ID
幂等执行；Controller 自身在写入后崩溃，可以从 Deployment 标记恢复执行结果。替代 Executor 会通过
单独的数据库对账租约只读查询现有合同，并严格核对完整 spec、generation、Executed 条件和结果摘要；
可信终态会自动补回 Action Intent，缺失、未完成、被替换或含糊的合同仍保持 `unknown`，绝不自动补建或重放。
补回 `succeeded` 也只代表集群动作结果已知，事故仍需完成业务恢复验证或由人工确认。

这套 fence 能阻止 SentinelOps 自己的旧审批和重复动作，但不能阻止集群中其他高权限账号绕过 Controller
直接修改 Deployment。要把边界扩展到所有写入者，还需要接入准入策略，并统一约束发布系统和人工权限。
`production` 环境没有配置数据库时，服务会拒绝启动。

`db-init` 使用带版本号的数据库迁移，不是简单执行 `create_all`。生产部署时应把它作为 API 和
Executor 之前单独运行的一次性 Job；API 和 Executor 只检查数据库是否已经到达当前版本，不会在
启动过程中偷偷改表。升级失败或版本落后时进程会直接退出，不会先读取事故、领取任务或执行集群写入。

如果是早期版本通过 `metadata.create_all()` 建出的未标版本数据库，迁移只会在表、字段类型、
是否可空、主键、唯一约束和关键索引全部吻合时接管并保留原数据。结构不完整或被手工改过的数据库
会停止迁移，需要先人工确认，避免把未知结构误标成最新版本。

Alertmanager 的 fingerprint 只代表一组标签，同一故障以后复发时 fingerprint 可能不变。因此数据库
还会保存 `startsAt` 和 resolved 墓碑：同一轮重复投递只会返回原事故；明确更晚的一轮才会创建新事故；
时间信息缺失时不会猜测性重开。不同集群必须配置不同的 `SENTINELOPS_ALERTMANAGER_SOURCE_ID`。

### 保护 Alertmanager Webhook

本地离线演示可以保持 `SENTINELOPS_ALERTMANAGER_WEBHOOK_AUTH_MODE=disabled`。生产环境不允许匿名接收告警，未配置 `bearer` 或 `hmac_sha256` 时 API 会直接拒绝启动。

原生 Alertmanager 最简单的接法是 Bearer Token。先生成至少 32 字节的随机凭据：

```bash
openssl rand -hex 32
```

把凭据交给 Secret 管理系统并以只读文件挂载到 Alertmanager，然后配置：

```yaml
receivers:
  - name: sentinelops
    webhook_configs:
      - url: https://sentinelops.example.com/api/v1/webhooks/alertmanager
        send_resolved: true
        http_config:
          authorization:
            type: Bearer
            credentials_file: /etc/alertmanager/secrets/sentinelops-token
          follow_redirects: false
```

服务端使用同一份值配置 `SENTINELOPS_ALERTMANAGER_WEBHOOK_BEARER_TOKEN`。这个写法来自 [Prometheus Alertmanager 配置文档](https://prometheus.io/docs/alerting/latest/configuration/#http_config)。生产流量仍应使用 HTTPS 和内网访问控制，凭据不要提交到 Git，也不要明文放入 ConfigMap。

`hmac_sha256` 用于前面有签名网关或转发服务的环境；原生 Alertmanager 不会为 Webhook 原始请求体生成这种签名。网关需要发送：

```text
X-SentinelOps-Timestamp: UNIX_SECONDS
X-SentinelOps-Signature: v1=HEX_DIGEST

HEX_DIGEST = HMAC-SHA256(
  secret,
  "sentinelops.alertmanager.v1\n" + UNIX_SECONDS + "\n" + 原始请求字节
)
```

默认只接受过去 300 秒内、未来偏差不超过 30 秒的签名，请求体上限是 1 MiB。签名时间窗负责挡住旧请求，数据库中的告警去重负责多副本并发和 Alertmanager 重试，两者不能互相替代。

轮换凭据时，所有 API 副本先同时配置新凭据、上一把凭据和绝对失效时间，再切换发送端。确认旧请求已走完重试和签名时间窗后删除上一把凭据：

```dotenv
SENTINELOPS_ALERTMANAGER_WEBHOOK_PREVIOUS_BEARER_TOKEN=previous-token
# HMAC 模式改用 SENTINELOPS_ALERTMANAGER_WEBHOOK_PREVIOUS_SIGNING_SECRET
SENTINELOPS_ALERTMANAGER_WEBHOOK_PREVIOUS_SECRET_EXPIRES_AT=2026-07-24T00:00:00Z
```

- API：<http://127.0.0.1:8000>
- API 文档：<http://127.0.0.1:8000/docs>
- Alertmanager Webhook：`POST http://127.0.0.1:8000/api/v1/webhooks/alertmanager`

直接运行这条命令时，默认使用模拟工具和 `rule_based` 固定规则，方便离线检查。要连接 Kubernetes、监控系统和大模型，请使用上面的环境变量，或直接运行 `make console-live`。

创建事故：

```bash
curl -sS http://127.0.0.1:8000/api/v1/incidents \
  -H 'content-type: application/json' \
  -d '{
    "name": "HighOrderServiceErrorRate",
    "namespace": "sentinelops-demo",
    "service": "order-service",
    "severity": "critical",
    "summary": "订单服务错误率超过阈值"
  }'
```

批准修复：

```bash
curl -sS http://127.0.0.1:8000/api/v1/incidents/INCIDENT_ID/approval \
  -H "Authorization: Bearer $SENTINELOPS_OPERATOR_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "approval_id": "APPROVAL_ID",
    "approval_version": 1,
    "approved": true,
    "note": "值班人员确认回滚"
  }'
```

## 测试和验收

日常检查：

```bash
make test
make lint
npm run build --prefix web
```

kind 故障测试：

```bash
make kind-e2e
```

Prometheus、Loki、Tempo 连通性测试：

```bash
make observability-e2e
```

完整的“告警 → 人工审批 → 回滚 → 恢复验证”测试：

```bash
make golden-path-e2e
```

GitHub Actions 会运行后端测试、前端构建、离线评估、kind 端到端测试和监控系统连通性测试。测试数量会随功能变化，以 [GitHub Actions](https://github.com/q741242673/sentinelops/actions) 的最新结果为准。

### Agent 安全评估

`make eval` 不再只跑两个“模型答对并修复成功”的正向例子。现在固定运行 11 个合同场景：

- 坏版本回滚、数据库连接池耗尽两个正确恢复场景；
- 当前证据健康、查询结果为空、诊断自相矛盾三个安全停止场景；
- 伪造 evidence ID、跨服务操作、百万副本扩容、结构化输出失败四个异常模型输出；
- 审批期间出现新 revision，以及写操作成功但恢复验证失败两个生命周期场景。

```bash
make eval
```

[最近一次 Agent 评估报告](evals/report.json) 使用确定性 Provider 和受控的异常 Provider，门槛全部
固定为 `100%`，不安全写入必须为 `0`：

| 指标 | 结果 |
|---|---:|
| 通过场景 | 11/11 |
| 根因正确率 | 100% |
| 已接受诊断的 evidence grounding | 100% |
| 正确恢复率 | 100% |
| 健康、空白或矛盾证据安全停止率 | 100% |
| 异常模型输出拦截率 | 100% |
| 过期审批拦截率 | 100% |
| 恢复失败识别率 | 100% |
| 不安全写入 | 0 |

这套评估测的是 Agent 后端合同和安全边界，不是拿固定规则冒充大模型能力。接入 DeepSeek、OpenAI
或其他模型后，还应使用脱敏的历史事故集单独测模型的根因准确率和证据引用质量；无论换哪个模型，
这里的越权、过期审批、恢复验证和写入边界都必须继续通过。CI 会保存
`agent-evaluation-report` 原始报告。

### 真实模型评估

`make eval` 回答的是“后端安全规则有没有被改坏”，不能证明远程大模型真的会分析事故。仓库因此
另外提供 `make live-model-eval`，把当前配置的真实模型放到 5 个脱敏事故里检查：

- 新版本缺少环境变量时，能否找对原因并精确规划回滚；
- 数据库连接池耗尽时，能否选择有边界的重启；
- 面对健康但带有 `false`、`disabled` 字样的日志，能否停止；
- 没有观测结果时，能否承认证据不足；
- 只有一条日志、其他证据健康时，能否拒绝草率修复。

这些样本只提供固定的只读查询结果。评估器把自动批准上限设为只读，并关闭写工具，所以模型最多
只能生成一个等待审批的方案，不能碰本地或云端集群。报告会记录根因命中率、证据引用、修复方案、
安全停止率、结构化输出成功率、Token、估算费用和 p50/p95 时延；不会保存完整提示词、模型原始
响应、API Key 或事故正文，只保留评分需要的 evidence 绑定、服务端拒绝原因和动作摘要。

```bash
SENTINELOPS_MODEL_PROVIDER=openai_compatible \
SENTINELOPS_MODEL_NAME=your-model-name \
SENTINELOPS_MODEL_BASE_URL=https://api.example.com/v1 \
SENTINELOPS_MODEL_API_KEY=replace-me \
make live-model-eval
```

如果希望报告估算费用，可以传入当前供应商公布的每百万 Token 单价。项目不把某家供应商的价格
写死，因为价格会变：

```bash
LIVE_EVAL_ARGS="--input-cost-per-million 1.0 --output-cost-per-million 2.0" \
make live-model-eval
```

结果写入 `artifacts/live-model-evaluation.json`。这个目录默认不提交 Git，防止把临时运行信息混入
仓库。GitHub Actions 里还有一个需要手动点击的 `live-model-eval` 工作流；普通 PR 不会自动调用
收费模型。仓库 Secret 使用通用名称 `SENTINELOPS_LIVE_EVAL_API_KEY`，现有旧名称只作为兼容兜底。

这两个评估要一起看：真实模型评估说明“模型在固定事故上表现怎样”，确定性安全评估说明“即使
模型答错，后端是否仍能挡住不安全操作”。前者不能替代后者。

### Release Candidate 与持续故障压测

当前候选版本是 `0.1.0-rc.1`（Python 包使用等价的 `0.1.0rc1`）。版本号同时出现在 Python
包、前端包和生产清单里，下面的检查会在任何一处漏改时直接失败：

```bash
make release-check
```

仓库有两条只允许手动或定时运行的工作流，不会让普通 PR 调用收费模型：

- `soak` 每周一运行，也可以手动指定轮数。默认在同一个真实 kind 环境连续完成 20 次
  “注入故障 → 告警 → 调查 → 精确回滚 → 五路恢复验证”，并在 PostgreSQL 中把五组并发和
  故障接管合同各跑 100 次。
- `release-candidate` 只从触发它的 Git commit 构建 Python wheel 和源码包，记录 commit、
  Actions run、版本与 SHA-256 校验和，再放入保留 90 天的 Artifact。它不会创建 Git Tag、
  GitHub Release 或推送容器镜像。
- `release` 只响应 RC Tag。它要求 Tag 指向 `main` 中已经通过完整 `soak` 的同一个 commit，
  否则直接停止。通过后才会构建 `linux/amd64` 镜像和 Python 包，生成 SPDX SBOM，写入
  provenance，用 GitHub OIDC 对镜像做无密钥签名，最后才创建 GitHub Prerelease。RC 不会覆盖
  已存在的版本镜像，也不会发布 `latest`。

压测结束后不是看日志凭感觉判断。`scripts/soak_gate.py` 会独立读取两份 JSON，并要求：

- Kubernetes 完整闭环、根因命中、后端验证恢复全部为 100%；
- 错误修复计划和不安全写入都为 0；
- 每轮事故 ID 唯一，且恰好只有一次成功写入；
- 每轮恢复后至少有 10 次健康请求，故障到确认恢复的 p95 不超过 60 秒；
- PostgreSQL 所有场景全部跑完，正确率 100%，不安全写入为 0。

任一任务崩溃、报告缺失或字段不认识，最终门禁都会失败，不会把“不知道”算成通过。三份原始
证据会分别保存 90 天。需要在本地跑同样的门禁时：

```bash
export SENTINELOPS_BENCHMARK_DATABASE_URL='postgresql+asyncpg://USER:PASSWORD@HOST:5432/ISOLATED_DATABASE'
make postgres-soak
make kubernetes-soak
make soak-gate
```

这套结果证明的是固定环境里的重复恢复能力和安全不变量，不是生产 SLA。正式 RC 发布后，
GitHub Release 会同时提供 wheel、源码包、`SHA256SUMS`、SPDX SBOM 和
`release-manifest.json`。清单把源码 commit、完整 soak run、发布 run、镜像 digest 和文件校验和
绑在一起，查看者不用根据可变 Tag 猜测运行的到底是哪一份代码。版本变化见
[CHANGELOG.md](CHANGELOG.md)。

下载 Release 文件后可以先验证 Python 制品：

```bash
sha256sum --check SHA256SUMS
```

镜像必须用 Release 清单中的 digest，而不是只信版本 Tag。下面把 `<digest>` 替换为清单里的
`sha256:...`：

```bash
docker pull ghcr.io/q741242673/sentinelops@<digest>

cosign verify \
  --certificate-identity \
    "https://github.com/q741242673/sentinelops/.github/workflows/release.yml@refs/tags/v0.1.0-rc.1" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/q741242673/sentinelops@<digest>

gh attestation verify \
  "oci://ghcr.io/q741242673/sentinelops@<digest>" \
  --repo q741242673/sentinelops
```

签名只接受这个仓库、这条 Release workflow 和这个 Tag 的 GitHub OIDC 身份；换仓库、换 workflow
或只拿一个同名镜像都不能通过上述校验。

### PostgreSQL 多副本与故障恢复基准

`make production-readiness` 使用独立 PostgreSQL 数据库运行五组可重复合同：同一告警并发投递、多个 Executor 争抢同一 Action Intent、Executor 在派发前崩溃后的接管、Anchor Publisher 在送达前崩溃后的接管，以及 Worker Lease 过期后的 fencing。通过门槛固定为正确率 `100%` 且不安全写入 `0`；任何场景失败时命令会以非零状态退出。运行前设置：

```bash
export SENTINELOPS_BENCHMARK_DATABASE_URL='postgresql+asyncpg://USER:PASSWORD@HOST:5432/ISOLATED_DATABASE'
make production-readiness
```

仓库中的 [最近一次本地报告](benchmarks/production-readiness.json) 来自 PostgreSQL 16.14、10 轮/场景、16 个并发请求，共 50 次试验：

| 场景 | 通过 | 不安全写入 | p95 |
|---|---:|---:|---:|
| Anchor Publisher 故障接管 | 10/10 | 0 | 28.399 ms |
| Alertmanager 告警并发去重 | 10/10 | 0 | 246.076 ms |
| Executor 单次领取 | 10/10 | 0 | 181.897 ms |
| Executor 派发前崩溃恢复 | 10/10 | 0 | 37.004 ms |
| Worker Lease fencing | 10/10 | 0 | 21.438 ms |

这些数字是当前开发机上的数据库合同结果，不是生产 SLA，也不是 Kubernetes 故障的端到端 MTTR。故障通过让数据库租约立即过期来注入，因此报告证明的是“接管后旧持有者不能继续写”和数据库协调开销；真实恢复时间还要加租约 TTL、网络、外部 API 与 Kubernetes rollout 时间。CI 会在干净的 PostgreSQL 17 数据库上重新运行 100 次试验，并把原始 JSON 作为 `production-readiness-report` Artifact 保存，不直接复用仓库里的本地数字。

### Kubernetes 故障闭环基准

`make kubernetes-readiness` 会创建或复用本地 kind 环境，运行真实的
inventory-service、order-service、Prometheus、Loki、Tempo 和 OpenTelemetry
Collector，然后连续执行三轮：

1. 发布 `FAIL_EVERY=3` 的库存服务故障版本，并产生真实 502、日志和 Trace；
2. 等待绑定 `namespace + service` 的 Prometheus 告警；
3. 让 Agent 查询 Kubernetes、Prometheus、Loki、Tempo 和代码变更；
4. 检查根因是否命中已知注入故障、计划是否精确回滚上一健康 revision；
5. 由基准操作者批准高风险回滚；
6. 从 Deployment、业务请求、错误率、告警和新 Trace 五个方向验证恢复。

```bash
make kubernetes-readiness
```

默认完成后会删除本轮 kind 集群。需要保留现场时使用：

```bash
SENTINELOPS_KEEP_OBSERVABILITY_CLUSTER=true make kubernetes-readiness
```

仓库中的 [最近一次本地报告](benchmarks/kubernetes-readiness.json)
来自 macOS arm64 上的 kind，共三轮：

| 指标 | 结果 |
|---|---:|
| 完整闭环成功率 | 3/3（100%） |
| 已知故障根因命中率 | 3/3（100%） |
| 后端验证恢复率 | 3/3（100%） |
| 错误修复计划 | 0 |
| 非预期集群写入 | 0 |
| 故障生效到告警 p95 | 10.172 秒 |
| Agent 调查到计划 p95 | 214.620 毫秒 |
| 回滚与恢复验证 p95 | 14.859 秒 |
| 故障生效到确认恢复 p95 | 24.283 秒 |

这组测试默认使用确定性 Provider，测的是“真实 Kubernetes 与可观测性证据能否驱动安全闭环”，
不是远程大模型能力排行榜，也不是生产 SLA。它在同一测试进程中运行 Agent，适合快速检查调查和
修复逻辑。CI 会在全新的 kind 集群中运行两轮，并上传
`kubernetes-readiness-report` 原始报告。

### 双 API、独立 Executor 的完整拓扑验收

`make topology-readiness` 检查的不是单进程 Demo，而是下面这条真实链路：

```text
Prometheus → Alertmanager → 2 个 API → PostgreSQL → 2 个 Executor → Kubernetes
                                      ↓
                              审批、操作意图和审计记录
```

测试会在 kind 中启动 PostgreSQL 16、两个 API Pod 和两个独立 Executor Pod。然后发布一个真实
故障版本，让 Prometheus 产生告警、Alertmanager 携带 Bearer Token 调用 API。API 只负责调查和
生成待审批操作，真正的 Kubernetes 写入由 Executor 从数据库领取并执行。测试最后会同时检查：

- 两个 API 是否看到同一份事故和审批；
- 数据库是否只有一条成功的操作意图，是否由真实 Executor Pod 领取；
- 是否只回滚到上一健康 revision，没有多余写入；
- Deployment、业务请求、错误率、告警和新 Trace 是否都恢复；
- resolved webhook、审批和 HMAC 审计记录是否已经落库。

```bash
make topology-readiness
```

默认执行完会删除 kind 集群；需要保留现场时运行：

```bash
SENTINELOPS_KEEP_OBSERVABILITY_CLUSTER=true make topology-readiness
```

仓库中的 [最近一次完整拓扑报告](benchmarks/topology-readiness.json) 来自
macOS arm64 上的 kind：

| 指标 | 结果 |
|---|---:|
| API / Executor 副本 | 2 / 2 |
| Alertmanager 告警进入 API | 17.858 ms |
| 故障生效到后端确认恢复 | 22.992 秒 |
| 故障生效到告警清除 | 23.233 秒 |
| 数据库操作意图 | 1 条成功 |
| 错误修复计划 / 非预期写入 | 0 / 0 |
| HMAC 审计事件 | 23 条 |
| 最终验收项 | 19/19 通过 |

这里使用确定性 Provider，是为了让 CI 每次得到同样的故障判断；远程模型仍可通过统一 Provider
接口替换。该结果证明的是一套可重复的 staging 闭环：真实告警、多副本 API、持久化状态、独立
Executor、最小权限和严格恢复验证已经连起来。它不等于企业生产环境已经上线；真正部署时仍需
把验收里的临时 OIDC 和 Anchor 替换为公司的正式服务，并接入 Secret 管理和长期压测。CI 会上传
`topology-readiness-report`，可以直接核对每个验收项和数据库结果。

### API 和 Executor 中途崩溃时能否继续

`make control-plane-chaos` 在上一套完整拓扑上再增加两个真实故障：

1. Agent 已经生成待审批方案后，删除实际接收 Alertmanager 告警的 API Pod；
2. 审批继续执行时，等第一个 Executor 已领取任务但尚未写 Kubernetes，强制删除该 Pod。

第二个 Executor 不能立刻猜测重试。它必须等旧租约到期，由数据库把未派发任务重新排队，再用更高
generation 领取。最终仍然只允许一条回滚成功。为了稳定命中“已领取、未派发”这个很短的窗口，
验收脚本会临时在测试 PostgreSQL 中延迟第一次 dispatch 事务；Pod 删除后事务自然回滚。这段故障
装置不在 Agent 或 Executor 的生产代码路径中。

```bash
make control-plane-chaos
```

[最近一次控制面故障报告](benchmarks/control-plane-chaos.json) 的结果：

| 指标 | 结果 |
|---|---:|
| 告警所有者 API Pod 替换 | 2.797 秒 |
| 待审批状态在 API 重启后保留 | 通过 |
| 首次 Executor claim | generation 1 |
| 接管 Executor claim | generation 2，不同 Pod |
| 旧 claim 重新排队 | 1 次 |
| 成功回滚 / 多余写入 | 1 / 0 |
| 故障生效到严格验证恢复 | 71.008 秒 |
| 最终验收项 | 25/25 通过 |

这证明了两个重点：API 内存状态丢失后可以从 PostgreSQL 恢复；Executor 在写入分界前崩溃时可以
安全接管，而且旧 generation 已失效。若 Executor 已跨过写入分界再失联，系统仍会标记结果未知并
停止自动重放，不会为了追求“自动恢复成功”而冒险重复写集群。CI 会保存
`control-plane-chaos-report` 原始报告。

### 身份和外部审计失效时是否会停

`make security-readiness` 使用的还是上面的真实 kind 故障，不是只测几个函数。区别是它会再启动一套
独立 PostgreSQL 和 Anchor 服务，并临时生成 RSA 身份签名密钥、查看者 Token、审批者 Token，以及
Anchor 的 Ed25519 回执密钥。密钥只存在于本次运行的临时目录和 Kubernetes Secret，报告不会保存
Token。

验收顺序是：

1. API 和 Executor 先启动，此时还没有外部对账结果，数据库写闸门必须保持关闭；
2. 两个 Anchor Publisher 与独立服务完成签名对账后，闸门才能打开；
3. 主动停掉 Anchor 服务，超过允许的新鲜度后，闸门必须再次关闭；
4. Anchor 恢复并重新对账，才继续注入真实故障；
5. 匿名请求、错误 audience 的 Token 和只有查看权限的审批请求都必须被拒绝；
6. 审批者通过后只允许一次回滚，恢复验证完成后，再从独立服务读取最终回执并单独验签。

```bash
make security-readiness
```

[最近一次安全闭环报告](benchmarks/security-readiness.json) 的结果：

| 指标 | 结果 |
|---|---:|
| API / Executor / Anchor Publisher 副本 | 2 / 2 / 2 |
| 初始未对账时禁止写入 | 通过 |
| Anchor 中断后自动关闭写闸门 | 通过 |
| 匿名 / 伪造 Token / 越权审批 | 全部拒绝 |
| OIDC 审批身份写入审计链 | 通过，只保存 subject 哈希 |
| 审计事件 / 外部已签名锚点 | 22 / 22 |
| 成功回滚 / 非预期写入 | 1 / 0 |
| 故障生效到严格验证恢复 | 22.768 秒 |
| 最终验收项 | 31/31 通过 |

这里的临时身份服务只负责让测试可重复，不是在项目里自造一套公司账号系统。真正部署时应接企业
OIDC，把 Anchor 放到独立权限域，并使用 HTTPS 和正式 Secret。这个验收能证明的是：代码已经真的
走过签名身份、权限拒绝、依赖失效关闸、恢复后对账、外部持久化和独立验签，而不只是 README 写了
这些能力。CI 会保存 `security-readiness-report` 原始报告。

## 项目目录

```text
src/sentinelops/
├── actions.py      # 可执行修复动作的 Action Plugin 合同与注册表
├── change_proposals.py # 不可执行的动态变更预览、边界检查和 diff
├── gitops.py       # 独立 GitOps Gateway 投递、回执绑定和重试
├── gitops_gateway.py # 参考 GitHub Draft PR Gateway
├── agent/          # Agent 执行流程、质量检查和风险策略
├── llm/            # 大模型接口和不同服务的适配代码
├── storage/        # PostgreSQL 事故、审批、租约和操作意图
├── tools/          # Kubernetes、监控和 Git 查询工具
├── executor.py     # 独立 Action Intent 领取、合同提交和结果回写
├── remediation_controller.py # 生成不可变 CR、提交并等待 Go Controller 结果
├── api.py          # FastAPI 接口、告警接收和实时进度
├── demo.py         # 本地演示的故障注入与环境恢复
├── lab_profiles.py # 三种演示流程的服务端绑定规则
└── runtime.py      # 生产 Agent 的组装入口
controller/         # Go 集群内执行 Controller、动作合同和幂等恢复测试
web/                # React + TypeScript 事故控制台
demo/               # 本地微服务和测试流量
deploy/             # 生产清单、完整拓扑验收、RBAC 和监控配置
evals/              # 可重复运行的 Agent 评估
benchmarks/          # PostgreSQL、Kubernetes 和多副本拓扑的原始报告
tests/              # 单元测试和安全边界测试
```

## 当前完成度

已经完成：

- 可替换的大模型接口；
- 告警到调查、审批、执行、验证和报告的完整流程；
- Kubernetes、Prometheus、Loki、Tempo 和 Git 证据采集；
- 人工审批、自动修复和复杂调查三种本地演示；
- React 实时事故控制台；
- kind、监控系统和 GitHub Actions 端到端测试；
- PostgreSQL 事故快照、追加式事件、一次性审批和等待审批状态的重启恢复；
- 带数据库 fencing generation 的 Worker Lease，以及写操作 Action Intent、审批自动过期和崩溃结果判定；
- 独立 `sentinelops executor`、单独的 Executor generation，以及生产环境 create-only 的修复合同提交权限；
- 不可变动态提案、事务型 GitOps Outbox、独立 Publisher、摘要绑定回执，以及与 API/Agent 分离的仓库凭据边界；
- `SentinelRemediation` v1alpha1 集群内执行合同、不可变 spec、独立 status、终态保护和 create-only Executor 提交权限；
- Python Executor 到 Go Remediation Controller 的真实执行链：跨语言合同摘要、create-only CR、真实 ServiceAccount Token、最小 RBAC 和 kind Deployment 写入验证；
- Executor 崩溃后的 Controller 终态自动对账：只读恢复、完整合同与结果摘要校验、数据库租约 fencing、幂等回写和 kind 崩溃窗口回放；
- Go Remediation Controller：三种注册动作、fresh preflight、resourceVersion CAS、动作标记幂等恢复、Lease 选主、最小 RBAC 和双副本部署；
- 版本化 Alembic 数据库迁移、生产启动版本门禁，以及 SQLite/PostgreSQL 数据保留回归测试；
- PostgreSQL 告警 fingerprint 生命周期、跨副本原子去重、乱序事件保护和崩溃后补调度；
- 生产 Webhook 启动门禁、Bearer Token、原始请求体 HMAC、密钥轮换和请求大小边界；
- API/Executor/审计锚定 Publisher 分离部署、Secret 文件挂载、迁移 Job、探针、PDB、容器加固和入站 NetworkPolicy；
- 独立审计表、事务内追加、逐事故哈希链、生产 HMAC 门禁、Durable Outbox、Ed25519 回执、challenge 防重放清单、反向对账和持久化写闸门；
- 数据库权威的审计锚定 Prometheus 指标、低基数标签、双副本安全 PromQL，以及积压、dead letter、对账过期和写闸门告警；
- 生产 OIDC 启动门禁、固定 issuer/audience/JWKS、异步 Key 缓存、细分 API 权限、人类身份 Claim，以及带稳定操作者摘要的审批审计；
- 审计锚点双人解锁闭环：绑定安全代次、区分申请与批准权限、禁止自批、追加式决策审计、对账租约 fencing、新 challenge 签名全量清单、inventory revision 和最终 CAS；

接入生产环境前还需要：

- 使用准入策略约束 Controller 之外的 Deployment 写入者，把 fence 从 SentinelOps 内部边界扩展到整个集群；
- 接入企业 Secret 管理和更细的 RBAC；
- 为外部锚定增加限流和灾难恢复方案。

现在它已经能在本地 Kubernetes 和监控环境中完成一整次事故处理，但还不适合未经评估就直接接管生产集群。

## 开源协议

Apache-2.0
