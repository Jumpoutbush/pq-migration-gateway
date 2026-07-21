# PQC Migration Gateway v3.7

面向异构存量系统的后量子迁移与密码资产发现原型。

本项目提供后量子 TLS 接入、经典客户端兼容、企业密码资产扫描、风险评估、迁移编排、配置发布、运行监测和回滚能力。项目不实现具体金融业务，企业可以将已有的 HTTP、HTTPS、TCP、MQTT、消息队列、数据库和遗留协议服务接入网关。

网关基于：

- NGINX 1.28.0；
- OpenSSL 3.5.0；
- TLS 1.3；
- `X25519MLKEM768` Hybrid 密钥交换；
- `X25519` 经典兼容回退。

默认兼容策略：

```text
X25519MLKEM768:X25519
```

严格策略：

```text
X25519MLKEM768
```

---

# 第一部分：整体框架介绍

## 1. 项目解决的问题

企业通常无法同时升级所有客户端、后端服务、密码库、证书体系和应用代码。本项目采用“资产驱动、网关过渡、兼容优先、验证后收紧”的迁移路线：

```text
发现密码资产
    ↓
识别算法、证书、密码库和网络端点
    ↓
风险评估
    ↓
确定需要保护的业务入口
    ↓
部署 PQC Gateway
    ↓
兼容模式：Hybrid 优先，经典可用
    ↓
统计真实 Hybrid 使用率和经典回退率
    ↓
升级、代理或隔离旧客户端
    ↓
严格模式：只允许 Hybrid
    ↓
继续升级网关到后端及应用内部密码资产
```

网关首先升级客户端到企业入口这一段 TLS。企业原后端可以暂时保持 HTTP 或经典 TLS，待业务稳定后再继续迁移。

## 2. 两段独立连接

Gateway 会终止客户端 TLS，并重新建立到企业后端的连接：

```text
客户端
   │
   │ 下游连接：Hybrid TLS 或经典 TLS
   ▼
PQC Gateway
   │
   │ 上游连接：HTTP、经典 TLS、mTLS 或 Hybrid TLS
   ▼
企业原业务服务
```

两段连接独立配置：

| 连接段 | 典型初始状态 | 迁移目标 |
|---|---|---|
| 客户端 → Gateway | `X25519MLKEM768:X25519` | 严格 `X25519MLKEM768` |
| Gateway → 企业后端 | 原有 HTTP 或经典 TLS | TLS、mTLS、Hybrid TLS |

如果客户端和服务器都只支持经典 TLS，单独增加服务器侧网关不能凭空产生后量子保护。至少需要客户端或客户端侧代理支持 Hybrid，客户端到网关这一段才能使用 `X25519MLKEM768`。

## 3. 兼容模式和严格模式

### 3.1 兼容模式

```json
{
  "mode": "compatibility",
  "groups": [
    "X25519MLKEM768",
    "X25519"
  ]
}
```

TLS 握手时：

- 支持 Hybrid 的客户端协商 `X25519MLKEM768`；
- 只支持经典算法的客户端协商 `X25519`；
- 没有共同算法时握手失败。

网关不会扫描客户端程序，也不会先建立一次失败连接再重新连接。TLS 根据双方提供的算法组完成能力协商，网关记录最终协商结果。

### 3.2 严格模式

```json
{
  "mode": "strict",
  "groups": [
    "X25519MLKEM768"
  ]
}
```

严格模式只接受 Hybrid。只支持 `X25519` 的客户端会被拒绝。

默认 pilot 证书仍可能使用 RSA。严格模式当前主要约束 TLS 1.3 密钥交换组，不代表服务器身份认证证书已经全部迁移为后量子签名。

## 4. 客户端如何接入网关

客户端原来访问：

```text
payment.internal:8080
```

接入后访问：

```text
payment-gateway.company.local:28443
```

常见切流方法：

- 修改客户端访问地址；
- 修改 DNS 记录；
- 修改负载均衡器转发目标；
- 保持原域名，将原域名解析到 Gateway；
- 对无法修改的旧客户端部署本地代理。

当前测试客户端主要由 OpenSSL `s_client`、curl 和协议测试脚本实现。客户端角色是模拟的，但 TLS 握手、证书验证、密钥交换和数据传输均由真实 OpenSSL 执行。

## 5. 核心组件

```text
PQC Migration Gateway
├── Gateway 数据面
│   ├── TLS 终止
│   ├── Hybrid/经典协商
│   ├── HTTP/Stream 代理
│   └── mTLS 与上游 TLS
├── Manager API 控制面
│   ├── 服务接入
│   ├── 扫描任务
│   ├── 资产与证据
│   ├── 风险评估
│   ├── 迁移计划
│   ├── 配置发布
│   ├── 状态与审计
│   └── 回滚
├── Gateway Agent
│   ├── 配置签名和校验和验证
│   ├── NGINX 候选配置生成
│   ├── nginx -t
│   ├── reload
│   └── 健康检查
├── Scanner
│   ├── 源码和配置扫描
│   ├── 二进制、动态库和静态库扫描
│   ├── 证书和密钥元数据扫描
│   ├── CMDB/CIDR/在线 TLS 扫描
│   └── 静态源码、制品和端点证据
├── Runtime Agent
│   ├── 运行进程与容器归属
│   ├── /proc 密码库映射
│   ├── 可选固定 eBPF 密码接口观测
│   └── 可靠上报与离线重试
└── Metrics Agent
    ├── Hybrid 使用量
    ├── 经典回退率
    ├── TLS/mTLS 错误
    └── 发布与 Agent 状态
```

## 6. 数据面接口和管理接口

业务客户端访问 Gateway 监听端口，例如：

```text
https://payment-gateway.company.local:28443
```

企业管理员访问 Manager API：

```text
http://127.0.0.1:18080
```

两类接口含义不同：

| 接口 | 用途 | 默认保护 |
|---|---|---|
| Gateway `28443` | 真实业务流量 | TLS 1.3 Hybrid/兼容 |
| Manager API `18080` | 扫描、资产、迁移、发布和回滚 | 本机回环 HTTP + Token |

`POST /v1/scans` 是 HTTP REST 请求，不是 Shell 命令或直接 Python 函数。Make 命令和 `pqapi.py` 是它的客户端封装：

```text
make enterprise-scan
        ↓
manager/pqapi.py scan create
        ↓
POST http://127.0.0.1:18080/v1/scans
        ↓
Manager API 调用扫描编排器
```

## 7. 主要 REST API

| HTTP 接口 | 作用 |
|---|---|
| `POST /v1/scans` | 创建异步企业扫描任务 |
| `GET /v1/scans` | 查询扫描任务 |
| `GET /v1/scans/{id}/findings` | 查询文件、符号和接口证据 |
| `POST /v1/runtime/reports` | Runtime Agent 上报进程、容器和调用证据 |
| `GET /v1/runtime/agents` | 查询 Runtime Agent 与运行进程 |
| `GET /v1/runtime/observations` | 查询密码库映射和实际接口调用 |
| `GET /v1/assets` | 查询归一化密码资产 |
| `POST /v1/assets/{id}/assess` | 风险评估 |
| `POST /v1/assets/{id}/migration` | 创建、验证或完成迁移计划 |
| `POST /v1/onboarding` | 接入并发布 Gateway 服务 |
| `GET /v1/status` | 聚合系统状态 |
| `GET /v1/releases` | 发布历史 |
| `POST /v1/releases/{version}/rollback` | 回滚历史版本 |
| `GET /v1/audit` | 审计事件 |

`POST`、`GET` 等 HTTP 方法本身没有经典或后量子属性。是否获得后量子保护取决于外层 TLS。当前 `18080` 只面向本机管理；远程开放时应增加 HTTPS、mTLS、防火墙和访问控制。

## 8. 支持的业务协议

| 适配器 | 使用场景 |
|---|---|
| `http` | HTTP/HTTPS 服务 |
| `tcp` | 通用 TCP 服务 |
| `mqtt` | MQTT 消息服务 |
| `amqp` | AMQP 消息服务 |
| `kafka` | Kafka |
| `mysql` | MySQL |
| `postgres` | PostgreSQL |
| `redis` | Redis |
| `generic-stream` | 通用长连接协议 |
| `legacy-line` | 行式遗留协议 |

业务协议需要企业在服务配置中明确指定。网关不会在生产流量中自动尝试 HTTP、HTTPS、MQTT 等协议，也不会在 HTTPS 失败后自动降级为 HTTP。

## 9. 密码资产扫描能力

扫描器支持多层证据：

- C、C++、Java、Rust、Go、Python、Shell 源码；
- TLS、NGINX、Apache、YAML、JSON、TOML、XML 等配置；
- X.509 证书和 PEM 私钥元数据；
- `compile_commands.json` 编译上下文；
- 受限的 Clang AST 语义分析，不重放原始编译命令；
- 复杂模板、嵌套宏、直接调用和跨包装函数调用关系；
- 可确定的函数指针目标、虚函数候选目标及动态符号加载；
- ELF、PE、Mach-O 和 WebAssembly；
- `.so` 动态库和 `.a` 静态库；
- JAR、WAR、EAR 和 Java class；
- 动态依赖、导入符号、字符串和 C++ 名称反修饰；
- Go、Rust 编译程序中的包路径和密码标记；
- `/proc/<pid>/maps` 运行进程映射；
- 可选固定 eBPF 探针事件；
- CMDB CSV/JSON 导入；
- CIDR 网段发现；
- 在线 TLS、证书和 group 探测。

扫描器不执行目标程序，也不执行 `compile_commands.json` 中的原始命令。它只从编译数据库提取经过白名单过滤的标准版本、头文件路径和非敏感宏，再以 `clang++ -fsyntax-only` 生成有大小和超时限制的 AST。编译器插件、响应文件、链接参数、输出参数和敏感宏值不会传入 Clang。Clang 不可用或解析失败时自动回退到宏展开和启发式调用图，不会中断整个扫描任务。

默认 `auto` 模式仅对具有编译数据库上下文的 C++ 文件启用语义分析。也可以显式控制：

```bash
python3 scripts/crypto_inventory.py \
  --root /srv/company/apps \
  --compile-commands /srv/company/apps/build/compile_commands.json \
  --cpp-semantic on \
  --out-json inventory.json \
  --out-csv inventory.csv
```

通过扫描 API 时可在请求中设置 `"cpp_semantic":"auto"`、`"on"` 或 `"off"`。对于运行时才决定的函数指针、跨动态库虚调用和动态加载目标，仍需结合进程映射或运行观测。裁剪、加壳程序会被保留为“分析不完整”证据，不再因为没有符号而被当作无密码资产。扫描器不保存私钥内容；字符串命中也不代表接口一定被执行。

### 9.1 运行中后端扫描

v3.7 增加独立 Runtime Agent，可部署在真实后端主机或容器节点：

```text
运行中后端
  → /proc 进程映射和 cgroup 容器归属
  → 可选固定 eBPF 密码接口调用
  → 认证、落盘缓存和幂等上报
  → Manager API
  → runtime 表 + crypto_assets + scan_findings
```

`/proc` 证据说明进程加载了某个密码库；eBPF 证据说明采样窗口内确实调用了某个允许的密码接口。Agent 不执行目标程序，不接收任意探针程序，默认也不采集命令行。完整部署与权限说明见 [`docs/runtime-agent.md`](docs/runtime-agent.md)。

默认 Agent 检查所在主机或节点上的运行进程；已知后端 PID 也可用重复的 `--pid` 参数限定范围。跨主机时必须在对应后端主机或 Kubernetes 节点部署 Agent，Manager 不能远程读取另一台机器的 `/proc`。

## 10. 扫描到迁移闭环

```text
POST /v1/scans
    ↓
GET /v1/assets
    ↓
POST /v1/assets/{id}/assess
    ↓
POST /v1/assets/{id}/migration
    ↓
发布兼容模式
    ↓
验证 Hybrid 和经典客户端
    ↓
观察回退率并升级旧客户端
    ↓
发布严格模式
    ↓
验证 Hybrid 成功、经典失败、业务正常
    ↓
VERIFIED 或回滚
```

扫描器不会自动猜测监听端口、域名、上游地址和业务负责人。这些业务接入信息由企业通过服务配置或 CMDB 提供。

## 11. 发布与迁移状态

配置发布状态：

```text
DRAFT → VALIDATED → STAGED → APPLIED → HEALTHY
```

迁移状态：

```text
DISCOVERED → ASSESSED → PLANNED → COMPATIBILITY
           → PQC_PREFERRED → STRICT → VERIFIED
```

发布失败时可能进入：

```text
VALIDATION_FAILED
NGINX_TEST_FAILED
RELOAD_FAILED
HEALTH_CHECK_FAILED
ROLLED_BACK
```

`STAGED` 只表示候选配置已生成并等待 Agent 应用。只有 `current_version` 与 `desired_version` 相同且状态为 `HEALTHY`，新版本才已真正生效。

## 12. 普通实验环境和 Enterprise 环境

| 环境 | 用途 | 后端 |
|---|---|---|
| `run_full_experiment.sh` | 自动功能、安全和性能验证 | 项目模拟后端 |
| Enterprise | 长期运行和企业手工/API 接入 | 企业真实或临时后端 |

两套环境共用代码和 Docker 镜像，但使用不同 Compose 配置、容器、运行数据和服务对象。通常交替运行，避免争用 `18080`、`8443` 等端口。

Enterprise 不是模拟企业实体，也不是单独的下游接口。它是一套包含 Gateway、Manager API、Metrics Agent、数据库和持久化目录的企业部署方式；Runtime Agent 按需部署到真实业务主机或容器节点。

## 13. 项目边界

当前版本是单节点企业试点框架。生产化还需要：

- 企业 PKI；
- 后量子证书体系；
- HSM/KMS；
- 密钥轮换和吊销；
- 高可用、负载均衡和多节点一致性；
- WAF、DDoS 防护和限流；
- SIEM 和审计留存；
- 大规模 CMDB、证书平台和监控平台集成；
- 经授权的生产网段扫描策略；
- 针对真实数据库、消息队列和专有协议的兼容性验证。

Gateway 保护经过它的网络连接，不会自动将应用内部的 RSA 签名、文件加密、数据库字段加密或业务报文签名替换为后量子算法。

---

# 第二部分：环境配置

## 14. 推荐环境

- Windows Subsystem for Linux 2（WSL2）Ubuntu 24.04；
- Docker Engine；
- Docker Compose V2；
- Python 3.12；
- curl；
- make；
- Git；
- unzip；
- `rg`（ripgrep，推荐）。

安装基础依赖：

```bash
sudo apt update
sudo apt install -y \
  ca-certificates \
  curl \
  git \
  make \
  unzip \
  python3 \
  docker.io \
  docker-compose-v2 \
  ripgrep
```

将当前用户加入 Docker 用户组：

```bash
sudo usermod -aG docker "$USER"
newgrp docker
```

检查：

```bash
docker version
docker compose version
python3 --version
```

## 15. 项目目录

```text
pq-migration-gateway/
├── backend/                  # 模拟 HTTP/HTTPS/MQTT/TCP/遗留后端
├── certs/                    # 演示 PKI
├── config/                   # 服务、扫描和 Enterprise 配置
├── deploy/enterprise/        # Enterprise Compose
├── docker/                   # OpenSSL + NGINX 镜像
├── gateway/                  # 数据面、Agent、适配器和模板
├── manager/                  # Manager API、数据库、迁移和指标
├── scanner/                  # 网络、CMDB 和持续扫描
├── scripts/                  # 初始化、实验、扫描和性能脚本
├── runtime-data/             # 持久运行数据
├── experiment-results/       # 普通实验结果
├── docker-compose.yml        # 普通实验环境
├── Makefile
└── README.md
```

## 16. WSL 代理构建

默认代理示例：

```text
http://127.0.0.1:7897
```

生成演示证书并构建：

```bash
make certs
make build
```

`make build` 应通过 `docker build --network=host`，同时传入大小写两组代理变量：

```bash
docker build \
  --network=host \
  --build-arg OPENSSL_VERSION=3.5.0 \
  --build-arg NGINX_VERSION=1.28.0 \
  --build-arg MAKE_JOBS=4 \
  --build-arg HTTP_PROXY=http://127.0.0.1:7897 \
  --build-arg HTTPS_PROXY=http://127.0.0.1:7897 \
  --build-arg http_proxy=http://127.0.0.1:7897 \
  --build-arg https_proxy=http://127.0.0.1:7897 \
  --build-arg NO_PROXY=localhost,127.0.0.1,::1 \
  --build-arg no_proxy=localhost,127.0.0.1,::1 \
  -f docker/Dockerfile.gateway \
  -t pq-migration-gateway-pq-gateway:3.7 \
  .
```

代理端口变化时：

```bash
make build WSL_PROXY=http://127.0.0.1:7890
```

### 16.1 本机 REST 测试与 NO_PROXY

Python `urllib` 可能不识别 `NO_PROXY` 中的 `127.*`。本机 REST 测试应使用精确地址：

```text
127.0.0.1,localhost
```

只对一次命令生效：

```bash
NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}" \
no_proxy="127.0.0.1,localhost${no_proxy:+,$no_proxy}" \
python3 scripts/test_scan_migration_api.py \
  /tmp/pq-scan-migration-debug
```

为保证测试确定性，进程内 REST 测试也可以在 Python 中禁用代理：

```python
urllib.request.install_opener(
    urllib.request.build_opener(
        urllib.request.ProxyHandler({})
    )
)
```

该设置只影响当前测试进程。

## 17. 普通环境初始化

首次运行：

```bash
cd ~/wkspace/pq-migration-gateway
make init
```

常用选项：

```bash
# 使用已有镜像
make init INIT_ARGS="--skip-build"

# 只准备环境、证书和初始发布
make init INIT_ARGS="--prepare-only"

# 非 WSL 环境无代理构建
make init INIT_ARGS="--no-proxy"
```

后续启动：

```bash
make up
```

查看状态和日志：

```bash
docker compose ps
make logs
```

停止：

```bash
make down
```

## 18. Enterprise 首次初始化

准备一个真实存在的宿主机扫描目录。测试时可以使用当前项目：

```bash
cd ~/wkspace/pq-migration-gateway

make enterprise-init \
  SCAN_ROOT="$PWD" \
  SERVER_NAME=payment-gateway.company.local \
  LISTEN_PORT=28443
```

生产部署示例：

```bash
make enterprise-init \
  SCAN_ROOT=/srv/company/apps \
  SERVER_NAME=payment-gateway.company.local \
  LISTEN_PORT=28443
```

`SCAN_ROOT` 是宿主机目录，Docker 将其只读挂载为：

```text
/workspace/project
```

`SCAN_ROOT` 只负责授权和挂载，本身不执行扫描。日常扫描通过 `/v1/scans` 创建任务。

## 19. Enterprise 启动和停止

启动：

```bash
make enterprise-up
```

检查：

```bash
make enterprise-status
make enterprise-capabilities
```

日志：

```bash
make enterprise-logs
```

停止：

```bash
make enterprise-down
```

如果需要同时停止可观测组件：

```bash
docker compose \
  --env-file .env.enterprise \
  -f deploy/enterprise/docker-compose.yml \
  --profile observability \
  down --remove-orphans
```

请勿随意添加 `-v`。

## 20. Enterprise 数据持久化

容器可以删除和重建，企业关键数据保存在宿主机：

```text
runtime-data/enterprise/
├── control/
│   ├── control-plane.db
│   └── scans/
│       └── <SCAN_ID>/
│           ├── inventory.json
│           └── inventory.csv
├── certs/
├── config/
├── runtime-agent/
│   └── spool/
└── metrics/
```

其他重要文件：

```text
.env.enterprise
config/enterprise/services.json
payment-service.json
```

普通 `enterprise-down` 后仍会保留：

- Token；
- 配置签名密钥；
- 证书；
- 扫描结果；
- 资产与风险评估；
- 发布和回滚历史。

容器内 `/tmp` 候选配置、活动连接和进程状态属于临时数据。

## 21. 主要端口

| 端口 | 用途 |
|---:|---|
| `8443` | 普通实验兼容入口 |
| `9443` | 普通实验严格入口 |
| `8883` | MQTT TLS |
| `10443`、`11443` | 客户端 mTLS 实验 |
| `12443` | 上游 HTTPS/mTLS |
| `13443`、`14443` | 上游负面实验 |
| `15443` | TCP TLS |
| `16443` | 遗留协议 TLS |
| `18080` | Manager API |
| `28443` | Enterprise 示例业务入口 |
| `3000` | Grafana |
| `9090` | Prometheus |

---

# 第三部分：实验流程

## 22. 两套实验的使用原则

```text
普通实验：停止 Enterprise → run_full_experiment → 清理普通实验

Enterprise：停止普通实验 → enterprise-up → 接入临时/真实后端
```

两套环境不需要同时开启。普通完整实验脚本会自行建立模拟后端和测试客户端；Enterprise 需要企业提供真实后端，或者手动建立临时测试后端。

---

## 23. 普通完整实验：run_full_experiment

### 23.1 停止 Enterprise 和残留实验环境

```bash
cd ~/wkspace/pq-migration-gateway

docker compose \
  --env-file .env.enterprise \
  -f deploy/enterprise/docker-compose.yml \
  --profile observability \
  down --remove-orphans

docker compose \
  -f docker-compose.yml \
  down --remove-orphans

docker stop pq-manager-api 2>/dev/null || true
```

检查：

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' \
  | grep -E 'pq-|bank-backend|grafana|prometheus' || true
```

### 23.2 运行完整实验

镜像已经构建时：

```bash
NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}" \
no_proxy="127.0.0.1,localhost${no_proxy:+,$no_proxy}" \
./scripts/run_full_experiment.sh --latest
```

需要重新构建：

```bash
BUILD=1 \
NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}" \
no_proxy="127.0.0.1,localhost${no_proxy:+,$no_proxy}" \
./scripts/run_full_experiment.sh --latest
```

性能档位：

```bash
PERF_PROFILE=quick ./scripts/run_full_experiment.sh --latest
PERF_PROFILE=standard ./scripts/run_full_experiment.sh --latest
PERF_PROFILE=stress ./scripts/run_full_experiment.sh --latest
```

完整实验默认使用 `standard`。

### 23.3 覆盖范围

完整实验包括：

- 兼容入口 Hybrid 和 X25519；
- 严格入口接受 Hybrid、拒绝 X25519；
- 客户端 mTLS 矩阵；
- 上游 HTTPS、SNI 和网关客户端证书；
- 错误 CA 和缺少客户端证书负面测试；
- 上游证书轮换；
- HTTP、MQTT、TCP 和遗留协议；
- 企业源码、制品、二进制和进程映射扫描；
- 扫描到资产到迁移 REST API 工作流；
- API-first 接入、发布、状态、审计和回滚；
- CMDB 导入和 CIDR 发现；
- 在线 TLS 和持续扫描；
- 回退指标；
- 端到端性能测试。

### 23.4 成功标志和结果

成功标志：

```text
All v3.7 experiments completed: experiment-results/<UTC时间戳>
```

查看：

```bash
cat experiment-results/latest/experiment-status.json
cat experiment-results/latest/SUMMARY.md
```

关键结果：

```text
experiment-results/latest/
├── experiment-status.json
├── SUMMARY.md
├──
