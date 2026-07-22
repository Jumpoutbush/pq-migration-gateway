# PQC Migration Gateway

面向异构存量系统的后量子迁移与密码资产发现原型。

项目由迁移网关、资产扫描器、运行时 Agent 和 Manager API 控制端组成，支持在不一次性改造全部客户端与后端的情况下，逐步将企业网络入口迁移到混合后量子 TLS，并根据静态扫描、运行时证据和真实连接指标制定迁移策略。

当前数据面基于：

- NGINX 1.28.0；
- OpenSSL 3.5.0；
- TLS 1.3；
- `X25519MLKEM768` 混合后量子密钥交换；
- `X25519` 经典兼容回退。

默认兼容策略：

```text
X25519MLKEM768:X25519
```

严格策略：

```text
X25519MLKEM768
```

## 1. 系统结构

```text
企业应用源码、二进制、配置 ──> 静态/网络扫描器 ──┐
                                                  │
业务客户端或服务端进程 ────────> Runtime Agent ──┼─> Manager API
                                                  │   资产、风险、迁移计划、发布、审计
网关协商结果、回退率和错误 ─────> Metrics Agent ──┘

客户端 ──> PQC Migration Gateway ──> 企业后端服务
             Hybrid/经典 TLS          HTTP、TLS、mTLS 或流式协议
```

### 1.1 迁移网关

网关位于客户端和企业后端之间，承载实际业务流量：

- 终止客户端到网关的 TLS；
- 优先协商 `X25519MLKEM768`；
- 在兼容阶段允许旧客户端回退到 `X25519`；
- 代理 HTTP、HTTPS、TCP、MQTT、消息队列、数据库和遗留流式协议；
- 独立配置网关到后端的 HTTP、TLS 或双向 TLS（mTLS）；
- 记录协商组、回退率、错误和发布状态；
- 支持兼容模式、严格模式、配置发布和回滚。

客户端到网关、网关到后端是两条独立连接：

```text
客户端
  │
  │ 下游：Hybrid TLS 或经典 TLS
  ▼
迁移网关
  │
  │ 上游：HTTP、经典 TLS、mTLS 或 Hybrid TLS
  ▼
企业后端
```

TLS 密钥交换组在握手阶段确定。发布严格策略后，新连接只允许 `X25519MLKEM768`；已经回退到 `X25519` 的长连接需要结束或被关闭，再重新握手才能升级。

### 1.2 密码资产扫描器

扫描器由管理端创建任务，在授权目录或授权端点上收集证据：

- C、C++、Java、Rust、Go、Python 和 Shell 源码；
- NGINX、Apache、YAML、JSON、TOML、XML 等配置；
- X.509 证书和 PEM 密钥元数据；
- `compile_commands.json` 编译上下文；
- 受限的 Clang 抽象语法树分析、宏展开和部分调用关系；
- ELF、PE、Mach-O、WebAssembly、JAR、WAR 和 EAR；
- 动态库、静态库、导入符号、字符串和 C++ 名称反修饰；
- CMDB CSV/JSON 导入；
- CIDR 网段发现；
- 在线 TLS、证书和密钥交换组探测。

扫描器不会执行目标程序，也不会执行 `compile_commands.json` 中的原始构建命令。字符串命中代表存在相关证据，不等同于接口在运行时实际被调用。

### 1.3 Runtime Agent

Runtime Agent 必须部署在需要观测的业务主机或容器节点上：

- 读取目标进程的 `/proc/<pid>/maps`；
- 识别实际加载的密码库；
- 根据进程、容器控制组和主机信息确定资产归属；
- 可选使用扩展伯克利包过滤器（eBPF）用户态探针观测允许列表中的密码接口调用；
- 将批次可靠上传到 Manager API，失败时保留本地缓存并重试。

证据含义：

| 来源 | 能够说明的事实 | 限制 |
|---|---|---|
| `/proc/<pid>/maps` | 进程加载了某个密码库 | 不能证明某个函数已经执行 |
| `ebpf_uprobe` | 采样窗口内执行了被监测接口 | 只能看到已挂载、已导出且实际触发的接口 |
| 静态扫描 | 源码或制品中存在调用、算法或配置证据 | 可能存在不可达代码或动态目标 |

Agent 无法隔着网络读取远程客户端或服务端的进程信息。要盘点多台业务主机，需要在各主机或容器节点分别部署 Agent。

### 1.4 Manager API 控制端

Manager API 负责连接网关、扫描器和 Agent：

- 扫描任务管理；
- 资产与证据归一化；
- 风险评估和迁移计划；
- 服务接入和配置生成；
- 配置发布、健康检查和回滚；
- Runtime Agent 数据接收；
- 指标、状态和审计查询。

常用接口：

| HTTP 接口 | 作用 |
|---|---|
| `POST /v1/scans` | 创建异步静态扫描任务 |
| `GET /v1/scans` | 查询扫描任务 |
| `GET /v1/scans/{id}/findings` | 查询扫描证据 |
| `POST /v1/runtime/reports` | Runtime Agent 上报运行时批次 |
| `GET /v1/runtime/agents` | 查询 Agent 和业务进程 |
| `GET /v1/runtime/observations` | 查询进程映射和接口调用证据 |
| `GET /v1/assets` | 查询归一化密码资产 |
| `POST /v1/assets/{id}/assess` | 进行风险评估 |
| `POST /v1/assets/{id}/migration` | 创建或更新迁移计划 |
| `POST /v1/onboarding` | 接入网关服务 |
| `GET /v1/releases` | 查询发布历史 |
| `POST /v1/releases/{version}/rollback` | 回滚历史版本 |
| `GET /v1/status` | 查询聚合系统状态 |
| `GET /v1/audit` | 查询审计记录 |

`manager/pqapi.py` 是项目提供的正式命令行客户端。例如：

```bash
python3 manager/pqapi.py status
python3 manager/pqapi.py scan list
python3 manager/pqapi.py asset list
python3 manager/pqapi.py runtime agents
```

演示材料中偶尔使用的 `api_get()` 只是临时 Shell 函数，不属于项目命令。

## 2. 迁移路线

```text
扫描企业应用和网络端点
        ↓
形成密码资产与证据
        ↓
风险评估和迁移计划
        ↓
部署兼容模式：Hybrid 优先，X25519 可回退
        ↓
统计 Hybrid 使用率、经典回退率和失败类型
        ↓
升级旧客户端、客户端代理和后端
        ↓
发布严格模式：仅允许 X25519MLKEM768
        ↓
验证新连接、业务流量和回滚能力
```

网关首先保护客户端到企业入口这一段连接。后端可以暂时保留 HTTP 或经典 TLS，再按资产风险继续迁移上游连接和应用内部密码功能。

兼容模式不会先制造一次失败握手再回退。客户端和网关在同一次 TLS 握手中提交支持的算法组，并选择共同支持的最高优先级组。

## 3. 支持的协议适配器

| 适配器 | 场景 |
|---|---|
| `http` | HTTP 和 HTTPS 服务 |
| `tcp` | 通用 TCP 服务 |
| `mqtt` | MQTT 消息服务 |
| `amqp` | AMQP 消息服务 |
| `kafka` | Kafka |
| `mysql` | MySQL |
| `postgres` | PostgreSQL |
| `redis` | Redis |
| `generic-stream` | 通用长连接协议 |
| `legacy-line` | 行式遗留协议 |

企业需要在服务配置中明确适配器、监听端口、域名和上游地址。网关不会在生产流量中逐个猜测应用协议，也不会在 HTTPS 连接失败后自动降级为 HTTP。

## 4. 资产范围与项目边界

企业资产盘点的对象应当是企业客户端、业务服务端、遗留应用、配置、证书和网络端点。项目自建网关的密码函数不应被当作企业待迁移资产。

```text
业务应用目录 ──> 静态扫描 ──> 企业密码资产
业务进程主机 ──> Runtime Agent ──> 企业运行时资产
迁移网关 ──> 协商、回退和错误指标 ──> 迁移运行指标
```

因此：

- `SCAN_ROOT` 应指向企业应用目录，不能在正式资产盘点中指向网关仓库；
- Runtime Agent 应部署在业务主机，并用进程标识、容器标识或节点范围限定资产归属；
- 网关上的 `SSL_accept`、`SSL_read` 等调用只证明网关自身执行了 TLS；
- 远程客户端的密码函数只有客户端主机上的 Agent 才能观测；
- 远程服务端的密码函数只有服务端主机或对应容器节点上的 Agent 才能观测。

当前版本仍属于单节点企业试点框架。生产部署还需要企业公钥基础设施（PKI）、硬件安全模块或密钥管理系统、高可用、负载均衡、访问控制、审计留存、网段扫描授权以及真实业务兼容性测试。

默认 pilot 证书使用 RSA。严格模式当前主要约束 TLS 1.3 密钥交换组，不表示服务器身份认证证书已经迁移为后量子签名。

## 5. 环境要求

推荐环境：

- Windows Subsystem for Linux 2（WSL2）Ubuntu 24.04，或原生 Linux；
- Docker Engine；
- Docker Compose V2；
- Python 3.12；
- GNU Make；
- curl；
- OpenSSL；
- `jq`；
- `timeout`；
- `rg`（ripgrep，可选但推荐）；
- `bpftrace`，仅在主机直接执行 eBPF 实验时需要。

Ubuntu 安装示例：

```bash
sudo apt update
sudo apt install -y \
  ca-certificates \
  curl \
  git \
  jq \
  make \
  openssl \
  python3 \
  ripgrep \
  docker.io \
  docker-compose-v2
```

将当前用户加入 Docker 用户组后重新登录：

```bash
sudo usermod -aG docker "$USER"
```

环境检查：

```bash
docker version
docker compose version
python3 --version
make --version
curl --version
openssl version
jq --version
timeout --version
```

## 6. 环境变量和配置文件

### 6.1 普通实验环境

`.env` 用于普通 Compose 实验，`config/services.json` 定义普通实验服务。首次准备：

```bash
make init
```

常用选项：

```bash
# 已经存在 v3.7 镜像
make init INIT_ARGS="--skip-build"

# 只生成环境、证书和初始配置
make init INIT_ARGS="--prepare-only"

# 原生 Linux 或无需代理
make init INIT_ARGS="--no-proxy"
```

### 6.2 Enterprise 环境

`.env.enterprise` 由 `make enterprise-init` 生成，权限为 `0600`。其中包含令牌和配置签名密钥，不能提交到 Git，也不应复制到 README 或日志中。

关键变量：

| 变量 | 用途 |
|---|---|
| `PQ_SCAN_HOST_ROOT` | 宿主机上被授权扫描的企业应用根目录 |
| `PQ_GATEWAY_IMAGE` | Enterprise 网关和 Manager API 镜像 |
| `PQ_MANAGER_API_BIND` | Manager API 监听地址，默认 `127.0.0.1` |
| `PQ_MANAGER_API_URL` | 命令行客户端和 Agent 使用的管理地址 |
| `MANAGER_API_TOKEN` | 管理员读取和控制接口令牌 |
| `RUNTIME_AGENT_TOKEN` | Runtime Agent 独立上报令牌 |
| `PQ_CONFIG_SIGNING_KEY` | 配置发布签名密钥 |
| `PQ_RUNTIME_UID`、`PQ_RUNTIME_GID` | Enterprise 容器使用的宿主机用户标识 |
| `PQ_PROCESS_SCAN_ENABLED` | Manager 内部进程扫描开关，默认关闭 |
| `PQ_EBPF_ENABLED` | Manager 内部 eBPF 开关，默认关闭 |

初始化示例：

```bash
make enterprise-init \
  SCAN_ROOT=/srv/company/apps \
  SERVER_NAME=pqc-gateway.company.local \
  LISTEN_PORT=28443
```

该命令把宿主机目录只读挂载到 Manager API 容器：

```text
/srv/company/apps  ──只读挂载──>  /workspace/project
```

日常扫描通过 `/v1/scans` 选择 `/workspace/project` 下的目录。管理接口不能借此读取未授权的其他宿主机目录。

已有 `.env.enterprise` 从旧版本升级时，重新执行相同初始化命令会补充缺少的 `RUNTIME_AGENT_TOKEN`，同时保留已有令牌和签名密钥。若需要重建初始服务配置，可显式执行：

```bash
./scripts/init_enterprise.sh \
  --scan-root /srv/company/apps \
  --server-name pqc-gateway.company.local \
  --listen-port 28443 \
  --force
```

`--force` 会替换 `config/enterprise/services.json`，已有企业服务配置应先备份或改用服务接入接口。

只检查变量是否存在，不打印秘密值：

```bash
for name in \
  GRAFANA_ADMIN_PASSWORD \
  MANAGER_API_TOKEN \
  PQ_CONFIG_SIGNING_KEY \
  PQ_GATEWAY_IMAGE \
  PQ_MANAGER_API_BIND \
  PQ_MANAGER_API_URL \
  PQ_RUNTIME_GID \
  PQ_RUNTIME_UID \
  PQ_SCAN_HOST_ROOT \
  RUNTIME_AGENT_TOKEN
do
  grep -qE "^${name}=.+" .env.enterprise || echo "missing: $name"
done
```

配置静态检查：

```bash
make validate-config
make enterprise-validate
```

查看 Compose 最终使用的镜像和变量替换结果：

```bash
docker compose config --images

docker compose \
  --env-file .env.enterprise \
  -f deploy/enterprise/docker-compose.yml \
  config --images

docker compose \
  --env-file .env.enterprise \
  -f deploy/runtime-agent/docker-compose.yml \
  -f deploy/runtime-agent/docker-compose.ebpf.yml \
  config --images
```

### 6.3 WSL 代理构建

Makefile 默认使用：

```text
http://127.0.0.1:7897
```

构建网关和 Agent：

```bash
make build WSL_PROXY=http://127.0.0.1:7897
make runtime-agent-build WSL_PROXY=http://127.0.0.1:7897
```

两个构建目标均使用 `docker build --network=host`，并传入大小写两组 `HTTP_PROXY`、`HTTPS_PROXY`、`NO_PROXY` 变量。代理端口不同可通过 `WSL_PROXY` 覆盖。

本机管理接口测试应确保回环地址不经过代理：

```bash
export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}"
export no_proxy="127.0.0.1,localhost${no_proxy:+,$no_proxy}"
```

## 7. 主要目录和端口

```text
pq-migration-gateway/
├── backend/                  # 实验业务后端
├── certs/                    # 普通实验 PKI
├── config/                   # 服务和扫描配置
├── deploy/enterprise/        # Enterprise Compose
├── deploy/runtime-agent/     # Runtime Agent Compose
├── docker/                   # 网关和 Agent 镜像
├── gateway/                  # 数据面、适配器和配置渲染
├── manager/                  # Manager API、发布和迁移编排
├── scanner/                  # 静态、网络和运行时采集
├── scripts/                  # 初始化、实验和测试脚本
├── runtime-data/             # 持久运行数据
├── experiment-results/       # 普通完整实验结果
├── docker-compose.yml        # 普通实验环境
├── Makefile
└── README.md
```

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
| `18082` | 本 README 企业演示的业务 TLS 后端 |
| `28443` | Enterprise 示例网关入口 |
| `3000` | Grafana，可选 |
| `9090` | Prometheus，可选 |

## 8. 实验一：普通完整实验

普通功能、安全、扫描和性能实验只保留一个入口：

```bash
./scripts/run_full_experiment.sh --latest
```

脚本自行启动普通 Compose 环境、模拟客户端和模拟后端。为避免端口冲突，运行前停止 Enterprise：

```bash
make runtime-agent-down 2>/dev/null || true
make enterprise-down 2>/dev/null || true
docker compose down --remove-orphans 2>/dev/null || true
```

已有镜像时：

```bash
NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}" \
no_proxy="127.0.0.1,localhost${no_proxy:+,$no_proxy}" \
./scripts/run_full_experiment.sh --latest
```

需要重建镜像时：

```bash
BUILD=1 \
WSL_PROXY=http://127.0.0.1:7897 \
NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}" \
no_proxy="127.0.0.1,localhost${no_proxy:+,$no_proxy}" \
./scripts/run_full_experiment.sh --latest
```

性能档位通过环境变量选择：

```bash
PERF_PROFILE=quick ./scripts/run_full_experiment.sh --latest
PERF_PROFILE=standard ./scripts/run_full_experiment.sh --latest
PERF_PROFILE=stress ./scripts/run_full_experiment.sh --latest
```

默认档位为 `standard`。完整实验覆盖：

- 兼容入口接受 Hybrid 和 `X25519`；
- 严格入口接受 Hybrid 并拒绝 `X25519`；
- 客户端 mTLS；
- 上游 HTTPS、SNI、mTLS、错误 CA、缺失客户端证书和证书轮换；
- HTTP、MQTT、TCP 和遗留协议；
- 企业源码、制品、二进制和进程映射扫描；
- 扫描、资产、评估、迁移、发布和回滚接口；
- CMDB、CIDR、在线 TLS 和持续扫描；
- 经典回退指标；
- 端到端性能测试。

成功标志：

```text
All v3.7 experiments completed: experiment-results/<UTC时间戳>
```

查看结果：

```bash
cat experiment-results/latest/experiment-status.json
cat experiment-results/latest/SUMMARY.md
```

主要输出位于：

```text
experiment-results/latest/
├── experiment-status.json
├── SUMMARY.md
├── mtls/
├── upstream/
├── stream/
├── enterprise-scan/
├── runtime-agent/
├── scan-migration-api/
├── api-first/
├── crypto-inventory.json
├── tls-inventory.json
├── risk-report.json
├── inventory.db
└── performance/
```

## 9. 实验二：企业应用扫描、运行时 Agent 与网关联动

本实验整理自 `todo.md`，同时修正资产归属：

```text
backend/ 模拟企业应用源码 ──> Enterprise 静态扫描

secure_backend.py 业务进程 ──> PID 限定的 Runtime Agent

测试客户端 ──> Hybrid TLS 网关 ──> 经典 TLS 业务后端

Manager API <── 静态资产、业务运行时证据、网关迁移指标
```

网关连接验证与资产扫描分开进行。Runtime Agent 只采集演示业务进程的 PID，不把网关和测试客户端的密码函数计入企业资产。

### 9.1 清理旧环境并检查端口

```bash
make runtime-agent-down 2>/dev/null || true
make enterprise-down 2>/dev/null || true
docker compose down --remove-orphans 2>/dev/null || true
```

```bash
sudo ss -ltnp |
rg ':(18080|18082|28443|3000|9090)\b' || true
```

端口被其他程序占用时，应停止对应旧实例或为演示选择新的端口。不要直接终止无法确认归属的进程。

### 9.2 构建镜像

```bash
docker image inspect \
  pq-migration-gateway-pq-gateway:3.7 \
  >/dev/null 2>&1 ||
make build WSL_PROXY=http://127.0.0.1:7897
```

PID 限定的主机 Agent 直接使用 Python，不依赖 Agent 镜像。若后续要在 Docker 或 Kubernetes 节点部署常驻 Agent，再构建：

```bash
docker image inspect \
  pq-migration-runtime-agent:3.7 \
  >/dev/null 2>&1 ||
make runtime-agent-build WSL_PROXY=http://127.0.0.1:7897
```

### 9.3 初始化 Enterprise 环境

演示只授权扫描 `backend/`，不会扫描整个网关仓库：

```bash
./scripts/init_enterprise.sh \
  --scan-root "$PWD/backend" \
  --server-name pqc-gateway.company.local \
  --listen-port 28443 \
  --force
```

检查环境文件是否完整：

```bash
for name in \
  MANAGER_API_TOKEN \
  RUNTIME_AGENT_TOKEN \
  PQ_CONFIG_SIGNING_KEY \
  PQ_GATEWAY_IMAGE \
  PQ_MANAGER_API_URL \
  PQ_SCAN_HOST_ROOT
do
  grep -qE "^${name}=.+" .env.enterprise || echo "missing: $name"
done
```

确认扫描根目录，不打印令牌：

```bash
sed -n 's/^PQ_SCAN_HOST_ROOT=/PQ_SCAN_HOST_ROOT=/p' \
  .env.enterprise
```

预期路径以当前仓库的 `/backend` 结尾。

### 9.4 启动模拟企业 TLS 后端

该进程代表一个仍使用经典 TLS 的企业业务服务：

```bash
python3 backend/secure_backend.py \
  --host 127.0.0.1 \
  --port 18082 \
  --cert runtime-data/enterprise/certs/server.crt \
  --key runtime-data/enterprise/certs/server.key \
  --client-ca runtime-data/enterprise/certs/ca.crt \
  > /tmp/pq-business-backend.log 2>&1 &

BUSINESS_PID=$!
echo "BUSINESS_PID=$BUSINESS_PID"
ps -fp "$BUSINESS_PID"
```

确认后端可访问：

```bash
curl --noproxy '*' \
  --resolve pqc-gateway.company.local:18082:127.0.0.1 \
  --cacert runtime-data/enterprise/certs/ca.crt \
  https://pqc-gateway.company.local:18082/healthz |
jq .
```

### 9.5 配置并启动 Enterprise 网关

将网关上游设置为前一步的经典 TLS 业务后端，并启用证书验证和上游 SNI：

```bash
python3 manager/generate_service_config.py \
  --config config/enterprise/services.json \
  --id enterprise-pilot \
  --adapter http \
  --listen 28443 \
  --server-name pqc-gateway.company.local \
  --upstream https://127.0.0.1:18082 \
  --mode compatibility \
  --upstream-tls \
  --upstream-tls-verify required \
  --upstream-sni pqc-gateway.company.local \
  --upstream-ca /etc/pq-gateway/certs/ca.crt
```

```bash
make enterprise-validate
make enterprise-up
make enterprise-apply
make enterprise-status
```

加载管理环境：

```bash
set -a
source .env.enterprise
set +a
```

使用项目正式客户端检查能力和发布状态：

```bash
python3 manager/pqapi.py capabilities
python3 manager/pqapi.py release list
python3 manager/pqapi.py status
```

### 9.6 验证经典回退和 Hybrid TLS

系统 curl 通常使用经典 `X25519`，可验证兼容回退：

```bash
curl --noproxy '*' \
  --resolve pqc-gateway.company.local:28443:127.0.0.1 \
  --cacert runtime-data/enterprise/certs/ca.crt \
  https://pqc-gateway.company.local:28443/service-info |
jq .
```

该响应应来自 `secure-upstream-backend`，从而证明经典客户端、网关和 TLS 后端的完整链路可用。

使用混合后量子组请求相同后端：

```bash
printf \
  'GET /service-info HTTP/1.1\r\nHost: pqc-gateway.company.local\r\nConnection: close\r\n\r\n' |
timeout 15 docker exec -i \
  pq-enterprise-gateway \
  /opt/openssl/bin/openssl s_client \
  -quiet \
  -connect 127.0.0.1:28443 \
  -servername pqc-gateway.company.local \
  -tls1_3 \
  -groups X25519MLKEM768 \
  -CAfile /etc/pq-gateway/certs/ca.crt \
  -verify_return_error
```

响应同样应包含 `secure-upstream-backend`。单独查看混合后量子协商结果：

```bash
timeout 15 docker exec -i \
  pq-enterprise-gateway \
  /opt/openssl/bin/openssl s_client \
  -brief \
  -connect 127.0.0.1:28443 \
  -servername pqc-gateway.company.local \
  -tls1_3 \
  -groups X25519MLKEM768 \
  -CAfile /etc/pq-gateway/certs/ca.crt \
  -verify_return_error \
  </dev/null
```

重点检查：

```text
Protocol version: TLSv1.3
Negotiated TLS1.3 group: X25519MLKEM768
Verification: OK
```

此处容器内的 `s_client` 只用于验证连接，不代表企业客户端资产。Runtime Agent 尚未对它进行采集。

### 9.7 扫描企业应用目录

```bash
SCAN_JSON="$(
  python3 manager/pqapi.py scan create \
    --root /workspace/project \
    --wait
)"

echo "$SCAN_JSON" | jq '{scan_id,scan_type,status,summary,error}'
SCAN_ID="$(echo "$SCAN_JSON" | jq -r '.scan_id')"
```

查询发现和资产：

```bash
python3 manager/pqapi.py scan findings "$SCAN_ID" |
jq '.items[:20]'

python3 manager/pqapi.py asset list
```

容器内 `/workspace/project` 对应宿主机 `$PWD/backend`。扫描结果属于模拟企业应用，不属于迁移网关源码。

### 9.8 采集指定业务进程的 `/proc` 证据

先再次确认 PID 仍属于业务后端：

```bash
ps -fp "$BUSINESS_PID"
```

只采集该 PID：

```bash
python3 manager/runtime_agent.py once \
  --agent-id demo-business-backend \
  --pid "$BUSINESS_PID" \
  --spool-dir /tmp/pq-runtime-agent-spool
```

查询业务进程和密码库映射：

```bash
python3 manager/pqapi.py runtime agent \
  demo-business-backend

python3 manager/pqapi.py runtime observations \
  --agent-id demo-business-backend |
jq '[.items[] | {
  source,
  method,
  library,
  observation_count,
  last_observed
}]'
```

预期至少出现 `source = "proc_maps"`，说明 `secure_backend.py` 进程实际加载了 TLS 密码库。

### 9.9 可选 eBPF 接口调用实验

该步骤需要 Linux eBPF 支持、`bpftrace`、`nm` 和相应权限。先检查：

```bash
command -v bpftrace
test -e /sys/kernel/debug/tracing/uprobe_events
```

在 20 秒采样窗口中，只对业务 PID 挂载固定允许列表探针：

```bash
sudo --preserve-env=PQ_MANAGER_API_URL,RUNTIME_AGENT_TOKEN \
  python3 manager/runtime_agent.py once \
  --agent-id demo-business-backend-ebpf \
  --pid "$BUSINESS_PID" \
  --ebpf \
  --ebpf-duration 20 \
  --spool-dir /tmp/pq-runtime-agent-ebpf-spool \
  > /tmp/pq-runtime-agent-ebpf.json 2>&1 &

AGENT_JOB=$!
sleep 3
```

采样期间直接访问业务后端，使业务进程执行 TLS 接口：

```bash
for attempt in $(seq 1 40); do
  curl --noproxy '*' \
    --resolve pqc-gateway.company.local:18082:127.0.0.1 \
    --cacert runtime-data/enterprise/certs/ca.crt \
    -sS \
    https://pqc-gateway.company.local:18082/healthz \
    >/dev/null
  sleep 0.2
done

wait "$AGENT_JOB"
cat /tmp/pq-runtime-agent-ebpf.json | jq .
```

查询实际接口调用：

```bash
python3 manager/pqapi.py runtime observations \
  --agent-id demo-business-backend-ebpf |
jq '[
  .items[] |
  select(.source == "ebpf_uprobe") |
  {
    method,
    library,
    observation_count,
    last_observed
  }
]'
```

如果 eBPF 不可用，Agent 会保留同批次的 `/proc` 证据，并在元数据中记录失败原因。WSL 内核、Docker Desktop 虚拟机和受限生产主机的能力可能不同。

常驻容器 Agent 的命令为：

```bash
make runtime-agent-up
make runtime-agent-ebpf-up
```

常驻模式默认观测所在节点可见的多个进程。生产环境应通过独立节点部署、已知 PID、容器控制组或后续的包含/排除策略保证资产归属，不能把网关进程的观测结果计入业务资产。

### 9.10 查看系统状态和迁移指标

```bash
python3 manager/pqapi.py status
python3 manager/pqapi.py asset list
python3 manager/pqapi.py audit
```

网关协商和回退数据属于迁移指标：

```bash
cat runtime-data/enterprise/metrics/current.json | jq .
```

业务源码扫描、业务 PID 的 `proc_maps` 和可选 `ebpf_uprobe` 属于企业密码资产证据。两类数据在 Manager API 中关联使用，但资产含义不同。

### 9.11 清理演示

停止 Enterprise 组件：

```bash
make runtime-agent-down 2>/dev/null || true
make enterprise-down
```

停止已确认 PID 的模拟业务后端：

```bash
kill "$BUSINESS_PID"
wait "$BUSINESS_PID" 2>/dev/null || true
```

检查端口：

```bash
sudo ss -ltnp |
rg ':(18080|18082|28443|3000|9090)\b' || true
```

普通清理不会删除：

```text
runtime-data/enterprise/
```

扫描结果、运行时证据、发布历史、指标和审计记录仍可用于后续展示。不要添加 Compose 的 `-v` 参数，除非已经确认要删除持久数据。

## 10. 常用 Enterprise 命令

```bash
make enterprise-up
make enterprise-status
make enterprise-capabilities
make enterprise-apply
make enterprise-history
make enterprise-assets
make enterprise-audit
make enterprise-logs
make enterprise-down
```

可观测组件：

```bash
make dashboard-up
make dashboard-down
```

访问地址：

```text
Manager API: http://127.0.0.1:18080
Prometheus:   http://127.0.0.1:9090
Grafana:      http://127.0.0.1:3000
```

远程开放 Manager API 时应增加 HTTPS、mTLS、防火墙和细粒度访问控制。默认回环 HTTP 只适用于单机管理和隔离实验。

## 11. 故障排查

### 11.1 `18080` 端口已占用

```bash
sudo ss -ltnp 'sport = :18080'
docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
```

确认旧容器属于本项目后再停止：

```bash
make enterprise-down 2>/dev/null || true
docker compose down --remove-orphans 2>/dev/null || true
```

### 11.2 `.env.enterprise` 缺少 `RUNTIME_AGENT_TOKEN`

使用原扫描目录重新初始化：

```bash
make enterprise-init \
  SCAN_ROOT=/srv/company/apps \
  SERVER_NAME=pqc-gateway.company.local \
  LISTEN_PORT=28443
```

初始化器会补充 Agent 令牌并保留现有秘密值。

### 11.3 Manager API 请求意外经过代理

```bash
export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}"
export no_proxy="127.0.0.1,localhost${no_proxy:+,$no_proxy}"
```

curl 查询可直接使用：

```bash
curl --noproxy '*' http://127.0.0.1:18080/healthz
```

### 11.4 eBPF 没有事件

依次检查：

- Agent 是否部署在目标业务进程所在主机或 PID 命名空间；
- 指定 PID 是否仍属于目标业务进程；
- 业务进程是否动态加载受支持的密码库；
- 目标接口是否为可导出符号；
- 采样窗口内是否产生了真实业务调用；
- `bpftrace`、内核、debugfs 和权限是否可用；
- 调用是否被静态链接、内联或移动到未覆盖的 Provider 内部。

eBPF 没有事件时不能据此断言业务未使用密码算法，应结合静态扫描和 `/proc` 证据判断。

### 11.5 Enterprise 配置修改后未生效

```bash
make enterprise-validate
make enterprise-apply
make enterprise-history
python3 manager/pqapi.py status
```

只有发布状态为 `HEALTHY`，且 `current_version` 与 `desired_version` 相同，才表示新配置已经应用。

## 12. 进一步文档

- [`docs/architecture.md`](docs/architecture.md)：系统架构；
- [`docs/control-plane.md`](docs/control-plane.md)：控制面与发布状态；
- [`docs/service-model.md`](docs/service-model.md)：服务配置模型；
- [`docs/enterprise-scanning.md`](docs/enterprise-scanning.md)：企业扫描能力；
- [`docs/cpp-semantic-scanning.md`](docs/cpp-semantic-scanning.md)：C++ 语义扫描；
- [`docs/runtime-agent.md`](docs/runtime-agent.md)：Runtime Agent 部署、权限和限制；
- [`docs/scan-migration-api.md`](docs/scan-migration-api.md)：扫描到迁移接口；
- [`docs/api-first.md`](docs/api-first.md)：以 API 为中心的企业接入；
- [`docs/experiment-matrix.md`](docs/experiment-matrix.md)：完整实验矩阵。

## 13. 安全说明

- 仅扫描获得授权的目录、主机和网段；
- `.env.enterprise`、私钥、令牌和运行数据不能提交到 Git；
- 扫描目录使用只读挂载；
- Runtime Agent 不接收任意 eBPF 程序；
- eBPF profile 需要额外能力，生产部署前必须进行主机安全审查；
- 远程 Agent 上报应使用 HTTPS 或企业 mTLS 入口；
- 迁移网关不能自动替换应用内部的 RSA 签名、文件加密、数据库字段加密或业务报文签名。
