# PQC Migration Gateway v3.2 — Control Plane Runtime

一个面向异构存量系统的后量子迁移基础设施原型。项目不实现具体金融业务，而是提供：

- 密码资产发现与风险评估；
- TLS 1.3 Hybrid/PQC 接入；
- 经典客户端兼容回退；
- HTTP/HTTPS、MQTT、通用 TCP 和非 HTTP 遗留协议代理；
- 客户端 mTLS 与网关到上游的 HTTPS/mTLS；
- 企业网段、批量端点和 CMDB 资产扫描；
- 持续扫描、配置验证、运行时回退统计；
- 完整功能与性能实验。

v3.2 把 v3.1 的框架核心升级为可持续运行的控制面：Service、Policy、ConfigVersion、GatewayAgent、MigrationState、AuditEvent 与 RuntimeMetric 都成为持久化资源；管理 API 提供资源 CRUD、发布、回滚、心跳和指标接口；发布过程拥有完整状态流水。旧 v3 配置和 v3.1 的统一模型仍可读取，默认配置继续使用 `schema_version: 4.0`。

网关使用 **NGINX 1.28.0 + OpenSSL 3.5.0**。默认迁移策略为：

```text
X25519MLKEM768:X25519
```

支持 PQC 的客户端优先使用 `X25519MLKEM768`，尚未升级的客户端可以回退到 `X25519`。严格入口只允许 `X25519MLKEM768`。

---

## 1. v3.2 功能

### 1.0 控制面运行时

- Service 与 Policy 资源持久化、查询、更新和删除；
- 配置发布状态：`DRAFT → VALIDATED → STAGED → APPLIED → HEALTHY`；
- 验证、`nginx -t`、reload、健康检查失败分别记录；
- Gateway Agent 心跳、当前/期望配置版本、健康和 reload 结果上报；
- `/metrics` 暴露发布、Agent、TLS group、经典回退和 TLS/mTLS 错误指标；
- `pqctl` 支持配置、资源、迁移、Agent 与指标管理。

### 1.1 通用接入

| 接入类型 | 实现方式 | 示例端口 |
|---|---|---:|
| HTTP/HTTPS | NGINX HTTP TLS 终止与反向代理 | 8443、9443 |
| 客户端 mTLS | `off`、`optional`、`required` | 10443、11443 |
| 上游 HTTPS | CA 校验、SNI、网关客户端证书 | 12443 |
| 错误 CA 测试 | 上游证书校验必须失败 | 13443 |
| 缺少上游客户端证书 | 上游 mTLS 必须失败 | 14443 |
| MQTT TLS | NGINX Stream TLS 终止 | 8883 |
| 通用 TCP TLS | NGINX Stream TLS 终止 | 15443 |
| 非 HTTP 遗留协议 | 透明转发示例 | 16443 |

所有业务载荷均被视为不透明数据。新增系统主要通过 `config/services.json` 配置，不要求修改网关源码。

### 1.2 企业密码资产发现

支持：

- X.509 证书、私钥、TLS 配置和源码引用扫描；
- 单端点和批量端点输入；
- CSV/JSON CMDB 资产导入；
- CIDR 网段与端口发现；
- 并发在线 TLS 端点扫描；
- TLS 版本、证书算法、密钥长度和 TLS group 探测；
- SQLite 资产、证据、端点、CMDB 与风险数据归一化；
- 定时持续扫描、快照保存和变化对比。

### 1.3 运行时迁移监测

HTTP 与 Stream 日志持久保存在：

```text
runtime-data/logs/
```

`metrics-agent` 持续生成：

```text
runtime-data/metrics/current.json
runtime-data/metrics/history.jsonl
runtime-data/metrics/pqc_gateway.prom
```

统计范围是网关实际运行期间的全部连接，而不局限于实验脚本流量。指标包括：

- Hybrid/PQC 连接数；
- X25519 经典回退数；
- 全局和按服务的 Hybrid 使用率；
- 按 HTTP、MQTT、TCP、遗留协议分类；
- 按客户端地址汇总。

### 1.4 完整安全实验

一键实验覆盖：

- 兼容入口的 Hybrid/PQC 与 X25519；
- 严格入口接受 Hybrid/PQC、拒绝 X25519；
- mTLS 的关闭、可选、强制、有效证书、无证书和错误 CA；
- 上游 HTTPS 证书验证；
- 上游 SNI；
- 网关到上游的 mTLS；
- 错误上游 CA 拒绝；
- 缺少上游客户端证书拒绝；
- 上游证书轮换；
- MQTT 发布/订阅；
- TCP echo；
- 非 HTTP 遗留行协议；
- 静态资产扫描、CMDB 导入、CIDR 发现和持续扫描；
- 风险评估、SQLite 导入和策略验证；
- 持久化回退统计；
- 握手、HTTP、TCP、遗留协议和 MQTT 性能测试。

---

## 2. 架构

```text
资产文件 / CMDB / 批量端点 / 企业 CIDR
                |
                v
+--------------------------------------------+
| Discovery and Inventory                    |
| 静态扫描、网段发现、TLS扫描、持续扫描       |
+--------------------------------------------+
                |
                v
+--------------------------------------------+
| Risk and Migration Manager                 |
| 风险评估、SQLite、配置生成、迁移验证         |
+--------------------------------------------+
                |
                v
客户端 ── TLS 1.3 Hybrid/PQC ──> PQC Gateway
                                  |
             +--------------------+--------------------+
             |                    |                    |
             v                    v                    v
        HTTP/HTTPS             MQTT/TCP          遗留协议
             |
             v
    HTTP 或 HTTPS/mTLS 上游系统
```

默认演示后端只用于验证协议透明性：

- `bank-backend`：普通 HTTP；
- `secure-backend`：要求客户端证书的 HTTPS；
- `mqtt-broker`：最小 MQTT 3.1.1 QoS-0 测试 broker；
- `tcp-backend`：TCP echo；
- `legacy-backend`：非 HTTP 行协议。

生产接入时应将这些演示后端替换为真实系统地址。

---

## 3. 目录结构

```text
pq-migration-gateway-v3/
├── backend/                  # HTTP、HTTPS、MQTT、TCP、遗留协议测试后端
├── certs/                    # 演示 PKI 与上游证书轮换脚本
├── config/
│   ├── services.json         # HTTP 与 Stream 服务配置
│   ├── scan-targets.json     # 批量 TLS 扫描目标
│   ├── continuous-scan.json  # 持续扫描配置
│   └── cmdb/                 # CMDB 导入样例
├── docker/                   # OpenSSL 3.5 + NGINX 构建
├── gateway/                  # 网关入口脚本
├── manager/                  # 风险、数据库、策略验证、运行指标
├── scanner/                  # 静态、批量、CIDR、CMDB、持续扫描
├── scripts/                  # 构建、实验和性能测试
├── tests/                    # 离线单元测试
├── runtime-data/             # 持久日志、指标、扫描快照
├── docker-compose.yml
├── Makefile
└── README.md
```

---

## 4. 环境要求

推荐环境：

- WSL2 Ubuntu 24.04；
- Docker Engine；
- Docker Compose V2；
- Python 3；
- curl、make、unzip。

安装：

```bash
sudo apt update
sudo apt install -y ca-certificates curl git make unzip python3 docker.io docker-compose-v2
sudo usermod -aG docker "$USER"
newgrp docker

docker version
docker compose version
```

---

## 5. WSL 代理构建

本项目默认使用 Windows 代理：

```text
http://127.0.0.1:7897
```

直接执行：

```bash
make certs
make build
```

`make build` 实际使用：

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
  -t pq-migration-gateway-pq-gateway:3.2 \
  .
```

代理端口变化时：

```bash
make build WSL_PROXY=http://127.0.0.1:7890
```

---

## 6. 启动项目

首次运行：

```bash
cd ~/wkspace/pq-migration-gateway
make init
```

`make init` 调用项目根目录的 `init_system.sh`；该入口再执行 `scripts/init_system.sh` 中的完整实现，一次完成：

- 环境与 Docker Compose 检查；
- `.env` 创建及管理 API/配置签名密钥生成；
- 运行时目录和演示 PKI 初始化；
- 统一服务配置校验；
- 初始签名配置版本发布；
- OpenSSL 3.5/NGINX 镜像构建；
- 网关、后端、指标 Agent 和 Manager API 启动；
- 网关健康状态等待与结果输出。

常用选项：

```bash
# 使用已有镜像
make init INIT_ARGS="--skip-build"

# 只准备环境、证书和初始发布，不要求 Docker
make init INIT_ARGS="--prepare-only"

# 非 WSL 环境无代理构建
make init INIT_ARGS="--no-proxy"
```

脚本默认不会覆盖已有密钥或证书。只有显式传入 `--force-certs` 才会轮换整套演示 PKI。

后续的 `make up` 使用已有证书和镜像，不会重新构建或重新生成 PKI：

```bash
docker compose up -d --no-build --force-recreate
```

检查：

```bash
docker compose ps
```

查看日志：

```bash
make logs
```

停止：

```bash
make down
```

机器重启后通常只需：

```bash
cd ~/wkspace/pq-migration-gateway
docker compose up -d --no-build
```

---

## 7. 快速验证

### 7.1 Hybrid/PQC

```bash
docker compose exec -T pq-gateway \
  /opt/openssl/bin/openssl s_client \
  -connect localhost:8443 \
  -servername bank-gateway.local \
  -tls1_3 \
  -groups X25519MLKEM768 \
  -CAfile /etc/pq-gateway/certs/ca.crt \
  -brief < /dev/null
```

### 7.2 X25519 回退

```bash
docker compose exec -T pq-gateway \
  /opt/openssl/bin/openssl s_client \
  -connect localhost:8443 \
  -servername bank-gateway.local \
  -tls1_3 \
  -groups X25519 \
  -CAfile /etc/pq-gateway/certs/ca.crt \
  -brief < /dev/null
```

### 7.3 严格模式拒绝 X25519

```bash
docker compose exec -T pq-gateway \
  /opt/openssl/bin/openssl s_client \
  -connect localhost:9443 \
  -servername strict-gateway.local \
  -tls1_3 \
  -groups X25519 \
  -CAfile /etc/pq-gateway/certs/ca.crt \
  -brief < /dev/null
```

预期出现 TLS handshake failure 或 alert 40。

### 7.4 HTTP 透明代理

```bash
curl --noproxy '*' \
  --resolve bank-gateway.local:8443:127.0.0.1 \
  --cacert certs/ca.crt \
  https://bank-gateway.local:8443/service-info
```

---

## 8. 一键完整实验

镜像已经构建后：

```bash
./scripts/run_full_experiment.sh
```

需要重新构建：

```bash
BUILD=1 ./scripts/run_full_experiment.sh
```

`BUILD=1` 同样默认使用 WSL 代理构建，不调用普通 `docker compose build`。

性能配置：

```bash
PERF_PROFILE=quick ./scripts/run_full_experiment.sh
PERF_PROFILE=standard ./scripts/run_full_experiment.sh
PERF_PROFILE=stress ./scripts/run_full_experiment.sh
```

完整实验默认使用 `standard`。

成功标志：

```text
All v3.2 experiments completed: experiment-results/<UTC时间戳>
```

并生成：

```text
experiment-results/<UTC时间戳>/
├── experiment-status.json
├── SUMMARY.md
├── mtls/mtls-matrix.json
├── upstream/upstream-tls-matrix.json
├── stream/stream-protocol-matrix.json
├── crypto-inventory.json
├── tls-inventory.json
├── cmdb-targets.json
├── network-discovery.json
├── continuous-scan-latest.json
├── continuous-scan-diff.json
├── risk-report.json
├── inventory.db
├── migration-verification.json
├── runtime-fallback-report.json
├── experiment-fallback-report.json
└── performance/
    ├── performance-report.json
    ├── performance-summary.csv
    ├── PERFORMANCE.md
    └── docker-stats.jsonl
```

检查状态：

```bash
latest="$(ls -1dt experiment-results/*/ | head -1)"
cat "$latest/experiment-status.json"
cat "$latest/SUMMARY.md"
```

---

## 9. mTLS 实验矩阵

单独运行：

```bash
make mtls-test
```

覆盖：

| 测试 | 预期 |
|---|---|
| client auth off，无证书 | 成功 |
| optional，无证书 | 成功 |
| optional，有效证书 | 成功 |
| optional，错误 CA 证书 | 拒绝 |
| required，无证书 | 拒绝 |
| required，有效证书 | 成功 |
| required，错误 CA 证书 | 拒绝 |

---

## 10. 上游 HTTPS 与 mTLS

单独运行：

```bash
make upstream-test
```

验证：

- 网关校验上游 CA；
- 网关发送 `upstream-secure.local` SNI；
- 网关使用上游客户端证书；
- 上游强制验证网关客户端证书；
- 错误 CA 导致 502；
- 缺少上游客户端证书导致 502；
- 更换同一 CA 签发的新上游证书后服务恢复正常。

---

## 11. MQTT、TCP 与遗留协议

```bash
make stream-test
```

验证：

- MQTT TLS 握手和发布/订阅；
- 通用 TCP TLS echo；
- 非 HTTP 行协议的 `PING`、`VERSION` 和 `QUIT`；
- 三个入口均支持 `X25519MLKEM768`。

接入真实系统时，使用统一服务模型：

```json
{
  "id": "database-tls-entry",
  "adapter": "postgres",
  "listen": {
    "address": "0.0.0.0",
    "port": 25432,
    "server_name": "database-gateway.local"
  },
  "downstream_tls": {
    "mode": "compatibility",
    "groups": ["X25519MLKEM768", "X25519"],
    "client_auth": "required"
  },
  "upstream": {
    "address": "postgres.internal:5432",
    "tls": {"enabled": false, "verify": "off"}
  }
}
```

适用于数据库、消息队列、设备协议和其他 TCP 系统。协议本身仍由后端处理。

---

## 12. 批量端点和 CMDB 导入

### 12.1 批量目标

编辑：

```text
config/scan-targets.json
```

格式：

```json
{
  "targets": [
    {
      "asset_id": "api-001",
      "host": "10.10.1.20",
      "port": 443,
      "sni": "api.internal",
      "protocol": "https",
      "owner": "api-team",
      "environment": "production",
      "criticality": "high"
    }
  ]
}
```

### 12.2 CMDB 导入

```bash
PYTHONPATH=scanner python3 scanner/cmdb_import.py \
  --input config/cmdb/sample-assets.csv \
  --out-json cmdb-targets.json \
  --out-csv cmdb-targets.csv
```

支持 CSV 和 JSON，可重复提供 `--input`。

---

## 13. CIDR 网段发现

只扫描明确授权的企业网段：

```bash
PYTHONPATH=scanner python3 scanner/network_discovery.py \
  --cidr 10.10.0.0/24 \
  --cidr 10.20.0.0/24 \
  --ports 443,8443,8883,9443 \
  --max-hosts 1024 \
  --workers 64 \
  --timeout 1.5 \
  --out-json discovered-endpoints.json \
  --out-csv discovered-endpoints.csv
```

`--max-hosts` 防止误展开过大的网段。

---

## 14. 在线 TLS 扫描

网关容器内使用 OpenSSL 3.5：

```bash
make tls-scan
```

批量调用：

```bash
docker compose exec -T pq-gateway \
  python3 /workspace/scanner/tls_scanner.py \
  --targets-file /etc/pq-gateway/config/scan-targets.json \
  --groups X25519MLKEM768:X25519 \
  --openssl /opt/openssl/bin/openssl \
  --cafile /etc/pq-gateway/certs/ca.crt \
  --workers 16 \
  --allow-unreachable \
  --out-json /tmp/tls-inventory.json \
  --out-csv /tmp/tls-inventory.csv
```

扫描器也支持：

```text
--endpoint HOST:PORT,SNI,PROTOCOL
--targets-file targets.json
--cmdb-file cmdb.csv
--discovery-file discovered.json
```

---

## 15. 定时持续扫描

启动扫描调度器：

```bash
make continuous-scan
```

等价于：

```bash
docker compose --profile continuous-scan up -d scanner-scheduler
```

配置：

```text
config/continuous-scan.json
```

结果：

```text
runtime-data/scans/
├── latest.json
└── <时间戳>/
    ├── tls-inventory.json
    ├── tls-inventory.csv
    └── diff.json
```

`diff.json` 标记新增、删除和能力变化，例如：

- 新证书；
- PQC group 被移除；
- X25519 fallback 被重新启用；
- 端点不可达；
- 证书指纹变化。

---

## 16. 持久化回退指标

查看：

```bash
make metrics
```

或：

```bash
cat runtime-data/metrics/current.json
cat runtime-data/metrics/pqc_gateway.prom
```

重新生成：

```bash
python3 manager/fallback_report.py \
  --log runtime-data/logs/access.log \
  --log runtime-data/logs/stream-access.log \
  --out runtime-fallback-report.json
```

最近 24 小时：

```bash
python3 manager/fallback_report.py \
  --log runtime-data/logs/access.log \
  --log runtime-data/logs/stream-access.log \
  --since-hours 24 \
  --out fallback-last-24h.json
```

---

## 17. 完整性能测试

```bash
make performance
```

或：

```bash
PERF_PROFILE=standard \
  ./scripts/run_performance_suite.sh experiment-results/performance-manual
```

测试内容：

- Hybrid 与 X25519 握手延迟；
- 严格 Hybrid 握手；
- HTTP Hybrid 与 X25519 往返延迟；
- TCP Hybrid 与 X25519 往返延迟；
- 遗留协议 Hybrid 往返；
- MQTT 在 `X25519MLKEM768` 与 `X25519` 下的 QoS-0 往返延迟和吞吐量；
- 兼容 MQTT 客户端的批量发布/订阅基线；
- 多并发成功率；
- P50、P95、P99；
- 每秒操作数；
- 网关与后端容器 CPU、内存采样。

配置：

| Profile | 说明 |
|---|---|
| `quick` | 快速回归 |
| `standard` | 默认完整实验 |
| `stress` | 较高连接量与并发 |

这些结果属于端到端工程测试，包含进程启动、容器调度和网络开销，不等同于纯密码算法 micro-benchmark。

---

## 18. SQLite 查看

```bash
sudo apt install -y sqlite3
latest="$(ls -1dt experiment-results/*/ | head -1)"
sqlite3 "$latest/inventory.db" ".tables"
```

查看资产：

```bash
sqlite3 -header -column "$latest/inventory.db" \
  "SELECT asset_id,asset_type,algorithm,key_bits,risk,path FROM assets;"
```

查看端点：

```bash
sqlite3 -header -column "$latest/inventory.db" \
  "SELECT name,host,port,sni,application_protocol,pqc_supported,fallback_enabled,owner,environment FROM endpoints;"
```

查看 CMDB：

```bash
sqlite3 -header -column "$latest/inventory.db" \
  "SELECT asset_id,name,host,port,protocol,owner,environment,criticality FROM cmdb_assets;"
```

---

## 19. 添加新服务

HTTP/HTTPS：

```bash
python3 manager/generate_service_config.py \
  --id legacy-api \
  --adapter http \
  --listen 17443 \
  --server-name legacy-api.local \
  --upstream https://legacy-api.internal:443 \
  --upstream-tls-verify required \
  --upstream-sni legacy-api.internal \
  --mode compatibility
```

TCP/消息队列/遗留协议：

```bash
python3 manager/generate_service_config.py \
  --id kafka-entry \
  --adapter kafka \
  --listen 19093 \
  --server-name kafka-gateway.local \
  --upstream kafka.internal:9092 \
  --mode compatibility
```

验证并创建不可变发布版本：

```bash
make validate-config
make config-apply
make config-history
```

网关代理检测到期望版本后会依次执行静态校验、`nginx -t`、原子替换、reload 和健康检查；失败时恢复上一个活动配置。

回滚会基于历史版本创建一个新的、可审计的发布版本，而不会修改历史记录：

```bash
make config-rollback VERSION=1
```

控制面 API：

```bash
export MANAGER_API_TOKEN='replace-with-a-random-secret'
make control-plane
curl -H "Authorization: Bearer $MANAGER_API_TOKEN" http://127.0.0.1:18080/v1/configs
curl http://127.0.0.1:18080/metrics

python3 manager/pqctl.py service list
python3 manager/pqctl.py agent list
python3 manager/pqctl.py metrics prometheus
```

完整说明见 `docs/service-model.md` 和 `docs/control-plane.md`。

---

## 20. 项目边界

v3.2 已提供单节点控制面运行时与安全发布闭环，但仍是框架原型，不是生产网关成品。生产化仍需：

- 银行或企业 PKI；
- HSM/KMS；
- 密钥轮换与吊销；
- 高可用与负载均衡；
- 多节点配置共识与滚动发布；
- WAF、DDoS、限流；
- SIEM 和审计留存；
- 大规模 CMDB/证书平台集成；
- 经授权的生产网段扫描策略；
- 针对实际数据库、Kafka、RabbitMQ、MQTT 和专有协议的兼容性测试。

项目不会解析或实现具体金融业务，也不会替代应用层报文签名迁移。
