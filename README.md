# PQC Migration Gateway v2

一个与具体业务无关的后量子迁移原型。它通过标准 TLS 和反向代理接口接入现有系统，不解析或修改业务报文。默认使用 **NGINX 1.28.0 + OpenSSL 3.5.0**。

## 1. 当前支持功能

### 通用迁移网关

- TLS 1.3 Hybrid/PQC 密钥交换：`X25519MLKEM768`；
- 兼容回退：`X25519MLKEM768:X25519`；
- 严格模式：只允许 `X25519MLKEM768`；
- 多域名、多端口、多上游系统配置；
- HTTP/HTTPS 上游反向代理；
- `off`、`optional`、`required` 三种 mTLS 策略；
- 每个服务独立配置 TLS group、证书和上游校验策略；
- JSON 访问日志记录实际协商 group 和回退情况；
- 后端业务代码无需实现 PQC。

默认配置在 `config/services.json`，自带两个测试入口：

|入口|模式|端口|
|---|---|---:|
|`bank-gateway.local`|兼容模式|8443|
|`strict-gateway.local`|Hybrid/PQC 严格模式|9443|

### 密码资产发现与迁移管理

- 静态扫描证书、私钥、TLS 配置和源码引用；
- 区分真实资产与源码/配置证据；
- 为资产和证据生成稳定 ID，避免重复计数；
- 识别 RSA 私钥，但不保存私钥模数或其他敏感内容；
- 在线扫描 TLS 版本、证书、Hybrid/PQC 支持和经典回退；
- 风险评估和迁移建议；
- SQLite 统一资产库；
- 根据扫描结果验证配置是否达到迁移策略；
- 从 NGINX 日志统计 Hybrid/PQC 使用率和 X25519 回退率；
- 自动生成完整实验结果目录和总结报告。

主要工具：

```text
scripts/crypto_inventory.py       静态密码资产扫描
scanner/tls_scanner.py            在线 TLS 扫描
manager/risk_engine.py            风险评估
manager/inventory_db.py           SQLite 资产库
manager/generate_service_config.py 服务配置生成
manager/verify_migration.py       迁移策略验证
manager/fallback_report.py        回退统计
scripts/run_full_experiment.sh    一键实验
```

## 2. 编译、启动与实验

### 2.1 环境准备

Ubuntu 24.04：

```bash
sudo apt update
sudo apt install -y ca-certificates curl git make unzip python3 docker.io docker-compose-v2
sudo usermod -aG docker "$USER"
newgrp docker

docker version
docker compose version
```

### 2.2 配置接入系统

编辑 `config/services.json`，每个系统只需提供监听信息和上游地址：

```json
{
  "name": "system-a",
  "listen_port": 10443,
  "server_name": "system-a.local",
  "upstream_url": "https://10.10.10.20:443",
  "tls_groups": "X25519MLKEM768:X25519",
  "client_auth": "off",
  "upstream_tls_verify": "on"
}
```

也可以用命令添加或更新服务：

```bash
python3 manager/generate_service_config.py \
  --config config/services.json \
  --name system-a \
  --listen 10443 \
  --server-name system-a.local \
  --upstream https://10.10.10.20:443 \
  --mode compatibility \
  --client-auth off \
  --upstream-tls-verify on
```

新增端口后，还需在 `docker-compose.yml` 的 `ports` 中增加对应映射。

检查配置：

```bash
make validate-config
```

### 2.3 首次构建和启动

```bash
cd ~/wkspace/pq-migration-gateway
make certs
make build
make up

docker compose ps
```

WSL 使用 Windows 代理 `127.0.0.1:7897` 时：

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
  -t pq-migration-gateway-pq-gateway:2.0 .

docker compose up -d --no-build --force-recreate
```

机器重启后通常只需：

```bash
docker compose up -d --no-build
```

### 2.4 手工验证

兼容入口的 Hybrid/PQC 握手：

```bash
docker compose exec -T pq-gateway \
  /opt/openssl/bin/openssl s_client \
  -connect localhost:8443 \
  -servername bank-gateway.local \
  -tls1_3 -groups X25519MLKEM768 \
  -CAfile /etc/pq-gateway/certs/ca.crt \
  -brief < /dev/null
```

兼容入口的 X25519 回退：

```bash
docker compose exec -T pq-gateway \
  /opt/openssl/bin/openssl s_client \
  -connect localhost:8443 \
  -servername bank-gateway.local \
  -tls1_3 -groups X25519 \
  -CAfile /etc/pq-gateway/certs/ca.crt \
  -brief < /dev/null
```

严格入口只允许 Hybrid/PQC：

```bash
docker compose exec -T pq-gateway \
  /opt/openssl/bin/openssl s_client \
  -connect localhost:9443 \
  -servername strict-gateway.local \
  -tls1_3 -groups X25519MLKEM768 \
  -CAfile /etc/pq-gateway/certs/ca.crt \
  -brief < /dev/null
```

宿主机访问测试必须绕过本机代理：

```bash
curl --noproxy '*' \
  --resolve bank-gateway.local:8443:127.0.0.1 \
  --cacert certs/ca.crt \
  https://bank-gateway.local:8443/service-info
```

### 2.5 运行完整实验

新版本第一次运行建议重新构建：

```bash
chmod +x scripts/run_full_experiment.sh
BUILD=1 ./scripts/run_full_experiment.sh
```

已有新版本镜像后：

```bash
./scripts/run_full_experiment.sh
```

每组执行 100 次握手：

```bash
COUNT=100 ./scripts/run_full_experiment.sh
```

实验自动完成：

1. 多服务配置校验；
2. 容器构建、启动和健康检查；
3. 兼容入口 Hybrid/PQC 握手；
4. 兼容入口 X25519 回退；
5. 严格入口 Hybrid/PQC 握手；
6. 严格入口拒绝 X25519；
7. 透明反向代理测试；
8. 静态密码资产扫描；
9. 在线 TLS 端点扫描；
10. 风险评估和 SQLite 入库；
11. 迁移策略自动验证；
12. Hybrid/PQC 与回退比例统计；
13. 两种 group 的握手性能测试。

结果保存在：

```text
experiment-results/<UTC时间戳>/
```

核心文件包括：

```text
SUMMARY.md
crypto-inventory.json
crypto-inventory.csv
tls-inventory.json
tls-inventory.csv
risk-report.json
inventory.db
migration-verification.json
fallback-report.json
handshake-hybrid.json
handshake-x25519.json
gateway-access.log
```

## 3. 后续改进方向

- 增加 TCP、数据库、消息队列和更多非 HTTP 协议代理；
- 扩展 Java KeyStore、PKCS#12、SSH、VPN/IKEv2 和 Kubernetes Secret 扫描；
- 接入 CMDB、HSM/KMS、证书生命周期平台和 SBOM/CBOM；
- 支持配置热加载、灰度切换、自动回滚和多实例高可用；
- 增加 Prometheus 指标、Web 管理界面、Webhook 和 SIEM 接口；
- 完成 RSA、ML-DSA 服务端证书和 mTLS 兼容性矩阵；
- 增加并发连接、吞吐量、CPU、内存、P50/P95/P99 性能实验；
- 将扫描、风险评估、配置生成、部署和验证接入 CI/CD。

项目边界：本项目负责密码资产发现、通用 TLS 接入和迁移验证，不实现具体转账、清算或金融报文业务逻辑。
