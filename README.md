# PQC Migration Gateway

一个面向存量银行服务的后量子迁移网关原型。项目使用 **NGINX 1.28.0 + OpenSSL 3.5.0**，在不修改后端业务代码的情况下，为客户端入口提供 TLS 1.3 Hybrid/PQC 密钥交换，并集成密码资产扫描与握手性能测试。

当前默认保持兼容迁移配置：

```yaml
TLS_GROUPS: "X25519MLKEM768:X25519"
```

含义是：支持 PQC 的客户端优先使用 `X25519MLKEM768`，传统客户端可以回退到 `X25519`。

```text
客户端
  |
  | TLS 1.3
  | X25519MLKEM768 或 X25519
  v
+--------------------------------+
| PQC Migration Gateway          |
| NGINX + OpenSSL 3.5            |
+--------------------------------+
  |
  | HTTP 或传统 HTTPS
  v
存量银行服务
```

## 1. 当前支持功能

### 后量子迁移网关

- TLS 1.3 服务入口；
- `X25519MLKEM768` Hybrid/PQC 密钥交换；
- `X25519` 经典客户端回退；
- RSA-3072 演示证书链；
- 可选客户端证书认证（mTLS）；
- HTTP 或 HTTPS 后端反向代理；
- JSON 格式访问日志；
- 后端业务系统无需实现 PQC。

当前已验证：

| 实验                       | 结果 |
| -------------------------- | ---- |
| TLS 1.3 + `X25519MLKEM768` | 成功 |
| TLS 1.3 + `X25519`         | 成功 |
| RSA 服务端证书验证         | 成功 |
| NGINX 到模拟银行后端转发   | 成功 |
| Docker Compose 部署        | 成功 |

当前迁移状态：

```text
TLS 密钥交换层：已支持 Hybrid/PQC
证书认证层：仍使用 RSA
后端业务层：保持原有 HTTP/HTTPS 架构
```

### 密码资产扫描

`scripts/crypto_inventory.py` 当前支持扫描：

- X.509 证书；
- 私钥文件；
- RSA、ML-DSA 等算法引用；
- TLS 和 NGINX 配置；
- Shell、Compose 等文本配置；
- 风险等级和量子安全状态；
- JSON 和 CSV 报告输出。

### 实验工具

- `tls_probe.py`：检查 TLS 版本、证书和协商 group；
- `bench_handshake.py`：比较不同 TLS group 的握手性能；
- `crypto_inventory.py`：生成密码资产清单；
- `run_full_experiment.sh`：自动执行完整实验并保存结果。

---

## 2. 启动项目与运行实验

### 2.1 环境要求

- Ubuntu 24.04；
- Docker Engine；
- Docker Compose V2；
- Git、Make、Python 3 和 curl。

安装基础工具：

```bash
sudo apt update
sudo apt install -y ca-certificates curl git make unzip python3 docker.io docker-compose-v2

sudo usermod -aG docker "$USER"
newgrp docker

docker version
docker compose version
```

已经安装 Docker 和 Compose 的环境可以跳过此步骤。

### 2.2 首次启动

进入项目目录：

```bash
cd ~/wkspace/pq-migration-gateway
```

生成演示证书：

```bash
make certs
```

标准网络环境下构建并启动：

```bash
make build
make up
```

检查服务状态：

```bash
docker compose ps
```

预期：

```text
bank-backend   Up (healthy)
pq-gateway     Up
```

### 2.3 WSL 代理环境构建

Windows HTTP 代理监听在 `127.0.0.1:7897` 时：

```bash
docker build   --network=host   --build-arg OPENSSL_VERSION=3.5.0   --build-arg NGINX_VERSION=1.28.0   --build-arg MAKE_JOBS=4   --build-arg HTTP_PROXY=http://127.0.0.1:7897   --build-arg HTTPS_PROXY=http://127.0.0.1:7897   --build-arg http_proxy=http://127.0.0.1:7897   --build-arg https_proxy=http://127.0.0.1:7897   --build-arg NO_PROXY=localhost,127.0.0.1,::1   --build-arg no_proxy=localhost,127.0.0.1,::1   -f docker/Dockerfile.gateway   -t pq-migration-gateway-pq-gateway   .
```

构建成功后：

```bash
docker compose up -d --no-build
docker compose ps
```

### 2.4 日常启动与停止

镜像和证书已经生成后，机器重启通常只需：

```bash
cd ~/wkspace/pq-migration-gateway
docker compose up -d --no-build
docker compose ps
```

停止项目：

```bash
docker compose down
```

查看日志：

```bash
docker compose logs -f pq-gateway
```

### 2.5 手工验证 Hybrid/PQC TLS

验证 `X25519MLKEM768`：

```bash
docker compose exec pq-gateway   /opt/openssl/bin/openssl s_client   -connect localhost:8443   -servername bank-gateway.local   -tls1_3   -groups X25519MLKEM768   -CAfile /etc/pq-gateway/certs/ca.crt   -brief < /dev/null
```

预期包含：

```text
Protocol version: TLSv1.3
Verification: OK
Negotiated TLS1.3 group: X25519MLKEM768
```

验证 `X25519` 回退：

```bash
docker compose exec pq-gateway   /opt/openssl/bin/openssl s_client   -connect localhost:8443   -servername bank-gateway.local   -tls1_3   -groups X25519   -CAfile /etc/pq-gateway/certs/ca.crt   -brief < /dev/null
```

预期包含：

```text
Protocol version: TLSv1.3
Verification: OK
Peer Temp Key: X25519
```

### 2.6 业务接口测试

健康检查：

```bash
curl --resolve bank-gateway.local:8443:127.0.0.1   --cacert certs/ca.crt   https://bank-gateway.local:8443/healthz
```

余额接口：

```bash
curl --resolve bank-gateway.local:8443:127.0.0.1   --cacert certs/ca.crt   https://bank-gateway.local:8443/api/balance
```

转账接口：

```bash
curl --resolve bank-gateway.local:8443:127.0.0.1   --cacert certs/ca.crt   -H 'Content-Type: application/json'   -d '{"from":"demo-001","to":"demo-002","amount":"100.00","currency":"CNY"}'   https://bank-gateway.local:8443/api/transfer
```

### 2.7 运行完整实验

确保脚本可执行：

```bash
chmod +x scripts/run_full_experiment.sh
```

运行：

```bash
./scripts/run_full_experiment.sh
```

每种 TLS group 执行 100 次握手：

```bash
COUNT=100 ./scripts/run_full_experiment.sh
```

脚本自动执行：

1. 检查 `TLS_GROUPS` 是否为 `X25519MLKEM768:X25519`；
2. 启动现有容器；
3. 验证 Hybrid/PQC 握手；
4. 验证 X25519 回退；
5. 测试健康、余额和转账接口；
6. 运行密码资产扫描；
7. 对两种 TLS group 进行握手性能测试；
8. 保存 OpenSSL、NGINX 和网关日志。

实验结果保存在：

```text
experiment-results/<UTC时间戳>/
```

`.gitignore` 中应包含：

```gitignore
experiment-results/
```

### 2.8 单独运行密码资产扫描

```bash
python3 scripts/crypto_inventory.py   --root ./certs   --root ./gateway   --root ./docker-compose.yml   --out-json crypto-inventory.json   --out-csv crypto-inventory.csv
```

### 2.9 单独运行握手性能测试

Hybrid/PQC：

```bash
docker compose exec pq-gateway   python3 /workspace/scripts/bench_handshake.py   --host pq-gateway   --port 8443   --sni bank-gateway.local   --groups X25519MLKEM768   --openssl /opt/openssl/bin/openssl   --cafile /etc/pq-gateway/certs/ca.crt   --count 50   --out /tmp/handshake-hybrid.json
```

经典对照：

```bash
docker compose exec pq-gateway   python3 /workspace/scripts/bench_handshake.py   --host pq-gateway   --port 8443   --sni bank-gateway.local   --groups X25519   --openssl /opt/openssl/bin/openssl   --cafile /etc/pq-gateway/certs/ca.crt   --count 50   --out /tmp/handshake-x25519.json
```

---

## 3. 后续改进方向

### 密码资产扫描

- 区分真实资产、配置引用和源码证据；
- 对证书、私钥和配置进行去重关联；
- 准确识别 RSA、ECDSA、ML-DSA、SLH-DSA 和 Hybrid group；
- 增加在线 TLS 端点扫描；
- 检测实际协商 group 和经典回退；
- 支持 Java KeyStore、PKCS#12、SSH、VPN/IKEv2；
- 接入 HSM、KMS、CMDB、证书平台和 SBOM/CBOM；
- 增加业务 owner、数据生命周期和迁移优先级。

### 迁移网关

- 完成 RSA mTLS 全流程测试；
- 测试 ML-DSA 服务端和客户端证书；
- 支持后端 HTTPS 和后端 mTLS；
- 增加按域名、客户端和接口的迁移策略；
- 增加 fallback 统计、告警和审计报表；
- 支持配置热更新、灰度部署和回滚；
- 增加高可用、限流、WAF 和监控指标；
- 接入银行 PKI、HSM/KMS 和证书生命周期平台。

### 性能评估

- 固定 CPU 和运行环境；
- 分别测量 X25519 与 X25519MLKEM768；
- 输出平均值、标准差、P50、P95 和 P99；
- 测量 CPU、内存、并发连接和握手吞吐量；
- 区分 TLS 握手、证书验证、代理转发和后端处理耗时；
- 对比 RSA 与 ML-DSA 证书链的性能和兼容性。

---

## 项目边界

本项目当前是可运行的后量子迁移工程原型，不是银行生产系统成品。

当前已完成：

```text
静态密码资产发现
        +
TLS 1.3 Hybrid/PQC KEX
        +
经典客户端回退
        +
存量后端反向代理
        +
自动化实验
```

生产部署前仍需补齐 PKI、HSM/KMS、高可用、审计、监管合规和完整安全测试。