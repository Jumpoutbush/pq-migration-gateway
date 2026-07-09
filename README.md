# PQC Migration Gateway for Banking Services

一个可插入“银行客户端 ↔ 银行服务端”之间的后量子迁移反向代理网关最小工程。

核心目标不是自己实现 ML-KEM / ML-DSA，而是使用 OpenSSL 3.5+ 的标准实现，在服务入口先完成 TLS 1.3 hybrid/PQC 密钥交换迁移，同时让后端银行服务可以暂时保持原有 HTTP/TLS 架构不变。

## 1. 架构定位

```text
银行客户端
  |
  |  TLS 1.3，优先 X25519MLKEM768，可选 mTLS
  v
+------------------------------------------------+
| 后量子迁移网关                                  |
| NGINX + OpenSSL 3.5+                            |
| - 前端 TLS hybrid/PQC KEX                       |
| - 可选客户端证书校验                             |
| - 反向代理到存量银行服务                         |
| - JSON 审计日志                                  |
| - TLS/证书/配置扫描脚本                          |
+------------------------------------------------+
  |
  |  HTTP 或传统 TLS，按存量系统能力配置
  v
银行服务端 / 核心业务系统
```

这个工程适合做三件事：

1. 在不改后端业务代码的情况下，先把客户端入口升级为 hybrid/PQC TLS。
2. 在迁移期保留经典 fallback，逐步识别不支持 PQC 的客户端。
3. 扫描证书、私钥、TLS 配置和源码引用，形成密码资产清单。

## 2. 使用的算法与参数

默认不手写密码算法。算法由 OpenSSL 3.5+ 提供。

| 层次 | 默认配置 | 说明 |
|---|---|---|
| 前端 TLS 协议 | TLS 1.3 only | 网关只暴露 TLS 1.3 |
| 前端 TLS KEX | `X25519MLKEM768:X25519` | 迁移模式：优先 hybrid PQ，允许经典 fallback |
| 严格测试 KEX | `X25519MLKEM768` | 只允许 hybrid PQ；用于验证 PQ-ready 客户端 |
| 默认服务端证书 | RSA-3072 demo cert | 兼容性最高；真实部署应换成银行 PKI 证书 |
| 可选实验签名证书 | `ML-DSA-65` | 需要 OpenSSL 3.5+，用于实验 PQ 证书链 |
| 后端连接 | HTTP 或 HTTPS | 后端可暂时不支持 PQC |

注意：TLS 密钥交换迁移和证书签名迁移是两个不同环节。本工程默认先迁移 TLS KEX，因为它对后端业务系统侵入最小。应用层报文签名、HSM、证书链、客户端 SDK 需要另行迁移。

## 3. 目录结构

```text
pq-migration-gateway/
├── backend/                    # 模拟银行后端服务，无 PQC 依赖
├── certs/                      # demo 证书生成脚本，生成物默认不提交
├── docker/                     # OpenSSL 3.5 + NGINX 网关镜像
├── docs/                       # 架构与部署说明
├── gateway/                    # NGINX 模板与 entrypoint
├── scripts/                    # TLS probe、握手 benchmark、密码资产扫描
├── docker-compose.yml
├── Makefile
└── README.md
```

## 4. Ubuntu 24.04 环境准备

```bash
sudo apt update
sudo apt install -y ca-certificates curl git make unzip docker.io docker-compose-plugin gh
sudo usermod -aG docker "$USER"
newgrp docker

docker version
docker compose version
```

如果不使用 GitHub CLI，可以不安装 `gh`。

## 5. 一键启动 demo

```bash
git clone <your-repo-url> pq-migration-gateway
cd pq-migration-gateway

make certs
make build
make up
```

等容器启动后：

```bash
docker compose ps
```

预期看到：

```text
bank-backend   running / healthy
pq-gateway     running
```

## 6. 普通 HTTPS 访问测试

主机上的 `curl` 未必使用 OpenSSL 3.5，所以这个测试只能证明 HTTPS 反向代理可用，不一定证明协商到了 PQC/hybrid 组。

```bash
curl --resolve bank-gateway.local:8443:127.0.0.1 \
  --cacert certs/ca.crt \
  https://bank-gateway.local:8443/healthz

curl --resolve bank-gateway.local:8443:127.0.0.1 \
  --cacert certs/ca.crt \
  https://bank-gateway.local:8443/api/balance

curl --resolve bank-gateway.local:8443:127.0.0.1 \
  --cacert certs/ca.crt \
  -H 'Content-Type: application/json' \
  -d '{"from":"demo-001","to":"demo-002","amount":"100.00","currency":"CNY"}' \
  https://bank-gateway.local:8443/api/transfer
```

## 7. 强制验证 hybrid/PQC TLS 协商

使用网关容器内的 OpenSSL 3.5 客户端强制 `X25519MLKEM768`：

```bash
docker compose exec pq-gateway \
  /opt/openssl/bin/openssl s_client \
  -connect pq-gateway:8443 \
  -servername bank-gateway.local \
  -tls1_3 \
  -groups X25519MLKEM768 \
  -CAfile /etc/pq-gateway/certs/ca.crt \
  -brief < /dev/null
```

输出中应出现类似字段：

```text
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Server Temp Key: X25519MLKEM768
Verification: OK
```

也可以使用封装好的 probe 脚本：

```bash
docker compose exec pq-gateway \
  python3 /workspace/scripts/tls_probe.py \
  --host pq-gateway \
  --port 8443 \
  --sni bank-gateway.local \
  --groups X25519MLKEM768 \
  --openssl /opt/openssl/bin/openssl \
  --cafile /etc/pq-gateway/certs/ca.crt \
  --json /tmp/tls-probe.json
```

## 8. 切换严格 hybrid-only 模式

默认配置是迁移模式：

```text
TLS_GROUPS=X25519MLKEM768:X25519
```

这表示优先 hybrid PQ，但允许传统 X25519 fallback。要测试强制 hybrid-only：

```bash
TLS_GROUPS=X25519MLKEM768 docker compose up -d --force-recreate pq-gateway
```

或者修改 `docker-compose.yml`：

```yaml
environment:
  TLS_GROUPS: "X25519MLKEM768"
```

然后重启：

```bash
docker compose up -d --force-recreate pq-gateway
```

此时不支持 `X25519MLKEM768` 的客户端应握手失败。这是识别 legacy 客户端的关键测试。

## 9. 启用客户端证书认证 mTLS

默认关闭客户端证书校验：

```yaml
CLIENT_AUTH: "off"
```

可选值：

```text
off       不校验客户端证书
optional  有证书则校验，无证书也放行
required  必须提供有效客户端证书
```

启动 optional mTLS：

```bash
CLIENT_AUTH=optional docker compose up -d --force-recreate pq-gateway
```

启动 required mTLS：

```bash
CLIENT_AUTH=required docker compose up -d --force-recreate pq-gateway
```

使用客户端证书访问：

```bash
curl --resolve bank-gateway.local:8443:127.0.0.1 \
  --cacert certs/ca.crt \
  --cert certs/client.crt \
  --key certs/client.key \
  https://bank-gateway.local:8443/api/balance
```

## 10. 接入真实银行后端服务

如果后端是传统 HTTP：

```yaml
environment:
  UPSTREAM_URL: "http://10.10.10.20:8080"
  UPSTREAM_TLS_VERIFY: "off"
```

如果后端是传统 HTTPS 且需要校验证书：

```yaml
environment:
  UPSTREAM_URL: "https://bank-core.internal:443"
  UPSTREAM_TLS_VERIFY: "on"
  UPSTREAM_CA: "/etc/pq-gateway/certs/upstream-ca.crt"
volumes:
  - ./certs:/etc/pq-gateway/certs:ro
```

然后重启：

```bash
docker compose up -d --force-recreate pq-gateway
```

生产环境不建议关闭后端 TLS 校验。只有本地 demo 或隔离测试环境可以使用 `UPSTREAM_TLS_VERIFY=off`。

## 11. 生成可选 ML-DSA demo 证书

需要 OpenSSL 3.5+。如果主机没有 OpenSSL 3.5，可以复用本工程构建出的网关镜像：

```bash
docker build -t pq-gateway-openssl35 -f docker/Dockerfile.gateway .
docker run --rm \
  -v "$PWD/certs:/certs" \
  --entrypoint sh \
  pq-gateway-openssl35 \
  -lc 'OPENSSL_BIN=/opt/openssl/bin/openssl MLDSA_ALG=ML-DSA-65 /certs/gen-mldsa-demo-certs.sh /certs/mldsa-demo'
```

如果主机已经安装 OpenSSL 3.5+，也可以直接运行：

```bash
OPENSSL_BIN=/path/to/openssl-3.5/bin/openssl \
  MLDSA_ALG=ML-DSA-65 \
  ./certs/gen-mldsa-demo-certs.sh ./certs/mldsa-demo
```

然后在 `docker-compose.yml` 中把证书路径改为：

```yaml
environment:
  GATEWAY_CERT: "/etc/pq-gateway/certs/mldsa-demo/server.crt"
  GATEWAY_KEY: "/etc/pq-gateway/certs/mldsa-demo/server.key"
  CLIENT_CA: "/etc/pq-gateway/certs/mldsa-demo/ca.crt"
```

说明：ML-DSA 证书链仍属于实验性接入场景。真实银行系统要结合浏览器、客户端 SDK、HSM、证书策略、监管要求和兼容性测试决定何时启用。

## 12. 密码资产扫描

扫描当前工程的证书、配置和源码引用：

```bash
python3 scripts/crypto_inventory.py \
  --root ./certs \
  --root ./gateway \
  --root ./docker-compose.yml \
  --out-json crypto-inventory.json \
  --out-csv crypto-inventory.csv
```

扫描系统路径示例：

```bash
sudo python3 scripts/crypto_inventory.py \
  --root /etc/nginx \
  --root /etc/apache2 \
  --root /etc/ssl \
  --out-json bank-host-crypto-inventory.json \
  --out-csv bank-host-crypto-inventory.csv
```

输出字段包括：

| 字段 | 含义 |
|---|---|
| `path` | 资产或引用所在文件 |
| `finding_type` | 证书、私钥、文本配置/源码引用 |
| `algorithm` | 检出的算法或模式 |
| `key_bits` | 密钥位数，能解析时填充 |
| `risk` | `CRITICAL/HIGH/MEDIUM/LOW/INFO` |
| `pq_status` | 是否 quantum-vulnerable 或 PQC/candidate |
| `recommendation` | 迁移建议 |

这个扫描器是迁移原型，不是完整企业级 CASB/CMDB/HSM 发现平台。银行生产环境还应接入：

- HSM/KMS 密钥清单；
- 证书生命周期平台；
- VPN/IKEv2 配置；
- TLS 端口全网扫描；
- Java keystore / PKCS#12；
- SBOM/CBOM；
- 业务系统 owner 和数据生命周期。

## 13. TLS 握手性能测试

同一台机器上比较不同 group 配置：

```bash
docker compose exec pq-gateway \
  python3 /workspace/scripts/bench_handshake.py \
  --host pq-gateway \
  --port 8443 \
  --sni bank-gateway.local \
  --groups X25519MLKEM768 \
  --openssl /opt/openssl/bin/openssl \
  --cafile /etc/pq-gateway/certs/ca.crt \
  --count 50 \
  --out /tmp/handshake-bench.json
```

经典对照：

```bash
docker compose exec pq-gateway \
  python3 /workspace/scripts/bench_handshake.py \
  --host pq-gateway \
  --port 8443 \
  --sni bank-gateway.local \
  --groups X25519 \
  --openssl /opt/openssl/bin/openssl \
  --cafile /etc/pq-gateway/certs/ca.crt \
  --count 50
```

该脚本是工程回归测试，不是严谨密码算法 benchmark。正式性能报告应固定 CPU、关闭频率抖动、隔离网络噪声、区分握手耗时、证书链验证耗时、应用代理耗时和后端耗时。

## 14. 日志与审计

查看网关日志：

```bash
docker compose logs -f pq-gateway
```

访问日志是 JSON，包含：

```json
{
  "ssl_protocol": "TLSv1.3",
  "ssl_cipher": "TLS_AES_256_GCM_SHA384",
  "ssl_curve": "X25519MLKEM768",
  "client_verify": "NONE",
  "upstream_addr": "bank-backend:8080"
}
```

生产中建议把 `/var/log/nginx/access.log` 接入 SIEM，并对 `ssl_curve` 做告警：如果目标端点应为 hybrid/PQ，但出现长期 `X25519`，说明发生 fallback 或客户端未升级。

## 15. GitHub 建库与上传命令

### 15.1 使用 GitHub CLI

```bash
cd pq-migration-gateway

git init
git add .
git commit -m "Initial PQC migration gateway"

gh auth login
gh repo create YOUR_ORG_OR_USER/pq-migration-gateway \
  --private \
  --description "Post-quantum migration gateway prototype for banking services" \
  --source=. \
  --remote=origin \
  --push
```

### 15.2 不使用 GitHub CLI

先在 GitHub 网页创建空仓库，然后：

```bash
cd pq-migration-gateway

git init
git add .
git commit -m "Initial PQC migration gateway"
git branch -M main
git remote add origin git@github.com:YOUR_ORG_OR_USER/pq-migration-gateway.git
git push -u origin main
```

不要提交真实银行证书、私钥、HSM 凭据、生产域名清单或扫描结果。`.gitignore` 已排除 demo 证书生成物和扫描输出，但提交前仍应人工检查：

```bash
git status --ignored
git diff --cached --name-only
```

## 16. 常用运维命令

```bash
# 启动
make up

# 停止
make down

# 查看日志
make logs

# 重新生成 demo 证书
make clean
make certs

# 重新构建网关镜像
docker compose build --no-cache pq-gateway

# 查看 OpenSSL 算法
docker compose exec pq-gateway /opt/openssl/bin/openssl version -a
docker compose exec pq-gateway /opt/openssl/bin/openssl list -kem-algorithms | grep -E 'ML-KEM|MLKEM'
docker compose exec pq-gateway /opt/openssl/bin/openssl list -signature-algorithms | grep -E 'ML-DSA|MLDSA|SLH-DSA'

# 查看 NGINX 编译参数
docker compose exec pq-gateway /opt/nginx/sbin/nginx -V
```

## 17. 生产边界声明

这个工程是“可运行迁移原型”，不是银行生产系统成品。生产化前至少需要补齐：

1. 银行 PKI / 证书生命周期系统接入；
2. HSM/KMS 中密钥生成、存储、签名和审计策略；
3. 双机热备、灰度发布、回滚策略；
4. SIEM、指标、告警和审计报表；
5. API 级鉴权、WAF、限流、DDoS 保护；
6. 客户端 SDK 兼容性矩阵；
7. 监管、等保、商密、FIPS 或本地密码合规验证。

## 18. 参考

- OpenSSL 3.5 release: native support for ML-KEM, ML-DSA, and SLH-DSA.
  <https://openssl-library.org/post/2025-04-08-openssl-35-final-release/>
- OpenSSL 3.5 TLS group documentation: `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`.
  <https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/>
- Open Quantum Safe provider note: OpenSSL 3.5+ has native standardized PQ algorithm families.
  <https://github.com/open-quantum-safe/oqs-provider>
