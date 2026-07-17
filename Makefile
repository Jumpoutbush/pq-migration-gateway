SHELL := /usr/bin/env bash
IMAGE := pq-migration-gateway-pq-gateway:3.6
WSL_PROXY ?= http://127.0.0.1:7897
INIT_ARGS ?=
ENTERPRISE_COMPOSE := deploy/enterprise/docker-compose.yml
ENTERPRISE_ENV := .env.enterprise
SCAN_ROOT ?= $(CURDIR)
SERVER_NAME ?= pqc-gateway.local
LISTEN_PORT ?= 8443

.PHONY: init certs validate-config config-apply config-history config-rollback control-plane agents control-metrics build up down logs test unit-test mtls-test upstream-test stream-test inventory enterprise-inventory enterprise-scan-test scan-migration-api-test api-first-test cmdb-import discover tls-scan continuous-scan metrics performance experiment enterprise-init enterprise-onboard enterprise-api-onboard enterprise-capabilities enterprise-validate enterprise-apply enterprise-history enterprise-rollback enterprise-up enterprise-down enterprise-status enterprise-logs enterprise-scan enterprise-assets enterprise-audit dashboard-up dashboard-down clean zip

init:
	./init_system.sh $(INIT_ARGS)

enterprise-init:
	./scripts/init_enterprise.sh --scan-root "$(SCAN_ROOT)" --server-name "$(SERVER_NAME)" --listen-port "$(LISTEN_PORT)"

enterprise-onboard:
	python3 manager/pqctl.py onboard

enterprise-api-onboard:
	@test -n "$(SERVICE_FILE)" || (echo "usage: make enterprise-api-onboard SERVICE_FILE=service.json" >&2; exit 2)
	@test -s $(ENTERPRISE_ENV) || (echo "$(ENTERPRISE_ENV) is missing" >&2; exit 2)
	set -a;source $(ENTERPRISE_ENV);set +a;python3 manager/pqapi.py onboard --file "$(SERVICE_FILE)"

enterprise-capabilities:
	@test -s $(ENTERPRISE_ENV) || (echo "$(ENTERPRISE_ENV) is missing" >&2; exit 2)
	set -a;source $(ENTERPRISE_ENV);set +a;python3 manager/pqapi.py capabilities

enterprise-validate:
	@test -s $(ENTERPRISE_ENV) || (echo "run 'make enterprise-init SCAN_ROOT=/path/to/apps' first" >&2; exit 2)
	python3 scripts/render_gateway_config.py --config config/enterprise/services.json --output /tmp/pq-gateway-enterprise-nginx.conf --check

enterprise-apply: enterprise-validate
	set -a;source $(ENTERPRISE_ENV);set +a;python3 manager/pqapi.py release publish --file config/enterprise/services.json

enterprise-history:
	@test -s $(ENTERPRISE_ENV) || (echo "$(ENTERPRISE_ENV) is missing" >&2; exit 2)
	set -a;source $(ENTERPRISE_ENV);set +a;python3 manager/pqapi.py release list

enterprise-rollback:
	@test -n "$(VERSION)" || (echo "usage: make enterprise-rollback VERSION=<version>" >&2; exit 2)
	@test -s $(ENTERPRISE_ENV) || (echo "$(ENTERPRISE_ENV) is missing" >&2; exit 2)
	set -a;source $(ENTERPRISE_ENV);set +a;python3 manager/pqapi.py release rollback $(VERSION)

enterprise-up: enterprise-validate
	@docker image inspect $(IMAGE) >/dev/null 2>&1 || (echo "enterprise image is missing; run 'make build' first" >&2; exit 2)
	set -a;source $(ENTERPRISE_ENV);set +a;docker compose --env-file $(ENTERPRISE_ENV) -f $(ENTERPRISE_COMPOSE) up -d gateway manager-api metrics-agent
	@for attempt in $$(seq 1 60);do curl -fsS http://127.0.0.1:18080/healthz >/dev/null && break;sleep 1;done;curl -fsS http://127.0.0.1:18080/healthz >/dev/null
	@if [[ ! -s runtime-data/enterprise/control/desired.json ]];then \
	  set -a;source $(ENTERPRISE_ENV);set +a;python3 manager/pqapi.py release publish --file config/enterprise/services.json; \
	fi

enterprise-down:
	@test -s $(ENTERPRISE_ENV) || (echo "$(ENTERPRISE_ENV) is missing" >&2; exit 2)
	docker compose --env-file $(ENTERPRISE_ENV) -f $(ENTERPRISE_COMPOSE) --profile observability down

enterprise-status:
	@test -s $(ENTERPRISE_ENV) || (echo "$(ENTERPRISE_ENV) is missing" >&2; exit 2)
	docker compose --env-file $(ENTERPRISE_ENV) -f $(ENTERPRISE_COMPOSE) --profile observability ps
	set -a;source $(ENTERPRISE_ENV);set +a;python3 manager/pqapi.py status

enterprise-logs:
	@test -s $(ENTERPRISE_ENV) || (echo "$(ENTERPRISE_ENV) is missing" >&2; exit 2)
	docker compose --env-file $(ENTERPRISE_ENV) -f $(ENTERPRISE_COMPOSE) logs -f gateway manager-api metrics-agent

enterprise-scan:
	@test -s $(ENTERPRISE_ENV) || (echo "$(ENTERPRISE_ENV) is missing" >&2; exit 2)
	set -a;source $(ENTERPRISE_ENV);set +a;python3 manager/pqapi.py scan create --root /workspace/project

enterprise-assets:
	@test -s $(ENTERPRISE_ENV) || (echo "$(ENTERPRISE_ENV) is missing" >&2; exit 2)
	set -a;source $(ENTERPRISE_ENV);set +a;python3 manager/pqapi.py asset list

enterprise-audit:
	@test -s $(ENTERPRISE_ENV) || (echo "$(ENTERPRISE_ENV) is missing" >&2; exit 2)
	set -a;source $(ENTERPRISE_ENV);set +a;python3 manager/pqapi.py audit

dashboard-up: enterprise-up
	docker compose --env-file $(ENTERPRISE_ENV) -f $(ENTERPRISE_COMPOSE) --profile observability up -d prometheus grafana
	@echo "Grafana: http://127.0.0.1:3000 (user: admin; password: GRAFANA_ADMIN_PASSWORD in $(ENTERPRISE_ENV))"
	@echo "Prometheus: http://127.0.0.1:9090"

dashboard-down:
	@test -s $(ENTERPRISE_ENV) || (echo "$(ENTERPRISE_ENV) is missing" >&2; exit 2)
	docker compose --env-file $(ENTERPRISE_ENV) -f $(ENTERPRISE_COMPOSE) --profile observability stop grafana prometheus

certs:
	./certs/gen-classic-demo-certs.sh ./certs

validate-config:
	python3 scripts/render_gateway_config.py --config config/services.json --output /tmp/pq-gateway-v3-nginx.conf --check

config-apply:
	python3 manager/pqctl.py config apply --file config/services.json

config-history:
	python3 manager/pqctl.py config history

config-rollback:
	@test -n "$(VERSION)" || (echo "usage: make config-rollback VERSION=<version>" >&2; exit 2)
	python3 manager/pqctl.py config rollback $(VERSION)

control-plane:
	docker compose --profile control-plane up -d manager-api

agents:
	python3 manager/pqctl.py agent list

control-metrics:
	python3 manager/pqctl.py metrics prometheus

# Default build path for this project: WSL host networking and proxy build args.
build:
	docker build \
	  --network=host \
	  --build-arg OPENSSL_VERSION=3.5.0 \
	  --build-arg NGINX_VERSION=1.28.0 \
	  --build-arg MAKE_JOBS=4 \
	  --build-arg HTTP_PROXY=$(WSL_PROXY) \
	  --build-arg HTTPS_PROXY=$(WSL_PROXY) \
	  --build-arg http_proxy=$(WSL_PROXY) \
	  --build-arg https_proxy=$(WSL_PROXY) \
	  --build-arg NO_PROXY=localhost,127.0.0.1,::1 \
	  --build-arg no_proxy=localhost,127.0.0.1,::1 \
	  -f docker/Dockerfile.gateway \
	  -t $(IMAGE) .

up: validate-config
	@test -s certs/server.crt -a -s certs/server.key -a -s certs/ca.crt \
	  -a -s certs/upstream/ca.crt -a -s certs/upstream/server.crt \
	  -a -s certs/upstream/server.key -a -s certs/upstream/client.crt \
	  -a -s certs/upstream/client.key || \
	  (echo "demo PKI is missing; run 'make init' or 'make certs' first" >&2; exit 2)
	docker compose up -d --no-build --force-recreate

down:
	docker compose down

logs:
	docker compose logs -f pq-gateway bank-backend secure-backend tcp-backend legacy-backend mqtt-broker metrics-agent

test:
	curl --noproxy '*' --resolve bank-gateway.local:8443:127.0.0.1 --cacert certs/ca.crt https://bank-gateway.local:8443/service-info

unit-test:
	python3 -m unittest discover -s tests -v

mtls-test:
	./scripts/test_mtls_matrix.sh experiment-results/manual-mtls

upstream-test:
	./scripts/test_upstream_tls.sh experiment-results/manual-upstream

stream-test:
	./scripts/test_stream_protocols.sh experiment-results/manual-stream

inventory:
	python3 scripts/crypto_inventory.py --root ./certs --root ./gateway --root ./backend --root ./config --root ./docker-compose.yml --root ./scripts --root ./scanner --root ./manager --out-json crypto-inventory.json --out-csv crypto-inventory.csv

enterprise-inventory:
	python3 scripts/crypto_inventory.py --root /opt --root /usr/local --root /etc --scan-processes --proc-root /proc --out-json enterprise-crypto-inventory.json --out-csv enterprise-crypto-inventory.csv

enterprise-scan-test:
	python3 scripts/test_enterprise_scanner.py experiment-results/manual-enterprise-scan

scan-migration-api-test:
	python3 scripts/test_scan_migration_api.py experiment-results/manual-scan-migration-api

api-first-test:
	python3 scripts/test_api_first_workflow.py experiment-results/manual-api-first

cmdb-import:
	PYTHONPATH=scanner python3 scanner/cmdb_import.py --input config/cmdb/sample-assets.csv --out-json cmdb-targets.json --out-csv cmdb-targets.csv

discover:
	PYTHONPATH=scanner python3 scanner/network_discovery.py --cidr 127.0.0.1/32 --ports 8443,9443,10443,11443,12443,13443,14443,8883,15443,16443 --out-json network-discovery.json --out-csv network-discovery.csv

tls-scan:
	docker compose exec -T pq-gateway python3 /workspace/scanner/tls_scanner.py --targets-file /etc/pq-gateway/config/scan-targets.json --groups X25519MLKEM768:X25519 --openssl /opt/openssl/bin/openssl --cafile /etc/pq-gateway/certs/ca.crt --workers 10 --allow-unreachable --out-json /tmp/tls-inventory.json --out-csv /tmp/tls-inventory.csv
	docker cp pq-gateway:/tmp/tls-inventory.json ./tls-inventory.json
	docker cp pq-gateway:/tmp/tls-inventory.csv ./tls-inventory.csv

continuous-scan:
	docker compose --profile continuous-scan up -d scanner-scheduler

metrics:
	cat runtime-data/metrics/current.json
	cat runtime-data/metrics/pqc_gateway.prom

performance:
	PERF_PROFILE=standard ./scripts/run_performance_suite.sh experiment-results/manual-performance

experiment:
	./scripts/run_full_experiment.sh

experiment-latest:
	./scripts/run_full_experiment.sh --latest

clean:
	rm -f certs/*.crt certs/*.key certs/*.csr certs/*.srl certs/*.ext
	rm -rf certs/upstream certs/untrusted certs/mldsa-demo
	rm -f crypto-inventory.json crypto-inventory.csv enterprise-crypto-inventory.json enterprise-crypto-inventory.csv tls-inventory.json tls-inventory.csv risk-report.json cmdb-targets.json cmdb-targets.csv network-discovery.json network-discovery.csv
	rm -rf experiment-results runtime-data/logs/*.log runtime-data/metrics/* runtime-data/scans/*
	rm -rf runtime-data/control/*
	touch runtime-data/logs/.gitkeep runtime-data/metrics/.gitkeep runtime-data/scans/.gitkeep runtime-data/control/.gitkeep

zip:
	cd .. && zip -r pq-migration-gateway-v3.6.0.zip pq-migration-gateway-v3 \
	  -x '*/.git/*' '*/experiment-results/*' '*/runtime-data/logs/*.log' \
	     '*/runtime-data/metrics/*' '*/runtime-data/scans/*' '*/runtime-data/control/*' \
	     '*/certs/*.key' '*/certs/*.crt' '*/certs/*.csr' '*/certs/*.srl' \
	     '*/certs/**/*.key' '*/certs/**/*.crt' '*/certs/**/*.csr' '*/certs/**/*.srl' \
	     '*/runtime-data/enterprise/*' '*/config/enterprise/services.json' \
	     '*/outputs/*' '*/__pycache__/*' '*.pyc' '*/.env' '*/.env.enterprise'
