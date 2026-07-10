SHELL := /usr/bin/env bash
PROJECT_DIR := $(notdir $(CURDIR))

.PHONY: certs validate-config build up up-build up-no-build down logs test probe probe-strict bench inventory tls-scan risk experiment clean zip

certs:
	./certs/gen-classic-demo-certs.sh ./certs

validate-config:
	python3 scripts/render_gateway_config.py --config config/services.json --output /tmp/pq-gateway-nginx.conf --check

build:
	docker compose build pq-gateway

up: certs validate-config
	docker compose up -d --no-build --force-recreate

up-build: certs validate-config
	docker compose up -d --build

up-no-build: up

down:
	docker compose down

logs:
	docker compose logs -f pq-gateway bank-backend

test:
	curl --noproxy '*' --resolve bank-gateway.local:8443:127.0.0.1 --cacert certs/ca.crt https://bank-gateway.local:8443/healthz
	curl --noproxy '*' --resolve bank-gateway.local:8443:127.0.0.1 --cacert certs/ca.crt https://bank-gateway.local:8443/service-info

probe:
	docker compose exec -T pq-gateway /opt/openssl/bin/openssl s_client -connect localhost:8443 -servername bank-gateway.local -tls1_3 -groups X25519MLKEM768 -CAfile /etc/pq-gateway/certs/ca.crt -brief < /dev/null

probe-strict:
	docker compose exec -T pq-gateway /opt/openssl/bin/openssl s_client -connect localhost:9443 -servername strict-gateway.local -tls1_3 -groups X25519MLKEM768 -CAfile /etc/pq-gateway/certs/ca.crt -brief < /dev/null

bench:
	docker compose exec -T pq-gateway python3 /workspace/scripts/bench_handshake.py --host localhost --port 8443 --sni bank-gateway.local --openssl /opt/openssl/bin/openssl --cafile /etc/pq-gateway/certs/ca.crt --groups X25519MLKEM768 --count 20

inventory:
	python3 scripts/crypto_inventory.py --root ./certs --root ./gateway --root ./config --root ./docker-compose.yml --root ./scripts --root ./scanner --root ./manager --out-json crypto-inventory.json --out-csv crypto-inventory.csv

tls-scan:
	docker compose exec -T pq-gateway python3 /workspace/scanner/tls_scanner.py --endpoint localhost:8443,bank-gateway.local --endpoint localhost:9443,strict-gateway.local --openssl /opt/openssl/bin/openssl --cafile /etc/pq-gateway/certs/ca.crt --out-json /tmp/tls-inventory.json --out-csv /tmp/tls-inventory.csv
	docker cp pq-gateway:/tmp/tls-inventory.json ./tls-inventory.json
	docker cp pq-gateway:/tmp/tls-inventory.csv ./tls-inventory.csv

risk:
	python3 manager/risk_engine.py --static crypto-inventory.json --tls tls-inventory.json --out risk-report.json

experiment:
	./scripts/run_full_experiment.sh

clean:
	rm -f certs/*.crt certs/*.key certs/*.csr certs/*.srl certs/*.ext
	rm -f crypto-inventory.json crypto-inventory.csv tls-inventory.json tls-inventory.csv risk-report.json
	rm -rf certs/mldsa-demo experiment-results

zip:
	cd .. && zip -r pq-migration-gateway-v2.zip $(PROJECT_DIR) -x '*/.git/*' '*/experiment-results/*' '*/certs/*.key' '*/certs/*.crt'
