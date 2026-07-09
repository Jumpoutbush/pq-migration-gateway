SHELL := /usr/bin/env bash

.PHONY: certs build up down logs test probe bench inventory clean zip

certs:
	./certs/gen-classic-demo-certs.sh ./certs

build:
	docker compose build

up: certs
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f pq-gateway bank-backend

test:
	curl --resolve bank-gateway.local:8443:127.0.0.1 --cacert certs/ca.crt https://bank-gateway.local:8443/healthz
	curl --resolve bank-gateway.local:8443:127.0.0.1 --cacert certs/ca.crt https://bank-gateway.local:8443/api/balance

probe:
	docker compose exec pq-gateway /opt/openssl/bin/openssl s_client -connect pq-gateway:8443 -servername bank-gateway.local -tls1_3 -groups X25519MLKEM768 -CAfile /etc/pq-gateway/certs/ca.crt -brief < /dev/null

bench:
	docker compose exec pq-gateway python3 /workspace/scripts/bench_handshake.py --host pq-gateway --port 8443 --sni bank-gateway.local --openssl /opt/openssl/bin/openssl --cafile /etc/pq-gateway/certs/ca.crt --groups X25519MLKEM768 --count 20

inventory:
	python3 scripts/crypto_inventory.py --root ./certs --root ./gateway --root ./docker-compose.yml --out-json crypto-inventory.json --out-csv crypto-inventory.csv

clean:
	rm -f certs/*.crt certs/*.key certs/*.csr certs/*.srl crypto-inventory.json crypto-inventory.csv tls-probe.json handshake-bench.json
	rm -rf certs/mldsa-demo

zip:
	cd .. && zip -r pq-migration-gateway.zip pq-migration-gateway -x 'pq-migration-gateway/.git/*'
