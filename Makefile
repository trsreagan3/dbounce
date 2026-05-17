# dbounce — make targets
#
# `make test`              unit tests only (always runnable, no docker)
# `make test-integration`  build-tag gated integration tests; safe to run
#                          even without engines up — integration tests
#                          SKIP CLEANLY when their target engine is not
#                          reachable
# `make test-integration-clean`
#                          tear down the compose stack + remove volumes
#
# Single-engine iteration loops:
#   `make pg-up`     /  `make pg-down`     /  `make pg-logs`
#   `make mysql-up`  /  `make mysql-down`  /  `make mysql-logs`
#
# All-engines-at-once:
#   `docker compose -f compose.test.yaml up -d` (PG + MySQL together)
#
# See docs/LOCAL-TEST-INFRA.md in iam-roles for the cross-repo plan.

DBOUNCE_TEST_PG_NAME ?= dbounce-test-pg
DBOUNCE_TEST_PG_PORT ?= 5432
DBOUNCE_TEST_PG_PASSWORD ?= test

DBOUNCE_TEST_MYSQL_NAME ?= dbounce-test-mysql
DBOUNCE_TEST_MYSQL_PORT ?= 3306
DBOUNCE_TEST_MYSQL_PASSWORD ?= test
DBOUNCE_TEST_MYSQL_DB ?= dbounce_test

.PHONY: build vet test test-integration test-integration-clean \
	pg-up pg-down pg-logs \
	mysql-up mysql-down mysql-logs

build:
	go build ./...

vet:
	go vet ./...

test:
	go test ./...

# Integration tests are build-tag gated so `go test ./...` never tries
# to run them without an upstream PG / MySQL. The integration tests
# themselves skip-with-message when their engine isn't reachable, so
# this target is safe to run even without any engines up (you'll see
# skips instead of failures).
test-integration:
	go test -tags=integration -timeout 5m ./...

# Tear down the compose stack + volumes. Use this between iteration
# loops to guarantee a clean engine state.
test-integration-clean:
	docker compose -f compose.test.yaml down -v 2>/dev/null || true
	@docker rm -f $(DBOUNCE_TEST_PG_NAME)    2>/dev/null || true
	@docker rm -f $(DBOUNCE_TEST_MYSQL_NAME) 2>/dev/null || true

pg-up:
	@if docker ps -a --format '{{.Names}}' | grep -q '^$(DBOUNCE_TEST_PG_NAME)$$'; then \
		echo "container $(DBOUNCE_TEST_PG_NAME) already exists; removing first"; \
		docker rm -f $(DBOUNCE_TEST_PG_NAME) >/dev/null; \
	fi
	docker run --rm -d \
		--name $(DBOUNCE_TEST_PG_NAME) \
		-p $(DBOUNCE_TEST_PG_PORT):5432 \
		-e POSTGRES_PASSWORD=$(DBOUNCE_TEST_PG_PASSWORD) \
		-e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
		-e POSTGRES_INITDB_ARGS="--auth-host=scram-sha-256" \
		postgres:16
	@echo "waiting for postgres to accept connections..."
	@for i in $$(seq 1 30); do \
		if docker exec $(DBOUNCE_TEST_PG_NAME) pg_isready -U postgres -d postgres >/dev/null 2>&1; then \
			echo "postgres ready on :$(DBOUNCE_TEST_PG_PORT)"; \
			echo "DBOUNCE_INTEGRATION_PG_URL=postgres://postgres:$(DBOUNCE_TEST_PG_PASSWORD)@127.0.0.1:$(DBOUNCE_TEST_PG_PORT)/postgres?sslmode=disable"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "postgres failed to become ready within 30s"; \
	docker logs $(DBOUNCE_TEST_PG_NAME) | tail -30; \
	exit 1

pg-down:
	@docker rm -f $(DBOUNCE_TEST_PG_NAME) 2>/dev/null || true

pg-logs:
	docker logs -f $(DBOUNCE_TEST_PG_NAME)

# MySQL 8.4 — parallels pg-up for the D-Slice 5 wire-protocol surface.
# The connection string printed at end matches the env-var convention
# D-Slice 5's integration tests will read (DBOUNCE_INTEGRATION_MYSQL_URL).
mysql-up:
	@if docker ps -a --format '{{.Names}}' | grep -q '^$(DBOUNCE_TEST_MYSQL_NAME)$$'; then \
		echo "container $(DBOUNCE_TEST_MYSQL_NAME) already exists; removing first"; \
		docker rm -f $(DBOUNCE_TEST_MYSQL_NAME) >/dev/null; \
	fi
	docker run --rm -d \
		--name $(DBOUNCE_TEST_MYSQL_NAME) \
		-p $(DBOUNCE_TEST_MYSQL_PORT):3306 \
		-e MYSQL_ROOT_PASSWORD=$(DBOUNCE_TEST_MYSQL_PASSWORD) \
		-e MYSQL_DATABASE=$(DBOUNCE_TEST_MYSQL_DB) \
		mysql:8.4
	@echo "waiting for mysql to accept connections..."
	@for i in $$(seq 1 60); do \
		if docker exec $(DBOUNCE_TEST_MYSQL_NAME) mysqladmin ping -h 127.0.0.1 -uroot -p$(DBOUNCE_TEST_MYSQL_PASSWORD) --silent >/dev/null 2>&1; then \
			echo "mysql ready on :$(DBOUNCE_TEST_MYSQL_PORT)"; \
			echo "DBOUNCE_INTEGRATION_MYSQL_URL=root:$(DBOUNCE_TEST_MYSQL_PASSWORD)@tcp(127.0.0.1:$(DBOUNCE_TEST_MYSQL_PORT))/$(DBOUNCE_TEST_MYSQL_DB)"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "mysql failed to become ready within 60s"; \
	docker logs $(DBOUNCE_TEST_MYSQL_NAME) | tail -30; \
	exit 1

mysql-down:
	@docker rm -f $(DBOUNCE_TEST_MYSQL_NAME) 2>/dev/null || true

mysql-logs:
	docker logs -f $(DBOUNCE_TEST_MYSQL_NAME)
