# dbounce — make targets
#
# `make test`             unit tests only (always runnable)
# `make test-integration` runs the build-tagged integration tests
#                         against the docker postgres started by `make pg-up`
# `make pg-up`            start a local Postgres 16 container on :5432 (test/test)
# `make pg-down`          stop + remove the local Postgres test container
# `make pg-logs`          tail the test container logs

DBOUNCE_TEST_PG_NAME ?= dbounce-test-pg
DBOUNCE_TEST_PG_PORT ?= 5432
DBOUNCE_TEST_PG_PASSWORD ?= test

.PHONY: build vet test test-integration pg-up pg-down pg-logs

build:
	go build ./...

vet:
	go vet ./...

test:
	go test ./...

# Integration tests are build-tag gated so `go test ./...` never tries
# to run them without an upstream PG. The integration tests themselves
# skip-with-message when PG isn't reachable, so this target is safe to
# run even without `make pg-up` (you'll see skips instead of failures).
test-integration:
	go test -tags=integration -timeout 5m ./...

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
