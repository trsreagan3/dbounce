# syntax=docker/dockerfile:1.7
#
# dbounce — local SQL gating proxy.
#
# Multi-stage build:
#   1. golang:1.25-alpine builds a static CGO-enabled binary with version
#      stamping via -ldflags. Matches go.mod's `go 1.25.0` directive so
#      the toolchain doesn't have to auto-download. CGO is required by
#      github.com/pganalyze/pg_query_go/v6 (the PostgreSQL AST parser),
#      which wraps libpg_query (C). modernc.org/sqlite (the audit-DB
#      driver) is pure-Go and adds nothing to the CGO surface. We link
#      statically against musl libc so the resulting binary needs no
#      runtime libc.
#   2. gcr.io/distroless/static-debian12:nonroot runs the static binary
#      as a non-root user with no shell, no package manager, ~2MB base.
#
# Image is a packaging CONVENIENCE — same binary as `go install`,
# no extra features, no telemetry. See [[ibounce-honest-positioning]].

# ---- builder ---------------------------------------------------------------
FROM golang:1.25-alpine AS builder

# git           — `go build` reads VCS info when --buildvcs=auto fires.
# ca-certificates — needed by `go mod download` for TLS to proxy.golang.org.
# build-base    — gcc + binutils + make so cgo can compile libpg_query.
# musl-dev      — musl headers (libpg_query #include's standard C headers).
RUN apk add --no-cache git ca-certificates build-base musl-dev

WORKDIR /build

# Cache module downloads independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

# Source.
COPY . .

# Stamp version from build arg (passed in by CI from `git describe`);
# fall back to "docker" when built locally without --build-arg VERSION=...
ARG VERSION=docker
ARG COMMIT=none
ARG BUILD_TIME=unknown

# BuildKit auto-populates TARGETOS / TARGETARCH for multi-arch builds, but
# only inside stages that re-declare them with ARG. We re-declare WITHOUT a
# default so BuildKit's auto-populated value wins — a non-empty default
# would mask the auto-populated platform-specific value, causing the arm64
# manifest to silently ship an amd64 binary (the class of bug kbounce
# caught locally with `exec format error`).
ARG TARGETOS
ARG TARGETARCH

# Static binary: CGO_ENABLED=1 (required by pg_query_go) + -trimpath +
# -s -w for size + -extldflags "-static" to statically link against musl
# so the binary runs on distroless/static (no libc). ldflags also
# populate the version/commit/buildTime vars in internal/cli/cli.go.
RUN CGO_ENABLED=1 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
        -trimpath \
        -ldflags "-s -w -extldflags '-static' \
            -X github.com/trsreagan3/dbounce/internal/cli.version=${VERSION} \
            -X github.com/trsreagan3/dbounce/internal/cli.commit=${COMMIT} \
            -X github.com/trsreagan3/dbounce/internal/cli.buildTime=${BUILD_TIME}" \
        -o /out/dbounce \
        ./cmd/dbounce

# ---- runtime ---------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

# OCI metadata — surfaced on GHCR + by `docker inspect`.
LABEL org.opencontainers.image.source="https://github.com/trsreagan3/dbounce" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="dbounce" \
      org.opencontainers.image.description="SQL gating proxy for AI agents and dev workflows"

COPY --from=builder /out/dbounce /usr/local/bin/dbounce

# Document the default ports:
#   5433 — SQL wire-protocol listener (one above PostgreSQL's 5432 so an
#          existing local PG install isn't disturbed).
#   8768 — management HTTP listener for /healthz (distinct from kbounce's
#          8766 and ibounce's 8767 so all three products coexist).
# The binary refuses non-loopback binds without
# --i-know-this-binds-externally, so EXPOSE here is purely documentation
# — the operator still has to pass --host 0.0.0.0 + the acknowledgement
# flag for the wire-protocol port to be reachable from outside the
# container.
EXPOSE 5433
EXPOSE 8768

# Distroless has no shell, so HEALTHCHECK NONE — operators hit /healthz
# externally (kubelet liveness probe, monit, systemd watchdog, etc.).
HEALTHCHECK NONE

# nonroot user (uid 65532) is the default in the :nonroot variant.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/dbounce"]
CMD ["--help"]
