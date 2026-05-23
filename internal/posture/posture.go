// Package posture implements dbounce's per-bouncer posture surface.
//
// Shared between `dbounce posture` (CLI) + `dbounce_posture` (MCP)
// per [[cross-product-agent-parity]]. Lives in its own package so
// neither cli nor mcp pulls the other.
//
// Per [[ibounce-honest-positioning]]: the output is HONEST — if
// PGHOST/PGPORT point at the dbounce wire port but dbounce isn't
// running, the snapshot reports MISCONFIGURED rather than silently
// claiming intercept.
//
// Per [[creates-never-mutates]]: read-only; the package never writes
// to disk, never mutates env, never starts goroutines.
package posture

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// SchemaVersion pins the shape of the JSON output. Bump on breaking
// changes per [[config-export-wire-divergence]] (string).
const SchemaVersion = "1.0"

// Default ports dbounce listens on. The wire port speaks the
// Postgres protocol; the mgmt port serves /healthz + /audit/events.
const (
	DefaultWirePort = 5433
	DefaultMgmtPort = 8768
)

// EnvProfileVar matches internal/cli's envProfileVar.
const EnvProfileVar = "DBOUNCE_PROFILE"

// EnvModeVar — operator can pin the mode value the posture surface
// reports. Honest "unknown" otherwise; we don't introspect a live
// dbounce process from a sibling process.
const EnvModeVar = "DBOUNCE_MODE"

// Block matches the cross-product per-bouncer schema in
// iam-roles/src/iam_jit/posture/bouncers.py.
type Block struct {
	SchemaVersion      string `json:"schema_version"`
	Bouncer            string `json:"bouncer"`
	CapturedAt         string `json:"captured_at"`
	Running            bool   `json:"running"`
	Port               int    `json:"port"`
	MgmtPort           int    `json:"mgmt_port"`
	DefaultPort        int    `json:"default_port"`
	DefaultMgmtPort    int    `json:"default_mgmt_port"`
	Mode               string `json:"mode"`
	ActiveProfile      string `json:"active_profile"`
	EnvVarPointingHere string `json:"env_var_pointing_here,omitempty"`
	EnvVarSetElsewhere string `json:"env_var_set_elsewhere,omitempty"`
	Misconfig          string `json:"misconfig,omitempty"`
}

// Capture builds the structured snapshot. No goroutines, no
// background IO — just env reads + loopback TCP probes.
// Always safe to call.
func Capture() Block {
	wirePort := DefaultWirePort
	mgmtPort := DefaultMgmtPort
	running := loopbackPortOpen(mgmtPort, 250*time.Millisecond) ||
		loopbackPortOpen(wirePort, 250*time.Millisecond)
	block := Block{
		SchemaVersion:   SchemaVersion,
		Bouncer:         "dbounce",
		CapturedAt:      time.Now().UTC().Format(time.RFC3339),
		Running:         running,
		Port:            wirePort,
		MgmtPort:        mgmtPort,
		DefaultPort:     DefaultWirePort,
		DefaultMgmtPort: DefaultMgmtPort,
		Mode:            envOrUnknown(EnvModeVar),
		ActiveProfile:   envOrUnknown(EnvProfileVar),
	}
	pghost := strings.TrimSpace(os.Getenv("PGHOST"))
	pgportRaw := strings.TrimSpace(os.Getenv("PGPORT"))
	if isLoopback(pghost) {
		pgport := 5432
		if pgportRaw != "" {
			if p, err := strconv.Atoi(pgportRaw); err == nil {
				pgport = p
			}
		}
		if loopbackPortOpen(pgport, 250*time.Millisecond) {
			block.EnvVarPointingHere = fmt.Sprintf(
				"PGHOST=%s PGPORT=%d", pghost, pgport,
			)
			block.Running = true
			block.Port = pgport
		} else {
			block.Misconfig = fmt.Sprintf(
				"PGHOST=%s PGPORT=%d but nothing is listening on that loopback port",
				pghost, pgport,
			)
		}
	}
	return block
}

func envOrUnknown(name string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return "unknown"
	}
	return v
}

func isLoopback(host string) bool {
	switch host {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	return false
}

func loopbackPortOpen(port int, timeout time.Duration) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	conn, err := net.DialTimeout(
		"tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout,
	)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
