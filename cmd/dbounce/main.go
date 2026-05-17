// Command dbounce is the local SQL gating proxy.
//
// Run it as a sidecar between a SQL client (psql / a coding agent /
// an analytics tool / a CI job) and the real database; dbounce parses
// every statement, matches it against gating rules (D-Slice 3+),
// records the decision in a SQLite audit log, and (in transparent
// mode) can deny statements that don't match.
//
// D-Slice 1 ships the observation-only foundation: PostgreSQL wire-
// protocol listener + AST-aware statement parser + decision audit log
// + minimum CLI surface (run, audit tail, --version, /healthz). Real
// upstream forwarding ships in D-Slice 2; rule engine in D-Slice 3;
// MySQL/Snowflake/BigQuery dialects in D-Slices 5-6; profiles + MCP
// in D-Slice 7; pause/prompts/presets in D-Slice 8.
//
// All command wiring lives in internal/cli so binaries built by
// downstream packagers (homebrew, scoop, distro repos) run the same
// code path.
package main

import "github.com/trsreagan3/dbounce/internal/cli"

func main() { cli.Main() }
