// Package cli is dbounce's cobra command tree. Both the cmd/dbounce
// binary and any future packaging shims delegate to cli.Main so the
// command surface has a single source of truth.
//
// D-Slice 1 commands:
//
//	dbounce run           start the SQL-wire-protocol listener
//	dbounce audit tail    show recent decisions from the audit log
//	dbounce --version     print version + commit + build time
//
// Profile / rules / tasks / pause / prompts / presets / mcp / init-tls
// land in D-Slices 3-8 respectively. The cobra parent commands aren't
// scaffolded here because cobra would print them in --help and mislead
// the operator into thinking they're partially-implemented; better to
// add them at the same time the underlying subcommands ship.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/proxy"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/upstream"
)

// loopbackHosts mirrors kbounce + ibounce's CRIT-32-02 closure:
// dbounce will hold inbound client SCRAM challenges + bearer tokens
// once D-Slice 2 lands; binding externally exposes that surface to
// anyone on the network. Refuse non-loopback bindings unless the
// operator passed --i-know-this-binds-externally to acknowledge they
// read the threat model.
var loopbackHosts = map[string]struct{}{
	"127.0.0.1":     {},
	"::1":           {},
	"localhost":     {},
	"ip6-localhost": {},
	"ip6-loopback":  {},
}

// envProfileVar is the env-var name used to select the active profile
// when --profile is not passed. The DBOUNCE_ prefix is preserved
// (rather than DB_) so the three-product `*BOUNCE_PROFILE` env-var
// pattern stays consistent across iam-jit-bouncer / kbouncer /
// dbounce.
const envProfileVar = "DBOUNCE_PROFILE"

// version is overridden at build time via -ldflags
// "-X github.com/trsreagan3/dbounce/internal/cli.version=...". Unstamped
// builds report "dev".
var version = "dev"

// commit is the git SHA the binary was built from. Set via -ldflags
// "-X github.com/trsreagan3/dbounce/internal/cli.commit=...". Unset →
// "none".
var commit = "none"

// buildTime is the ISO-8601 UTC timestamp the binary was built at.
// Set via -ldflags
// "-X github.com/trsreagan3/dbounce/internal/cli.buildTime=...". Unset
// → "unknown".
var buildTime = "unknown"

// Main is the package's exported entry point so any binary that wraps
// dbounce (homebrew shim, distro packager, downstream fork) runs the
// same code path.
func Main() {
	proxy.EnsureLogger()
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// versionString returns the human-readable version surfaced via
// `dbounce --version`. Format: `dbounce <version> (commit X, built Y)`.
// Mirrors kbounce + ibounce's UAT-K2 HIGH-K2-06 closure pattern.
func versionString() string {
	return fmt.Sprintf("dbounce %s (commit %s, built %s)", version, commit, buildTime)
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "dbounce",
		Short:         "Local SQL gating proxy",
		Long:          rootLongHelp,
		Version:       versionString(),
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.SetVersionTemplate("{{.Version}}\n")
	root.AddCommand(newRunCmd())
	root.AddCommand(newAuditCmd())
	root.AddCommand(newInitTLSCmd())
	// D-Slice 7: environment profile + MCP server subcommand trees.
	root.AddCommand(newProfileCmd())
	root.AddCommand(newMCPCmd())
	// D-Slice 8: pause + prompts + presets + rules subcommands.
	// ProfileWriter wiring bridges D-Slice 7's internal/profile package
	// (the writer) to D-Slice 8's CLI surface (the consumer). The
	// adapter loads profiles.yaml lazily on the first writer call so
	// that root-cmd construction stays cheap + the whole CLI doesn't
	// hard-fail at startup if profiles.yaml is missing — `dbounce
	// audit tail` should keep working even without a profiles file.
	writer := newCLIProfileWriter("")
	root.AddCommand(newPauseCmd())
	root.AddCommand(newPromptsCmd(writer))
	root.AddCommand(newPresetsCmd(writer))
	root.AddCommand(newRulesCmd(writer))
	return root
}

// profileWriterAdapter implements the cli.ProfileWriter interface
// using D-Slice 7's internal/profile package. The adapter is the
// merge-time bridge promised by the prompts.go ProfileWriter
// docstring: it lets the D-Slice 8 CLI surfaces (prompts answer
// --kind profile / presets apply / rules recommend --save-as-profile)
// create real profiles on disk via Profiles.AddLocalProfile.
//
// Lazy load: profilesPath / loaded.Profiles are populated on the
// first CreateProfile or ExistingProfileNames call. Two reasons:
//
//  1. Root-cmd construction runs for every dbounce invocation
//     including `dbounce --help` and `dbounce audit tail`. A
//     hard-fail here on a missing profiles.yaml would break those
//     unrelated workflows. Lazy means the error only surfaces when
//     the operator actually asks to write a profile.
//
//  2. The --profiles-path flag (D-Slice 7 run command) lets the
//     operator override the default path. Lazy + the optional
//     path argument to CreateProfile/AddLocalProfile mean we can
//     extend the adapter to honor the flag later without breaking
//     the current callers.
//
// Conversion note: cli.ProfileWriter.CreateProfile takes []ProxyRule
// for both allow + deny, but profile.Profile uses ProfileAllowRule
// for allows and []string DenyActions for denies. The Pattern + Note
// fields round-trip; rules.ProxyRule's SchemaScope / TableScope /
// FunctionScope / Origin / Effect are DROPPED on the allow side
// (ProfileAllowRule's ArnScope / RegionScope are AWS-shaped and not
// the same axis). For deny rules we extract the Pattern's statement
// type and append to DenyActions — table-half of the pattern is
// dropped because DenyActions is a category-or-type list, not a
// pattern list. Both lossy conversions are documented inline.
type profileWriterAdapter struct {
	// configuredPath is the path the adapter was constructed with.
	// Empty means "use profile.DefaultProfilesPath() on first call."
	configuredPath string

	mu             sync.Mutex
	loaded         *profile.Profiles
	resolvedPath   string
}

func newCLIProfileWriter(path string) *profileWriterAdapter {
	return &profileWriterAdapter{configuredPath: path}
}

// ensureLoaded resolves the on-disk path + loads the current profile
// set. Idempotent; the first call wins. Safe for concurrent callers.
func (a *profileWriterAdapter) ensureLoaded() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.loaded != nil {
		return nil
	}
	path := a.configuredPath
	if path == "" {
		p, err := profile.DefaultProfilesPath()
		if err != nil {
			return fmt.Errorf("dbounce: resolve profiles path: %w", err)
		}
		path = p
	}
	ps, err := profile.LoadProfiles(path)
	if err != nil {
		return fmt.Errorf("dbounce: load profiles for writer: %w", err)
	}
	// LoadProfiles falls back to embedded defaults when the file is
	// missing + leaves Path = "". Override so AddLocalProfile lands the
	// new profile on the disk path the operator expects (rather than
	// silently creating profiles.yaml at a nondeterministic default
	// resolved inside AddLocalProfile).
	if ps.Path == "" {
		ps.Path = path
	}
	a.loaded = ps
	a.resolvedPath = path
	return nil
}

// CreateProfile satisfies cli.ProfileWriter. Converts the wire-shape
// []ProxyRule into the on-disk profile.Profile shape + persists via
// AddLocalProfile. See type docstring for the lossy-conversion notes.
func (a *profileWriterAdapter) CreateProfile(name, description string,
	allow []dbrules.ProxyRule, deny []dbrules.ProxyRule) error {
	if err := a.ensureLoaded(); err != nil {
		return err
	}
	p := &profile.Profile{
		Name:        name,
		Description: description,
	}
	for _, r := range allow {
		// Pattern + Note round-trip. SchemaScope / TableScope /
		// FunctionScope / Origin / Effect are dropped — ProfileAllowRule
		// does not carry those axes. Origin is captured implicitly via
		// the Description ("from preset X" / "from prompt N" /
		// "auto-generated by rules recommend").
		p.AllowRules = append(p.AllowRules, profile.ProfileAllowRule{
			Pattern: r.Pattern,
			Note:    r.Note,
		})
	}
	for _, r := range deny {
		// DenyActions is a statement-type / category list, not a pattern
		// list. Pull the statement_type half from the pattern; if the
		// pattern is malformed, skip it (caller has bigger problems than
		// a profile write) rather than reject the whole CreateProfile
		// call. The table-glob half is DROPPED — profile.Profile has no
		// per-deny-action table scope (the keyword-target denies live on
		// a separate field). For pattern "DELETE:public.users" we deny
		// the whole DELETE statement type under this profile.
		stmtType, _, err := dbrules.ParsePattern(r.Pattern)
		if err != nil || stmtType == "" {
			continue
		}
		p.DenyActions = append(p.DenyActions, stmtType)
	}
	if err := a.loaded.AddLocalProfile(a.resolvedPath, p); err != nil {
		// Re-wrap ErrProfileExists with a friendlier message that names
		// the file the operator will need to edit, but preserve the
		// sentinel via errors.Is for callers that test for it.
		if errors.Is(err, profile.ErrProfileExists) {
			return fmt.Errorf(
				"%w (profiles file: %s — pick a different name or "+
					"delete the existing entry)",
				err, a.resolvedPath)
		}
		return err
	}
	return nil
}

// ExistingProfileNames satisfies cli.ProfileWriter. Returns a set so
// naming.ResolveProfileName can do membership tests in O(1).
func (a *profileWriterAdapter) ExistingProfileNames() (map[string]struct{}, error) {
	if err := a.ensureLoaded(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	names := a.loaded.NamesSorted()
	a.mu.Unlock()
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		// strings.TrimSpace defends against a hand-edited YAML with
		// trailing whitespace in a profile name — the collision check
		// should still fire.
		out[strings.TrimSpace(n)] = struct{}{}
	}
	return out, nil
}

const rootLongHelp = `dbounce is a local proxy that sits between a SQL client (psql /
a coding agent / an analytics tool / a CI job) and the real database.
It parses every statement, records the decision in an audit log, and
(in later slices, transparent mode) can deny statements that don't
match its rule set.

Two operating modes (mirroring kbounce + ibounce):

  cooperative   parse + log every statement (D-Slice 1 default).
                D-Slice 1 NEVER forwards or blocks — observation only.
  transparent   DENY verdicts return a SQL error to the client.
                Real upstream forwarding lands in D-Slice 2.

D-Slice 1 ships:
  - PostgreSQL wire-protocol listener (observation-only)
  - AST-aware statement parser (pg_query_go v6)
  - Decision audit log (~/.dbounce/state.db)
  - dbounce run, dbounce audit tail, dbounce --version, /healthz

Read-vs-write framing: D-Slice 1 records statement_type (SELECT vs
INSERT/UPDATE/DELETE/MERGE/DDL/CALL/DO/EXECUTE/WITH-WRITE) for every
row + flags HasMutatingNode so the D-Slice 7 safe-default profile
can default to "reads are fine; writes get layered checks" out of
the gate.`

func newRunCmd() *cobra.Command {
	var (
		port              int
		host              string
		mgmtHost          string
		mgmtPort          int
		modeStr           string
		defaultPolStr     string
		dialectStr        string
		upstreamURL       string
		upstreamCACert    string
		upstreamTLSStr    string
		dbPath            string
		forceExternalBind bool
		// D-Slice 4: TLS flags. All optional; empty preserves D-Slice
		// 1+2's plaintext behavior.
		listenerTLSCert     string
		listenerTLSKey      string
		listenerTLSClientCA string
		requireClientCert   bool
		mgmtTLSCert         string
		mgmtTLSKey          string
		// D-Slice 7: environment profile + profiles.yaml path.
		profileName  string
		profilesPath string
		// D-Slice 8: async deny-prompt UX. When true, transparent DENY
		// decisions enqueue a pending_prompts row for `dbounce prompts
		// answer` to drain. Default false preserves D-Slice 3 behavior.
		promptOnDeny bool
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the SQL wire-protocol listener",
		Long: `Start the dbounce SQL wire-protocol listener.

The wire-protocol listener binds to 127.0.0.1:5433 by default
(loopback only — dbounce will hold SCRAM challenges + bearer tokens
once D-Slice 2's real forwarding lands; binding externally exposes
that surface). The management HTTP listener for /healthz binds to
127.0.0.1:8768 (distinct from kbounce's 8766 and ibounce's 8767).

D-Slice 1 is OBSERVATION-ONLY: each inbound statement is parsed +
audit-logged, then a synthetic ReadyForQuery is sent to the client.
NOTHING ACTUALLY EXECUTES against any upstream. D-Slice 2 lands real
forwarding.

Ctrl+C exits cleanly (graceful shutdown).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mode, err := proxy.ParseMode(modeStr)
			if err != nil {
				return err
			}
			defaultPol, err := proxy.ParseDefaultPolicy(defaultPolStr)
			if err != nil {
				return err
			}
			dialect, err := proxy.ParseDialect(dialectStr)
			if err != nil {
				return err
			}

			// D-Slice 5 → 4 cross-slice guard: MySQL listener TLS not
			// shipped yet (per dbounce-build-plan §D-Slice 5). Fail-fast
			// here rather than silently accepting flags that won't take
			// effect on the MySQL handler. Revisit when MySQL TLS lands.
			if dialect == proxy.DialectMySQL &&
				(listenerTLSCert != "" || listenerTLSKey != "" || requireClientCert) {
				return fmt.Errorf(
					"--dialect=mysql does not yet support listener TLS " +
						"(--listener-tls-cert / --listener-tls-key / " +
						"--require-client-cert). MySQL listener TLS is " +
						"post-launch; use --dialect=postgres for now.")
			}

			// CRIT-32-02 (mirrored from kbounce + ibounce): refuse to
			// bind externally without explicit operator acknowledgement.
			if _, ok := loopbackHosts[host]; !ok && !forceExternalBind {
				fmt.Fprintf(os.Stderr,
					"refusing to bind to %q: this exposes dbounce's "+
						"credential-handling surface to the network.\n\n"+
						"If you genuinely need to bind externally (test VM "+
						"with no real DB credentials, network-segmented dev "+
						"box), re-run with --i-know-this-binds-externally.\n",
					host)
				os.Exit(2)
			}

			// D-Slice 2: resolve the upstream forwarding target. Empty
			// --upstream preserves D-Slice 1 observation-only mode.
			var resolvedUpstream *upstream.Upstream
			if upstreamURL != "" {
				tlsMode, err := upstream.ParseTLSMode(upstreamTLSStr)
				if err != nil {
					return err
				}
				up, err := upstream.Resolve(upstream.Options{
					UpstreamURL: upstreamURL,
					CACertPath:  upstreamCACert,
					TLSMode:     tlsMode,
				})
				if err != nil {
					return fmt.Errorf("resolve upstream: %w", err)
				}
				resolvedUpstream = up
			}

			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			// D-Slice 4: optional listener-side TLS. When both
			// --listener-tls-cert + --listener-tls-key are set, the
			// listener answers SSLRequest with 'S' + performs the TLS
			// handshake before the StartupMessage parser fires.
			var listenerTLSCfg *proxy.ListenerTLS
			if listenerTLSCert != "" || listenerTLSKey != "" || requireClientCert {
				lcfg, err := proxy.LoadListenerTLS(
					listenerTLSCert, listenerTLSKey, listenerTLSClientCA, requireClientCert)
				if err != nil {
					return err
				}
				listenerTLSCfg = lcfg
			}

			// D-Slice 4: /healthz over HTTPS sanity check. Either both
			// management-tls flags are set, or neither. A half-set pair
			// is an operator typo we should surface loudly.
			if (mgmtTLSCert == "") != (mgmtTLSKey == "") {
				return fmt.Errorf(
					"dbounce: --management-tls-cert and --management-tls-key " +
						"must both be set or both empty")
			}

			// D-Slice 7: profile resolution. Precedence: --profile flag >
			// DBOUNCE_PROFILE env var. Env-var fallback intentionally
			// only fires when the flag is unset so a shell-wide default
			// can be overridden per-invocation without unsetting the env
			// var. profiles.yaml is auto-created from embedded defaults
			// on first run; existing files are NEVER overwritten.
			profileFromFlag := profileName != ""
			if profileName == "" {
				profileName = os.Getenv(envProfileVar)
			}
			resolvedProfilesPath := profilesPath
			if resolvedProfilesPath == "" {
				resolvedProfilesPath, err = profile.DefaultProfilesPath()
				if err != nil {
					return fmt.Errorf("resolve profiles path: %w", err)
				}
			}
			if written, ferr := profile.EnsureDefaultProfilesFile(resolvedProfilesPath); ferr != nil {
				log.Warn().Err(ferr).Str("path", resolvedProfilesPath).
					Msg("dbounce: could not write default profiles.yaml; using embedded defaults")
			} else if written {
				fmt.Fprintf(os.Stderr,
					"dbounce: wrote default profiles to %s\n", resolvedProfilesPath)
			}
			profiles, err := profile.LoadProfiles(resolvedProfilesPath)
			if err != nil {
				return fmt.Errorf("load profiles: %w", err)
			}
			activeProfile, err := profiles.Active(profileName)
			if err != nil {
				return fmt.Errorf("select profile: %w", err)
			}

			cfg := proxy.Config{
				Host:              host,
				Port:              port,
				MgmtHost:          mgmtHost,
				MgmtPort:          mgmtPort,
				Mode:              mode,
				DefaultPolicy:     defaultPol,
				Dialect:           dialect,
				UpstreamURL:       upstreamURL,
				Upstream:          resolvedUpstream,
				ListenerTLS:       listenerTLSCfg,
				MgmtTLSCertFile:   mgmtTLSCert,
				MgmtTLSKeyFile:    mgmtTLSKey,
				ActiveProfile:     activeProfile,
				ActiveProfileName: activeProfile.Name,
				PromptOnDeny:      promptOnDeny,
			}.Normalize()
			_ = profileFromFlag // reserved for the not-selected banner in newer slices

			s := proxy.NewServer(cfg, st)

			// Banner per the agent-parity requirement + the read-write
			// framing the safe-default profile (D-Slice 7) will hook
			// into. Goes to stderr so stdout stays clean.
			wireProto := "tcp"
			if cfg.ListenerTLS != nil {
				wireProto = "tcp+tls"
				if cfg.ListenerTLS.RequireClientCert {
					wireProto += "+mtls"
				}
			}
			fmt.Fprintf(os.Stderr,
				"dbounce wire listener  : %s:%d  (dialect=%s, mode=%s, default-policy=%s, transport=%s)\n",
				cfg.Host, cfg.Port, cfg.Dialect, cfg.Mode, cfg.DefaultPolicy, wireProto)
			mgmtScheme := "http"
			if cfg.MgmtTLSCertFile != "" {
				mgmtScheme = "https"
			}
			fmt.Fprintf(os.Stderr,
				"dbounce mgmt /healthz : %s://%s:%d/healthz\n",
				mgmtScheme, cfg.MgmtHost, cfg.MgmtPort)
			fmt.Fprintf(os.Stderr, "audit db              : %s\n", st.Path())
			if resolvedUpstream != nil {
				fmt.Fprintf(os.Stderr,
					"upstream              : %s (D-Slice 2 forwarding ACTIVE; TLS=%s)\n",
					upstreamURL, resolvedUpstream.TLSMode)
				if upstreamCACert != "" {
					fmt.Fprintf(os.Stderr,
						"upstream CA bundle    : %s\n", upstreamCACert)
				}
			} else {
				fmt.Fprintln(os.Stderr,
					"upstream              : <none> — observation-only mode (no forwarding)")
			}
			fmt.Fprintf(os.Stderr,
				"profile               : %s (loaded from %s)\n",
				activeProfile.Name, resolvedProfilesPath)
			if !profileFromFlag && os.Getenv(envProfileVar) == "" {
				fmt.Fprintln(os.Stderr,
					"                        no --profile / "+envProfileVar+" set — running as 'full-user' "+
						"(passthrough). To block writes by default, pass --profile safe-default OR "+
						"export "+envProfileVar+"=safe-default.")
			}
			fmt.Fprintln(os.Stderr,
				"mode                  : cooperative — every statement is parsed + audit-logged.")
			fmt.Fprintln(os.Stderr,
				"                        D-Slice 1 is OBSERVATION-ONLY: nothing actually executes")
			fmt.Fprintln(os.Stderr,
				"                        against the upstream. To opt into the (D-Slice 2+) transparent")
			fmt.Fprintln(os.Stderr,
				"                        block path once it ships, pass --mode transparent.")
			fmt.Fprintln(os.Stderr,
				"read vs write         : reads (SELECT) and writes (INSERT/UPDATE/DELETE/MERGE/DDL/")
			fmt.Fprintln(os.Stderr,
				"                        CALL/DO/EXECUTE/WITH-WRITE) are classified per-statement so the")
			fmt.Fprintln(os.Stderr,
				"                        D-Slice 7 safe-default profile can default to reads-fine +")
			fmt.Fprintln(os.Stderr,
				"                        writes-layered-checks (the readonly-admin-minus shape).")
			fmt.Fprintln(os.Stderr, "Ctrl+C to stop.")

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			serveErr := make(chan error, 1)
			go func() {
				err := s.Serve()
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					serveErr <- err
					return
				}
				serveErr <- nil
			}()

			select {
			case <-ctx.Done():
				log.Info().Msg("dbounce received shutdown signal")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := s.Shutdown(shutdownCtx); err != nil {
					return fmt.Errorf("shutdown: %w", err)
				}
				if err := <-serveErr; err != nil {
					return err
				}
				fmt.Fprintln(os.Stderr, "dbounce stopped.")
				return nil
			case err := <-serveErr:
				return err
			}
		},
	}
	cmd.Flags().IntVar(&port, "port", 5433,
		"TCP port for the SQL wire-protocol listener (loopback only by default).")
	cmd.Flags().StringVar(&host, "host", "127.0.0.1",
		"Interface to bind the wire-protocol listener. Anything other than "+
			"127.0.0.1 / ::1 / localhost requires --i-know-this-binds-externally.")
	cmd.Flags().StringVar(&mgmtHost, "mgmt-host", "127.0.0.1",
		"Interface to bind the management HTTP listener (/healthz). Loopback by default.")
	cmd.Flags().IntVar(&mgmtPort, "mgmt-port", 8768,
		"TCP port for the management HTTP listener (/healthz). Distinct from "+
			"kbounce's 8766 and ibounce's 8767 so all three products coexist.")
	cmd.Flags().StringVar(&modeStr, "mode", "cooperative",
		"cooperative | transparent. cooperative = parse + log + advisory. "+
			"transparent = DENY verdicts return a SQL error (D-Slice 2+).")
	cmd.Flags().StringVar(&defaultPolStr, "default-policy", "deny",
		"allow | deny. What transparent mode does when no rule matches. "+
			"Scaffolding for D-Slice 3 (no rule engine yet).")
	cmd.Flags().StringVar(&dialectStr, "dialect", "postgres",
		"SQL wire-protocol dialect: postgres (default) | mysql. "+
			"D-Slice 5 ships mysql via xwb1989/sqlparser + a MySQL wire-"+
			"protocol listener (auth pass-through; COM_QUERY gating; "+
			"prepared statements + listener TLS deferred to post-launch).")
	cmd.Flags().StringVar(&upstreamURL, "upstream", "",
		"Upstream DB URL (e.g. postgres://user@host:5432/db). When set, "+
			"dbounce dials this on every inbound session + forwards SCRAM "+
			"auth verbatim + proxies ALLOW verdicts. When empty, dbounce "+
			"runs in observation-only mode (D-Slice 1 behavior).")
	cmd.Flags().StringVar(&upstreamCACert, "upstream-ca-cert", "",
		"Optional CA bundle (PEM) for outbound TLS validation. Empty = "+
			"system trust store. Has no effect when --upstream-tls=skip "+
			"or --upstream-tls=disable.")
	cmd.Flags().StringVar(&upstreamTLSStr, "upstream-tls", "verify",
		"Outbound TLS mode: verify | skip | disable. verify (default) "+
			"validates the upstream's cert against the system trust + any "+
			"--upstream-ca-cert. skip disables verification (self-signed "+
			"dev clusters; never production). disable refuses TLS even "+
			"when the upstream offers it.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite audit DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().BoolVar(&forceExternalBind, "i-know-this-binds-externally", false,
		"Required acknowledgement when --host is anything other than 127.0.0.1 "+
			"/ ::1 / localhost. Binding externally exposes dbounce's "+
			"credential-handling surface (once D-Slice 2 lands SCRAM "+
			"pass-through). Don't pass without a specific reason.")

	// D-Slice 4: listener-side TLS for the SQL wire-protocol port.
	cmd.Flags().StringVar(&listenerTLSCert, "listener-tls-cert", "",
		"PEM cert for the SQL wire-protocol listener. Pair with "+
			"--listener-tls-key. When both are set, dbounce answers PG SSLRequest "+
			"with 'S' + performs the TLS handshake before the StartupMessage "+
			"parser fires. Generate via `dbounce init-tls`.")
	cmd.Flags().StringVar(&listenerTLSKey, "listener-tls-key", "",
		"PEM private key for the SQL wire-protocol listener (matches --listener-tls-cert).")
	cmd.Flags().StringVar(&listenerTLSClientCA, "listener-tls-client-ca", "",
		"PEM CA bundle clients' certs are verified against when "+
			"--require-client-cert is set. Required for mTLS.")
	cmd.Flags().BoolVar(&requireClientCert, "require-client-cert", false,
		"Reject TLS clients that don't present a cert signed by --listener-tls-client-ca. "+
			"Opt-in mTLS. Has no effect when --listener-tls-cert is unset.")

	// D-Slice 4: management-listener TLS for /healthz.
	cmd.Flags().StringVar(&mgmtTLSCert, "management-tls-cert", "",
		"PEM cert for the management HTTP listener. Pair with "+
			"--management-tls-key. When both are set, /healthz is served over HTTPS. "+
			"Generate via `dbounce init-tls`.")
	cmd.Flags().StringVar(&mgmtTLSKey, "management-tls-key", "",
		"PEM private key for the management HTTP listener (matches --management-tls-cert).")

	// D-Slice 7: environment profile flags.
	cmd.Flags().StringVar(&profileName, "profile", "",
		"Active environment profile. Built-in: 'full-user' (passthrough, "+
			"default) and 'safe-default' (sql_read_only baseline + "+
			"AST-walk Layer 2 backstop for mutations). Community "+
			"profiles install via `dbounce profile install --from URL`. "+
			"Falls back to "+envProfileVar+" env var; defaults to "+
			"'full-user' if neither is set. Profile denies are a HARD "+
			"FLOOR — a permissive task scope CANNOT override them. "+
			"Legacy aliases ('readonly', 'prod-readonly', 'none') "+
			"resolve in v1.0 and are removed in v1.1.")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.dbounce/profiles.yaml). "+
			"Honors DBOUNCE_PROFILES_PATH env var if --profiles-path unset.")
	// D-Slice 8: async deny-prompt UX.
	cmd.Flags().BoolVar(&promptOnDeny, "prompt-on-deny", false,
		"When in transparent mode, every DENY enqueues a row in "+
			"pending_prompts. Drain the queue with `dbounce prompts list` "+
			"+ `dbounce prompts answer ID --kind {ignore|always|profile}`. "+
			"Has no effect in cooperative mode (advisory verdicts aren't "+
			"prompted) or during an active pause window (operator already "+
			"said allow).")
	return cmd
}

// newAuditCmd implements `dbounce audit ...`. D-Slice 1 ships `tail`
// only — the highest-leverage operator workflow ("show me what just
// went through the proxy"). Later slices may add `search`, `export`,
// and diff-against-baseline.
func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect the dbounce decision audit log",
		Long: `dbounce records every parsed statement in a local SQLite audit
log at ~/.dbounce/state.db. ` + "`dbounce audit tail`" + ` is the
fastest way to see what a SQL client just sent through the proxy +
what verdict each statement got.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("audit", cmd)
	cmd.AddCommand(newAuditTailCmd())
	return cmd
}

// parentRequiresSubcommand returns a RunE that prints a clear error +
// returns exit 1 when a cobra parent command is invoked without a
// known sub-subcommand. Mirrors kbounce's UAT-K2 BLOCKER-K2-02
// closure pattern.
func parentRequiresSubcommand(parent string, _ *cobra.Command) func(*cobra.Command, []string) error {
	return func(c *cobra.Command, args []string) error {
		if len(args) == 0 {
			fmt.Fprintf(c.ErrOrStderr(),
				"dbounce: missing subcommand for %q; see `dbounce %s --help` for valid subs\n",
				parent, parent)
			os.Exit(1)
		}
		fmt.Fprintf(c.ErrOrStderr(),
			"dbounce: unknown subcommand %q for %q; see `dbounce %s --help` for valid subs\n",
			args[0], parent, parent)
		os.Exit(1)
		return nil
	}
}

func newAuditTailCmd() *cobra.Command {
	var (
		limit   int
		dbPath  string
		asJSON  bool
	)
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show the most recent N decisions (newest first)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Bound --limit at parse time so operators understand the
			// range rather than silently no-op'ing on out-of-range
			// values. Mirrors kbounce + ibounce UAT-K2 HIGH-K2-03.
			if limit < 1 || limit > 1000 {
				return fmt.Errorf("--limit must be in 1-1000 (got %d)", limit)
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			rows, err := st.RecentDecisions(limit)
			if err != nil {
				return err
			}
			if asJSON {
				// Cross-product parity per [[cross-product-agent-parity]]:
				// kbounce + ibounce both ship `audit tail --json`; dbounce
				// matches the shape (one decision per line, newest first).
				enc := json.NewEncoder(cmd.OutOrStdout())
				for _, r := range rows {
					rec := map[string]any{
						"at":                r.At.UTC().Format(time.RFC3339),
						"dialect":           r.Dialect,
						"statement":         r.Statement,
						"statement_type":    r.StatementType,
						"tables":            r.TablesTouched,
						"functions":         r.FunctionsCalled,
						"is_dml":            r.IsDML,
						"is_ddl":            r.IsDDL,
						"has_mutating_node": r.HasMutatingNode,
						"mutating_node_type": r.MutatingNodeType,
						"is_explain":        r.IsExplain,
						"is_explain_analyze": r.IsExplainAnalyze,
						"impersonated_role": r.ImpersonatedRole,
						"parse_errors":      r.ParseErrors,
						"decision_verdict":  r.DecisionVerdict,
						"decision_reason":   r.DecisionReason,
						"mode_at_decision":  r.ModeAtDecision,
						"enforced":          r.Enforced,
						"decision_source":   r.DecisionSource,
						"profile_name":      r.ProfileName,
						"task_id":           r.TaskID,
						"is_stream":         r.IsStream,
						"stream_kind":       r.StreamKind,
					}
					if err := enc.Encode(rec); err != nil {
						return err
					}
				}
				return nil
			}
			if len(rows) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no decisions recorded yet)")
				return nil
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-20s  %-6s  %-7s  %-12s  %s\n",
				"AT (UTC)", "MODE", "VERDICT", "STMT-TYPE", "STATEMENT")
			for _, r := range rows {
				at := r.At.UTC().Format("2006-01-02 15:04:05")
				stmt := r.Statement
				if len(stmt) > 60 {
					stmt = stmt[:57] + "..."
				}
				fmt.Fprintf(w, "%-20s  %-6s  %-7s  %-12s  %s\n",
					at, r.ModeAtDecision, r.DecisionVerdict, r.StatementType, stmt)
				if r.DecisionReason != "" {
					reason := r.DecisionReason
					if len(reason) > 80 {
						reason = reason[:77] + "..."
					}
					fmt.Fprintf(w, "%52s  %s\n", "↳", reason)
				}
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50,
		"Max rows to return (1-1000). Default 50.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit one JSON object per decision row, newest first. Mirrors "+
			"kbounce + ibounce's `audit tail --json` for cross-product "+
			"agent parity.")
	return cmd
}
