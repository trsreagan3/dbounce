// Cobra `dbounce mcp ...` subcommands.
//
// Mirrors kbouncer/internal/cli/mcp.go shape: serve / install-{claude-
// code,cursor,codex} / show-config / list-tools. The package-level
// internal/mcp + internal/mcpinstall packages own all the logic.

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/mcp"
	"github.com/trsreagan3/dbounce/internal/mcpinstall"
	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/proxy"
	"github.com/trsreagan3/dbounce/internal/store"
)

// newMCPCmd implements `dbounce mcp` — a command group for the
// MCP-over-stdio server an agent (Claude Code, Cursor, Codex, Devin)
// connects to so it can introspect + scope itself via the dbounce_*
// tool family.
//
// Subcommands:
//
//	dbounce mcp serve                 — start the JSON-RPC stdio server
//	dbounce mcp install-claude-code   — wire dbounce into Claude Code / Desktop
//	dbounce mcp install-cursor        — wire dbounce into Cursor
//	dbounce mcp install-codex         — wire dbounce into Codex (manual snippet)
//	dbounce mcp show-config           — print the canonical JSON snippet
//	dbounce mcp list-tools            — print the tool list (name + summary)
//
// Backward compatibility: `dbounce mcp` with no subcommand still
// starts the server (same as `dbounce mcp serve`), matching kbouncer
// + ibounce shape.
//
// Server-config flags (--db, --profile, --profiles-path, --mode,
// --default-policy, --owner, --actor) live on the `serve` subcommand
// and are mirrored on bare `dbounce mcp` so existing scripts that
// invoke `dbounce mcp --db ...` keep working.
func newMCPCmd() *cobra.Command {
	var (
		dbPath        string
		profileName   string
		profilesPath  string
		modeStr       string
		defaultPolStr string
		dialectStr    string
		owner         string
		actor         string
	)

	runServe := func(cmd *cobra.Command, args []string) error {
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
		st, err := store.Open(dbPath)
		if err != nil {
			return fmt.Errorf("open store: %w", err)
		}
		defer st.Close()

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
		profiles, err := profile.LoadProfiles(resolvedProfilesPath)
		if err != nil {
			return fmt.Errorf("load profiles: %w", err)
		}
		activeProfile, _ := profiles.Active(profileName) // err on unknown; serve anyway

		srv := mcp.NewServer(mcp.Config{
			Store:         st,
			ActiveProfile: activeProfile,
			ProfilesPath:  resolvedProfilesPath,
			Mode:          mode,
			DefaultPolicy: defaultPol,
			Dialect:       dialect,
			TaskOwner:     owner,
			Actor:         actor,
		})

		fmt.Fprintf(os.Stderr,
			"dbounce mcp serving on stdio (mode=%s, dialect=%s, profile=%s, db=%s)\n",
			mode, dialect, profileName, st.Path())
		fmt.Fprintln(os.Stderr, "Press Ctrl+D / close stdin to stop.")

		return srv.Serve(os.Stdin, os.Stdout)
	}

	addServeFlags := func(cmd *cobra.Command) {
		cmd.Flags().StringVar(&dbPath, "db", "",
			"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env). "+
				"MUST match the path the running proxy uses for live audit-log "+
				"access via dbounce_tail_decisions.")
		cmd.Flags().StringVar(&profileName, "profile", "",
			"Active environment profile name (mirror of `dbounce run --profile`). "+
				"Surfaced by dbounce_active_profile.")
		cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
			"Path to profiles.yaml (default: ~/.dbounce/profiles.yaml).")
		cmd.Flags().StringVar(&modeStr, "mode", "cooperative",
			"Mode the running proxy is in (cooperative | transparent). "+
				"Returned by dbounce_active_mode.")
		cmd.Flags().StringVar(&defaultPolStr, "default-policy", "deny",
			"Default policy the running proxy is in (allow | deny).")
		cmd.Flags().StringVar(&dialectStr, "dialect", "postgres",
			"Default SQL dialect dbounce_decide parses with when the caller "+
				"doesn't pass an explicit dialect arg. Accepts postgres | "+
				"mysql | snowflake | bigquery. snowflake + bigquery ship via "+
				"the JDBC-driver-shim (see docs/SHIM-INTEGRATION.md).")
		cmd.Flags().StringVar(&owner, "owner", "",
			"Task-owner slot. Empty = default-owner slot (single-laptop).")
		cmd.Flags().StringVar(&actor, "actor", "",
			"Actor name recorded in audit rows when MCP-initiated mutations land "+
				"(default: 'dbounce-mcp').")
	}

	parent := &cobra.Command{
		Use:   "mcp",
		Short: "MCP-over-stdio server + agent-client install helpers",
		Long: `MCP-over-stdio server + install helpers for the common agent
clients (Claude Code, Cursor, Codex).

Subcommands:

  dbounce mcp serve                 start the JSON-RPC stdio server
  dbounce mcp install-claude-code   wire dbounce into Claude Code / Desktop
  dbounce mcp install-cursor        wire dbounce into Cursor
  dbounce mcp install-codex         print Codex TOML snippet (manual install)
  dbounce mcp show-config           print the canonical JSON / YAML snippet
  dbounce mcp list-tools            print the dbounce_* tool list

For backward compatibility ` + "`dbounce mcp`" + ` with no subcommand
still starts the server (same as ` + "`dbounce mcp serve`" + `).

The MCP server reads the SAME on-disk state the running proxy uses
(--db + --profiles-path). It does NOT start a proxy listener of its
own — run ` + "`dbounce run`" + ` separately for the gating + forwarding
layer.

stdin/stdout are reserved for the JSON-RPC stream; logs + banner go
to stderr so they don't poison the wire.`,
		Args: cobra.ArbitraryArgs,
		RunE: runServe,
	}
	addServeFlags(parent)

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the MCP-over-stdio server (canonical name)",
		Long: `Run the dbounce MCP server on stdin/stdout (canonical name;
` + "`dbounce mcp`" + ` with no subcommand still works for back-compat).

This is the command the install-* subcommands generate config for —
the agent spawns ` + "`dbounce mcp serve`" + ` and speaks JSON-RPC 2.0
on stdin/stdout.`,
		Args: cobra.NoArgs,
		RunE: runServe,
	}
	addServeFlags(serveCmd)
	parent.AddCommand(serveCmd)

	parent.AddCommand(newMCPInstallClaudeCodeCmd())
	parent.AddCommand(newMCPInstallCursorCmd())
	parent.AddCommand(newMCPInstallCodexCmd())
	parent.AddCommand(newMCPShowConfigCmd())
	parent.AddCommand(newMCPListToolsCmd())
	return parent
}

// newMCPInstallClaudeCodeCmd implements `dbounce mcp install-claude-code`.
func newMCPInstallClaudeCodeCmd() *cobra.Command {
	var (
		path  string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "install-claude-code",
		Short: "Install dbounce as an MCP server in Claude Code / Claude Desktop",
		Long: `Add (or update) the ` + "`dbounce`" + ` MCP server entry in your
Claude Code / Claude Desktop MCP config file.

Default config path detection (first that exists wins; otherwise the
first candidate is used as a fresh-install target):

  macOS    ~/Library/Application Support/Claude/claude_desktop_config.json
           ~/.config/claude-code/mcp.json
           ~/.claude.json
  Linux    ~/.config/Claude/claude_desktop_config.json
           ~/.config/claude-code/mcp.json
           ~/.claude.json
  Windows  %APPDATA%/Claude/claude_desktop_config.json
           ~/.claude.json

Override with --path. The merge preserves any OTHER mcpServers
entries; the dbounce entry is REPLACED (not appended) so re-running
is idempotent.

After install, restart your MCP client so it re-reads the config.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := mcpinstall.InstallClaudeCode(mcpinstall.Options{
				Path:   path,
				Force:  force,
				Out:    cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
			return err
		},
	}
	cmd.Flags().StringVar(&path, "path", "",
		"Override the auto-detected config path.")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite malformed existing config without prompting.")
	return cmd
}

// newMCPInstallCursorCmd implements `dbounce mcp install-cursor`.
func newMCPInstallCursorCmd() *cobra.Command {
	var (
		path  string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "install-cursor",
		Short: "Install dbounce as an MCP server in Cursor",
		Long: `Add (or update) the ` + "`dbounce`" + ` MCP server entry in your
Cursor MCP config.

Default config path: ~/.cursor/mcp.json (global).

The merge preserves any OTHER mcpServers entries; the dbounce entry
is REPLACED (not appended) so re-running is idempotent.

After install, restart Cursor so it re-reads the config.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := mcpinstall.InstallCursor(mcpinstall.Options{
				Path:   path,
				Force:  force,
				Out:    cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
			return err
		},
	}
	cmd.Flags().StringVar(&path, "path", "",
		"Override the auto-detected config path (default: ~/.cursor/mcp.json).")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite malformed existing config without prompting.")
	return cmd
}

// newMCPInstallCodexCmd implements `dbounce mcp install-codex`.
func newMCPInstallCodexCmd() *cobra.Command {
	var (
		path  string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "install-codex",
		Short: "Print the Codex MCP server snippet (manual install)",
		Long: `Codex stores MCP config in TOML (~/.codex/config.toml). To avoid
corrupting unrelated keys in the operator's TOML config, dbounce
refuses to edit the TOML file in place + instead prints a snippet
the operator pastes into their Codex config.

If you maintain a JSON-shaped Codex config elsewhere, pass
--path /full/path/to/file.json — dbounce installs into JSON files
the same way it does for Claude Code / Cursor.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := mcpinstall.InstallCodex(mcpinstall.Options{
				Path:   path,
				Force:  force,
				Out:    cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
			return err
		},
	}
	cmd.Flags().StringVar(&path, "path", "",
		"Override the default Codex config path. Pass a .json path to "+
			"install into a JSON-shaped Codex MCP config; .toml paths "+
			"are not edited in place.")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite malformed existing JSON config without prompting.")
	return cmd
}

// newMCPShowConfigCmd implements `dbounce mcp show-config`.
func newMCPShowConfigCmd() *cobra.Command {
	var shape string
	cmd := &cobra.Command{
		Use:   "show-config",
		Short: "Print the canonical MCP server config snippet",
		Long: `Print the JSON (or YAML, with --shape yaml) snippet for any
custom MCP client. Vendor-neutral — paste into any MCP-compatible
agent's config.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return mcpinstall.ShowConfig(cmd.OutOrStdout(), mcpinstall.Shape(shape))
		},
	}
	cmd.Flags().StringVar(&shape, "shape", string(mcpinstall.ShapeJSON),
		"Output shape: json | yaml.")
	return cmd
}

// newMCPListToolsCmd implements `dbounce mcp list-tools`.
func newMCPListToolsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-tools",
		Short: "Print the dbounce_* MCP tool list (name + 1-line summary)",
		Long: `Print the tool descriptors served by the dbounce MCP server
as a 2-column table (name + 1-line summary).

The list is the same one ` + "`tools/list`" + ` returns to an agent client,
so an operator who ran ` + "`dbounce mcp install-claude-code`" + ` can
verify their install worked without restarting their agent.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			descriptors := mcp.ToolDescriptors()
			entries := make([]mcpinstall.ToolListEntry, 0, len(descriptors))
			for _, d := range descriptors {
				name, _ := d["name"].(string)
				desc, _ := d["description"].(string)
				entries = append(entries, mcpinstall.ToolListEntry{
					Name:        name,
					Description: desc,
				})
			}
			return mcpinstall.FormatToolList(cmd.OutOrStdout(), entries)
		},
	}
	return cmd
}
