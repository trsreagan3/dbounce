// D-Slice 4 — `dbounce init-tls` cobra command.
//
// `init-tls` is a tiny shim around internal/tlsmat.GenerateCAAndServerCert.
// The shape mirrors `kbounce init-tls` so the operator's muscle memory
// carries between products (per [[cross-product-agent-parity]]).
//
// Per [[creates-never-mutates]]: this command CREATES files under the
// caller-supplied (or default) out-dir. It refuses to silently overwrite
// existing material — operators must pass --force to rotate.

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/tlsmat"
)

func newInitTLSCmd() *cobra.Command {
	var (
		outDir         string
		withClientCert bool
		force          bool
	)
	cmd := &cobra.Command{
		Use:   "init-tls",
		Short: "Generate a self-signed CA + server cert for local dbounce TLS",
		Long: `init-tls writes ca.crt + server.crt + server.key (and
optionally client.crt + client.key) into ~/.dbounce/tls/ — or whatever
--out points at.

The generated material is self-signed and intended for LOCAL
development:

  ca.crt        the local CA (clients add this to their trust store).
  server.crt    the server cert SAN-bound to localhost + 127.0.0.1.
  server.key    matching private key (file mode 0600).
  client.crt    (only when --with-client-cert is set) client cert
                signed by the same CA — used for mTLS.
  client.key    matching private key for the client cert.

Run dbounce with the generated cert + key:

  dbounce run \
    --listener-tls-cert ~/.dbounce/tls/server.crt \
    --listener-tls-key  ~/.dbounce/tls/server.key

To also accept HTTPS health checks:

  dbounce run \
    --management-tls-cert ~/.dbounce/tls/server.crt \
    --management-tls-key  ~/.dbounce/tls/server.key

To require client certs (mTLS):

  dbounce init-tls --with-client-cert
  dbounce run \
    --listener-tls-cert        ~/.dbounce/tls/server.crt \
    --listener-tls-key         ~/.dbounce/tls/server.key \
    --listener-tls-client-ca   ~/.dbounce/tls/ca.crt \
    --require-client-cert

By default init-tls refuses to overwrite existing files; pass --force
to rotate.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if outDir == "" {
				outDir = tlsmat.DefaultOutDir()
				if outDir == "" {
					return fmt.Errorf(
						"dbounce init-tls: could not resolve $HOME for default --out " +
							"(pass --out explicitly)")
				}
			}
			res, err := tlsmat.GenerateCAAndServerCert(tlsmat.Options{
				OutDir:            outDir,
				WithClientCert:    withClientCert,
				OverwriteExisting: force,
			})
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "dbounce init-tls: wrote certs to %s\n", res.OutDir)
			fmt.Fprintf(w, "  ca.crt        : %s\n", res.CACertPath)
			fmt.Fprintf(w, "  server.crt    : %s\n", res.ServerCertPath)
			fmt.Fprintf(w, "  server.key    : %s\n", res.ServerKeyPath)
			if res.ClientCertPath != "" {
				fmt.Fprintf(w, "  client.crt    : %s\n", res.ClientCertPath)
				fmt.Fprintf(w, "  client.key    : %s\n", res.ClientKeyPath)
			}
			fmt.Fprintln(w, "\nNext step: pass --listener-tls-cert + --listener-tls-key to `dbounce run`.")
			return nil
		},
	}
	cmd.Flags().StringVar(&outDir, "out", "",
		"Destination directory (default: ~/.dbounce/tls).")
	cmd.Flags().BoolVar(&withClientCert, "with-client-cert", false,
		"Also issue a client.crt + client.key pair signed by the same CA, "+
			"for clients that connect with mTLS (--require-client-cert on the listener).")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite any existing cert/key files in --out. Default refuses to "+
			"rotate so clients that already trust the CA don't see surprise breakage.")
	// Mirror kbounce + ibounce's stderr-banner pattern: write the
	// security-sensitive reminder before the cobra success exit. The
	// banner goes to stderr so JSON-consuming scrapers reading stdout
	// stay clean. Tests assert on the stdout body, so this stderr write
	// is invisible to them.
	cmd.PostRun = func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(os.Stderr,
			"\n(reminder) The generated keys are PRIVATE; do not check them into git.")
	}
	return cmd
}
