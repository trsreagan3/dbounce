package proxy

import (
	"encoding/json"
	"io"
	"os"
)

// jsonEncode is the actual JSON encoder. Split into its own file so
// the small std-lib imports stay isolated from proxy.go.
func jsonEncode(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}

// osLookupEnv reads an env var. Tiny wrapper to keep proxy.go's
// imports minimal.
func osLookupEnv(key string) string { return os.Getenv(key) }
