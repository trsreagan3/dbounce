// #276 — `GET /schemas/config` HTTP endpoint for dbounce.
//
// Serves the published `schemas/dbounce-config.schema.json`
// byte-for-byte on the running bouncer's mgmt port so an agent can
// fetch the authoritative wire shape without reaching out to
// GitHub.
//
// Per [[cross-product-agent-parity]]: every Bounce product exposes
// the same endpoint with its own product schema. The endpoint
// contract:
//
//	GET /schemas/config
//	Content-Type: application/schema+json
//	Body: the embedded `dbounce-config.schema.json` bytes
//
// No auth required. The schema is non-sensitive metadata — the
// same file ships in the repo under `schemas/dbounce-config.schema.json`.
// Per [[self-host-zero-billing-dependency]]: the bytes are embedded
// at build time via //go:embed (no runtime fetch).
package proxy

import (
	_ "embed"
	"net/http"
)

//go:embed schemas_config.json
var embeddedConfigSchema []byte

// schemasConfigHandler implements `GET /schemas/config`. Returns the
// embedded schema bytes with Content-Type: application/schema+json
// (the IANA-registered media type for JSON Schema documents).
//
// Defensive: a non-GET verb returns 405; the schema is read-only.
func schemasConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/schema+json; charset=utf-8")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(embeddedConfigSchema)
}
