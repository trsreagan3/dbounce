// dynamic_deny_reload.go — #324c POST /admin/dynamic-denies/reload
// handler on the mgmt port (default 8768).
//
// The handler triggers an immediate reload of the dynamic-deny YAML
// from disk + returns a structured JSON payload describing the result.
// Useful for the cross-bouncer fan-out CLI (#324e), which will write
// the YAML on the operator's host + call this endpoint on each Bounce
// product's mgmt port to confirm "rules are live."
//
// Success shape:
//
//	HTTP 200 application/json
//	{
//	  "reloaded": true,
//	  "rules_count": N,
//	  "rules_applied_to_dbounce": M,
//	  "instance_denied": bool,
//	  "denying_rule_id": "dd_..." | null,
//	  "path": "/home/.../dynamic-denies.yaml"
//	}
//
// Error shape (parse / schema failure on the file):
//
//	HTTP 422 application/json
//	{
//	  "reloaded": false,
//	  "error": "<structured error>",
//	  "previous_rules_count": N
//	}
//
// Other error shapes:
//
//	HTTP 405: non-POST verb
//	HTTP 401 / 403: bearer-token gate (mirrors /audit/events)
//	HTTP 503: watcher not configured (operator passed --disable-dynamic-denies
//	          OR no path could be resolved)
//
// Per [[cross-product-agent-parity]] the shape ships identically in
// gbounce + ibounce + kbounce; the cross-bouncer CLI keys on the same
// JSON shape regardless of which product replied. The dbounce-specific
// `instance_denied` + `denying_rule_id` fields are the new bits in this
// product's response (because dbounce's gate is connection-level vs the
// per-request matchers in the other products).

package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/trsreagan3/dbounce/internal/dynamicdeny"
)

// dynamicDenyReloadHandler builds the POST /admin/dynamic-denies/reload
// handler. Pass requireBearer="" to allow unauthenticated requests
// (loopback-only deploys); a non-empty token gates external binds.
func (s *Server) dynamicDenyReloadHandler(requireBearer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeDDReloadError(w, http.StatusMethodNotAllowed, "only POST is supported")
			return
		}
		if requireBearer != "" {
			ah := r.Header.Get("Authorization")
			if ah == "" {
				writeDDReloadError(w, http.StatusUnauthorized, "Authorization: Bearer <token> required")
				return
			}
			tok, ok := parseBearerHeader(ah)
			if !ok || tok != requireBearer {
				writeDDReloadError(w, http.StatusForbidden, "bearer token rejected")
				return
			}
		}
		if s.dynamicDeny == nil {
			writeDDReloadError(w, http.StatusServiceUnavailable,
				"dynamic-deny watcher not configured (dbounce was started without --dynamic-denies-path OR with --disable-dynamic-denies)")
			return
		}
		rs, err := s.dynamicDeny.ReloadNow(dynamicdeny.ReasonReloadRequested)
		if err != nil {
			prev := 0
			if rs != nil {
				prev = len(rs.Rules)
			}
			body := map[string]any{
				"reloaded":             false,
				"error":                err.Error(),
				"previous_rules_count": prev,
				"path":                 s.dynamicDeny.Path(),
			}
			writeDDReloadJSON(w, http.StatusUnprocessableEntity, body)
			return
		}
		s.BumpDynamicDenyReload()
		ruleID, _ := s.dynamicDeny.DenyingRule()
		body := map[string]any{
			"reloaded":                  true,
			"rules_count":               len(rs.Rules),
			"rules_applied_to_dbounce":  len(rs.Rules),
			"instance_denied":           s.dynamicDeny.InstanceDenied(),
			"denying_rule_id":           emptyToNil(ruleID),
			"path":                      s.dynamicDeny.Path(),
		}
		writeDDReloadJSON(w, http.StatusOK, body)
	}
}

// emptyToNil returns nil for the empty string so the JSON-encoded
// response surfaces `"denying_rule_id": null` rather than `""` —
// callers parsing the field can pivot on nil-ness cleanly.
func emptyToNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// writeDDReloadError emits a structured-error JSON body with the given
// status code.
func writeDDReloadError(w http.ResponseWriter, status int, msg string) {
	writeDDReloadJSON(w, status, map[string]any{
		"reloaded": false,
		"error":    msg,
	})
}

// writeDDReloadJSON writes an arbitrary JSON body with the given status
// code. Local helper so the handler doesn't pull on the audit_events
// response helpers (which are scoped to the audit-events shape).
func writeDDReloadJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
