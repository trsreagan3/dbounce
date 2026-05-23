// profile_reload.go — #387 / §A25 Phase 2 POST /admin/profile/reload
// handler on the dbounce mgmt port (same port as
// /admin/dynamic-denies/reload).
//
// Re-reads ~/.dbounce/profiles.yaml from disk + hot-swaps the
// proxy's active profile pointer via SwapProfile so a `dbounce
// profile allow` mutation takes effect on the very next decision
// without a bouncer restart.
//
// Response shape mirrors ibounce + kbouncer byte-for-byte per
// [[cross-product-agent-parity]] modulo the field naming:
//
//	HTTP 200 application/json
//	{ "reloaded": true, "active_profile": "<name>",
//	  "rules_in_active_profile": N }
//
// Error shapes: 405 (non-POST), 401/403 (bearer-token gate),
// 400 (parse error), 409 (active profile missing from file).

package proxy

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"github.com/trsreagan3/dbounce/internal/profile"
)

func (s *Server) profileReloadHandler(requireBearer string, profilesPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeProfileReloadJSON(w, http.StatusMethodNotAllowed,
				map[string]any{"reloaded": false, "error": "only POST is supported"})
			return
		}
		if requireBearer != "" {
			ah := r.Header.Get("Authorization")
			if ah == "" {
				writeProfileReloadJSON(w, http.StatusUnauthorized,
					map[string]any{"reloaded": false, "error": "Authorization: Bearer <token> required"})
				return
			}
			tok, ok := parseBearerHeader(ah)
			// §A99 — constant-time compare; see audit_events.go.
			if !ok || subtle.ConstantTimeCompare([]byte(tok), []byte(requireBearer)) != 1 {
				writeProfileReloadJSON(w, http.StatusForbidden,
					map[string]any{"reloaded": false, "error": "bearer token rejected"})
				return
			}
		}

		current, currentName := s.loadActiveProfile()
		if current == nil || currentName == "" || currentName == profile.FullUserProfileName {
			// No active profile (or the passthrough sentinel).
			// Successful no-op per [[ibounce-honest-positioning]].
			writeProfileReloadJSON(w, http.StatusOK, map[string]any{
				"reloaded":                true,
				"no_active_profile":       true,
				"active_profile":          currentName,
				"rules_in_active_profile": 0,
			})
			return
		}

		resolvedPath := profilesPath
		if resolvedPath == "" {
			resolvedPath = s.ProfilesPath()
		}
		if resolvedPath == "" {
			rp, perr := profile.DefaultProfilesPath()
			if perr != nil {
				writeProfileReloadJSON(w, http.StatusInternalServerError, map[string]any{
					"reloaded": false,
					"error":    "resolve_path_failed",
					"detail":   perr.Error(),
				})
				return
			}
			resolvedPath = rp
		}

		fresh, lerr := profile.LoadProfiles(resolvedPath)
		if lerr != nil {
			writeProfileReloadJSON(w, http.StatusBadRequest, map[string]any{
				"reloaded":       false,
				"error":          "parse_error",
				"detail":         lerr.Error(),
				"active_profile": currentName,
			})
			return
		}

		resolved, aerr := fresh.Active(currentName)
		if aerr != nil {
			writeProfileReloadJSON(w, http.StatusConflict, map[string]any{
				"reloaded": false,
				"error":    "active_profile_missing_from_file",
				"detail": "active profile " + currentName +
					" no longer present in profiles.yaml; refusing to silently swap",
				"active_profile": currentName,
			})
			return
		}

		s.SwapProfile(resolved)
		writeProfileReloadJSON(w, http.StatusOK, map[string]any{
			"reloaded":                  true,
			"active_profile":            resolved.Name,
			"rules_in_active_profile":   len(resolved.AllowRules),
			"deny_actions_in_active_profile": len(resolved.DenyActions),
		})
	}
}

func writeProfileReloadJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
