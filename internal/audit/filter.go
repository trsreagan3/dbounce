// filter.go ships the cross-product filter expression parser + matcher
// used by both `dbounce audit tail --filter` (CLI) and
// GET /audit/events?filter=... (HTTP, #271).
//
// Lives in the audit package so both `internal/cli` (the CLI surface)
// and `internal/proxy` (the HTTP surface) can call into it without
// creating an import cycle.
//
// Grammar (per [[cross-product-agent-parity]] — ibounce + kbounce +
// gbounce ship the identical grammar):
//
//	field=value        string equality (case-sensitive)
//	field~regex        Go RE2 regex match
//	field>=N           numeric greater-or-equal
//	field<=N           numeric less-or-equal
//
// Field paths: dotted OCSF names (e.g. `actor.user.name`,
// `api.operation`, `unmapped.iam_jit.event_type`) + dbounce-specific
// fields under `unmapped.iam_jit.ext.*` (e.g.
// `unmapped.iam_jit.ext.dialect`, `unmapped.iam_jit.ext.statement_type`).
//
// Walks the projected OCSF Event struct (NOT a re-marshaled map) so
// nested-path lookups are zero-allocation in the hot path.

package audit

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// FilterOp is one of the four supported comparison ops.
type FilterOp int

const (
	FilterOpEq    FilterOp = iota // field=value
	FilterOpRegex                 // field~regex
	FilterOpGE                    // field>=N
	FilterOpLE                    // field<=N
)

// Filter is one parsed expression. Regex is non-nil only for
// FilterOpRegex; Number is populated only for FilterOpGE / FilterOpLE.
type Filter struct {
	Raw    string
	Field  string
	Op     FilterOp
	Value  string
	Number float64
	Regex  *regexp.Regexp
}

// ParseFilter parses one expression. Order matters: ">=" / "<=" are
// checked BEFORE "=" so `severity_id>=3` doesn't silently parse as
// field="severity_id>" + value="=3".
func ParseFilter(raw string) (Filter, error) {
	for _, op := range []struct {
		token string
		kind  FilterOp
	}{
		{">=", FilterOpGE},
		{"<=", FilterOpLE},
	} {
		if idx := strings.Index(raw, op.token); idx > 0 {
			field := strings.TrimSpace(raw[:idx])
			val := strings.TrimSpace(raw[idx+len(op.token):])
			if field == "" || val == "" {
				return Filter{}, fmt.Errorf("missing field or value around %q", op.token)
			}
			n, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return Filter{}, fmt.Errorf(
					"numeric value required for %q (got %q)", op.token, val)
			}
			return Filter{Raw: raw, Field: field, Op: op.kind, Value: val, Number: n}, nil
		}
	}
	if idx := strings.Index(raw, "~"); idx > 0 {
		field := strings.TrimSpace(raw[:idx])
		val := raw[idx+1:]
		if field == "" || val == "" {
			return Filter{}, errors.New(`missing field or value around "~"`)
		}
		re, err := regexp.Compile(val)
		if err != nil {
			return Filter{}, fmt.Errorf("invalid regex %q: %w", val, err)
		}
		return Filter{Raw: raw, Field: field, Op: FilterOpRegex, Value: val, Regex: re}, nil
	}
	if idx := strings.Index(raw, "="); idx > 0 {
		field := strings.TrimSpace(raw[:idx])
		val := raw[idx+1:]
		if field == "" {
			return Filter{}, errors.New(`missing field around "="`)
		}
		return Filter{Raw: raw, Field: field, Op: FilterOpEq, Value: val}, nil
	}
	return Filter{}, errors.New(
		"expected field=value, field~regex, field>=N, or field<=N")
}

// ParseFilters parses a slice of expressions. Empty input → nil.
// AND semantics — every filter must match for an event to qualify.
func ParseFilters(exprs []string) ([]Filter, error) {
	if len(exprs) == 0 {
		return nil, nil
	}
	out := make([]Filter, 0, len(exprs))
	for _, e := range exprs {
		f, err := ParseFilter(e)
		if err != nil {
			return nil, fmt.Errorf("invalid --filter %q: %w", e, err)
		}
		out = append(out, f)
	}
	return out, nil
}

// MatchAll returns true when every filter matches the projected event.
func MatchAll(ev Event, filters []Filter) bool {
	for _, f := range filters {
		if !MatchOne(ev, f) {
			return false
		}
	}
	return true
}

// MatchOne evaluates one filter against the projected event.
func MatchOne(ev Event, f Filter) bool {
	switch f.Op {
	case FilterOpEq:
		v, ok := LookupNestedString(ev, f.Field)
		if !ok {
			if n, nok := LookupNestedNumber(ev, f.Field); nok {
				return strconv.Itoa(int(n)) == f.Value
			}
			return false
		}
		return v == f.Value
	case FilterOpRegex:
		v, ok := LookupNestedString(ev, f.Field)
		if !ok {
			if n, nok := LookupNestedNumber(ev, f.Field); nok {
				return f.Regex.MatchString(strconv.Itoa(int(n)))
			}
			return false
		}
		return f.Regex.MatchString(v)
	case FilterOpGE:
		n, ok := LookupNestedNumber(ev, f.Field)
		if !ok {
			return false
		}
		return n >= f.Number
	case FilterOpLE:
		n, ok := LookupNestedNumber(ev, f.Field)
		if !ok {
			return false
		}
		return n <= f.Number
	}
	return false
}

// LookupNestedString resolves a dotted OCSF path to a string value.
// Returns ("", false) when the path doesn't resolve to a string (the
// caller can fall back to LookupNestedNumber). The dbounce-specific
// fallback walks unmapped.iam_jit.ext.* for ext-map fields.
func LookupNestedString(evt Event, path string) (string, bool) {
	switch path {
	case "severity":
		return evt.Severity, true
	case "status":
		return evt.Status, true
	case "status_detail":
		return evt.StatusDetail, true
	case "activity_name":
		return evt.ActivityName, true
	case "class_name":
		return evt.ClassName, true
	case "api.operation":
		return evt.API.Operation, true
	case "api.service.name":
		return evt.API.Service.Name, true
	case "api.request.uid":
		if evt.API.Request != nil {
			return evt.API.Request.UID, true
		}
		return "", true
	case "actor.user.name":
		if evt.Actor != nil && evt.Actor.User != nil {
			return evt.Actor.User.Name, true
		}
		return "", true
	case "actor.user.uid":
		if evt.Actor != nil && evt.Actor.User != nil {
			return evt.Actor.User.UID, true
		}
		return "", true
	case "actor.session.uid":
		if evt.Actor != nil && evt.Actor.Session != nil {
			return evt.Actor.Session.UID, true
		}
		return "", true
	case "src_endpoint.hostname":
		if evt.SrcEndpoint != nil {
			return evt.SrcEndpoint.Hostname, true
		}
		return "", true
	case "dst_endpoint.hostname":
		if evt.DstEndpoint != nil {
			return evt.DstEndpoint.Hostname, true
		}
		return "", true
	case "unmapped.iam_jit.event_type":
		if evt.Unmapped != nil {
			return evt.Unmapped.IAMJIT.EventType, true
		}
		return "", true
	case "unmapped.iam_jit.verdict":
		if evt.Unmapped != nil {
			return evt.Unmapped.IAMJIT.Verdict, true
		}
		return "", true
	case "unmapped.iam_jit.mode":
		if evt.Unmapped != nil {
			return evt.Unmapped.IAMJIT.Mode, true
		}
		return "", true
	case "unmapped.iam_jit.profile":
		if evt.Unmapped != nil {
			return evt.Unmapped.IAMJIT.Profile, true
		}
		return "", true
	case "unmapped.iam_jit.agent.name":
		if evt.Unmapped != nil && evt.Unmapped.IAMJIT.Agent != nil {
			return evt.Unmapped.IAMJIT.Agent.Name, true
		}
		return "", true
	case "unmapped.iam_jit.agent.session_id":
		if evt.Unmapped != nil && evt.Unmapped.IAMJIT.Agent != nil {
			return evt.Unmapped.IAMJIT.Agent.SessionID, true
		}
		return "", true
	case "unmapped.iam_jit.agent.detected_from":
		if evt.Unmapped != nil && evt.Unmapped.IAMJIT.Agent != nil {
			return string(evt.Unmapped.IAMJIT.Agent.DetectedFrom), true
		}
		return "", true
	}
	const extPrefix = "unmapped.iam_jit.ext."
	if strings.HasPrefix(path, extPrefix) && evt.Unmapped != nil {
		key := strings.TrimPrefix(path, extPrefix)
		if v, ok := evt.Unmapped.IAMJIT.Ext[key]; ok {
			switch tv := v.(type) {
			case string:
				return tv, true
			case []string:
				return strings.Join(tv, ","), true
			case bool:
				if tv {
					return "true", true
				}
				return "false", true
			case float64:
				return strconv.FormatFloat(tv, 'g', -1, 64), true
			case int:
				return strconv.Itoa(tv), true
			case int64:
				return strconv.FormatInt(tv, 10), true
			}
		}
	}
	return "", false
}

// LookupNestedNumber resolves a dotted path to a numeric field. Used
// for >= / <= and fallback equality when an OCSF numeric field is
// asked for as a string-equality predicate.
func LookupNestedNumber(evt Event, path string) (float64, bool) {
	switch path {
	case "severity_id":
		return float64(evt.SeverityID), true
	case "activity_id":
		return float64(evt.ActivityID), true
	case "status_id":
		return float64(evt.StatusID), true
	case "class_uid":
		return float64(evt.ClassUID), true
	case "category_uid":
		return float64(evt.CategoryUID), true
	case "type_uid":
		return float64(evt.TypeUID), true
	case "time":
		return float64(evt.Time), true
	case "src_endpoint.port":
		if evt.SrcEndpoint != nil {
			return float64(evt.SrcEndpoint.Port), true
		}
		return 0, false
	case "dst_endpoint.port":
		if evt.DstEndpoint != nil {
			return float64(evt.DstEndpoint.Port), true
		}
		return 0, false
	}
	const extPrefix = "unmapped.iam_jit.ext."
	if strings.HasPrefix(path, extPrefix) && evt.Unmapped != nil {
		key := strings.TrimPrefix(path, extPrefix)
		if v, ok := evt.Unmapped.IAMJIT.Ext[key]; ok {
			switch tv := v.(type) {
			case float64:
				return tv, true
			case int:
				return float64(tv), true
			case int64:
				return float64(tv), true
			}
		}
	}
	return 0, false
}
