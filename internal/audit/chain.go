// Tamper-evident hash-chain for the audit-export JSONL stream —
// ADOPT-10 / #734 / #624. Port of the Python ibounce implementation
// (src/iam_jit/bouncer/audit_export/chain.py + the shared _hash_event
// in src/iam_jit/audit.py). The on-disk wire format is BYTE-IDENTICAL
// to the Python format AND identical across all three Go bouncers
// (gbounce / kbouncer / dbounce) — a tamper-evident log is worthless
// if bouncers chain differently, so the canonicalization, hash
// preimage, chain-block placement, and state-file shape all match
// exactly. See chain_vectors_test.go for the cross-impl assertion.
//
// Each emitted OCSF event gains three fields under
// unmapped.iam_jit.audit_chain:
//
//   - seq        monotonic; gaps reveal deletion
//   - prev_hash  previous row's SHA-256 hex, or null on genesis
//   - hash       this row's hash; covers prev_hash + the row's
//                canonical-JSON payload (event WITHOUT the chain block)
//
// Hash preimage (matches audit.py:_hash_event exactly):
//
//	sha256( (prev_hash || "") ++ canonical({"seq":seq,"prev_hash":prev_hash,"event":event}) )
//
// where canonical() == Python json.dumps(sort_keys=True,
// separators=(",",":"), ensure_ascii=True): sorted keys, compact
// separators, non-ASCII escaped to \uXXXX (with surrogate pairs for
// astral code points), and HTML-significant chars (< > &) NOT escaped.
// See canonicalJSON below.
//
// Per [[creates-never-mutates]] the chain block is ADDITIVE — the
// existing OCSF shape is preserved verbatim.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Field names inside the OCSF event's unmapped.iam_jit.audit_chain
// block. Kept as constants so verify + tests reference the same
// strings.
const (
	ChainField         = "audit_chain"
	ChainSeqField      = "seq"
	ChainPrevHashField = "prev_hash"
	ChainHashField     = "hash"
)

// ChainStateFilename is the persistent chain-state file inside the
// audit log directory. JSON for trivial readability; written 0o600.
const ChainStateFilename = "audit-chain-state.json"

// ChainStateSchemaVersion stamps the state file. Bump only when the
// on-disk shape changes in a way an older verifier can't read. Matches
// the Python CHAIN_STATE_SCHEMA_VERSION.
const ChainStateSchemaVersion = 1

// DefaultSaveEveryNEvents persists chain state to disk every N stamped
// events. Matches the Python default (50).
const DefaultSaveEveryNEvents = 50

// canonicalJSON encodes v exactly as Python's
// json.dumps(v, sort_keys=True, separators=(",",":"), ensure_ascii=True).
//
// Go's encoding/json already sorts map keys lexically and uses compact
// separators, so json.Marshal(map[string]any) matches the sort_keys +
// separators part. Two divergences from the Python default are
// corrected here:
//
//  1. HTML escaping — Go escapes < > & to < etc. by default;
//     Python does not. We disable it via Encoder.SetEscapeHTML(false).
//  2. ensure_ascii — Python escapes every non-ASCII rune to \uXXXX
//     (surrogate pairs for code points > U+FFFF); Go emits raw UTF-8.
//     asciiEscape() rewrites the compact output to match.
//
// CRITICAL: callers MUST decode untrusted JSON with a Decoder whose
// UseNumber() is set, so integers survive the round-trip as
// json.Number rather than becoming float64 (which would re-marshal as
// e.g. 1700000000000 vs 1.7e+12 and silently diverge from Python — the
// [[config-export-wire-divergence]] failure mode). See decodeJSONNumber.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encoder.Encode appends a trailing newline; strip it.
	out := bytes.TrimRight(buf.Bytes(), "\n")
	return asciiEscape(out), nil
}

// asciiEscape rewrites every non-ASCII byte sequence in already-valid
// compact JSON to \uXXXX escapes (surrogate pairs for astral chars),
// matching Python's ensure_ascii=True. Non-ASCII bytes only ever
// appear inside JSON string literals in compact output, so a byte-wise
// scan is safe.
func asciiEscape(b []byte) []byte {
	// Fast path: pure ASCII needs no rewrite.
	if isASCII(b) {
		return b
	}
	var out strings.Builder
	out.Grow(len(b) + 8)
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			out.WriteByte(c)
			i++
			continue
		}
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8 byte; emit the replacement-char escape so
			// output stays deterministic. Should not happen for valid
			// JSON produced by encoding/json.
			out.WriteString("\\ufffd")
			i++
			continue
		}
		if r > 0xFFFF {
			r -= 0x10000
			hi := 0xD800 + (r >> 10)
			lo := 0xDC00 + (r & 0x3FF)
			fmt.Fprintf(&out, "\\u%04x\\u%04x", hi, lo)
		} else {
			fmt.Fprintf(&out, "\\u%04x", r)
		}
		i += size
	}
	return []byte(out.String())
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

// decodeJSONNumber decodes raw JSON into a generic any tree using
// json.Number for all numbers, so integers survive canonicalization
// without becoming float64. Used by the stamper and verifier.
func decodeJSONNumber(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// hashEvent computes the chain hash for one row. Matches Python
// audit.py:_hash_event exactly:
//
//	h = sha256()
//	h.update((prev_hash or "").encode("utf-8"))
//	h.update(canonical({"seq":seq,"prev_hash":prev_hash,"event":event}))
//	return h.hexdigest()
//
// eventTree is the event decoded with json.Number (no chain block).
// prevHash is nil on genesis.
func hashEvent(prevHash *string, seq int64, eventTree any) (string, error) {
	payload := map[string]any{
		"seq":       jsonInt(seq),
		"prev_hash": prevHashAny(prevHash),
		"event":     eventTree,
	}
	canon, err := canonicalJSON(payload)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if prevHash != nil {
		h.Write([]byte(*prevHash))
	}
	// else: prev_hash || "" — write nothing.
	h.Write(canon)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// jsonInt returns a json.Number for an int so canonicalJSON emits it as
// an integer literal (matching Python's int), never as a float.
func jsonInt(n int64) json.Number {
	return json.Number(fmt.Sprintf("%d", n))
}

// prevHashAny converts the *string prev hash into the value Python puts
// in the payload: the string, or nil (→ JSON null).
func prevHashAny(prevHash *string) any {
	if prevHash == nil {
		return nil
	}
	return *prevHash
}

// ChainState is the in-memory + on-disk state for one bouncer's audit
// chain. The LogWriter worker owns the only live instance; Stamp
// mutates it under stateMu.
type ChainState struct {
	mu              sync.Mutex
	nextSeq         int64
	lastHash        *string // hex of most-recent stamped event; nil on genesis
	logDir          string
	stateFileAbsent bool // true when LoadChainState found no prior state
	saveEveryN      int
	eventsSinceSave int
}

// NextSeq returns the seq the next stamped event will get (0 = genesis
// not yet stamped). Safe for concurrent read.
func (c *ChainState) NextSeq() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nextSeq
}

// HeadHash returns the chain head hash (hex) or "" when nothing has
// been stamped yet.
func (c *ChainState) HeadHash() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastHash == nil {
		return ""
	}
	return *c.lastHash
}

// HeadSeq returns the seq of the last stamped event, or -1 when nothing
// has been stamped.
func (c *ChainState) HeadSeq() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nextSeq - 1
}

// StateFileAbsent reports whether LoadChainState found no prior state
// (a fresh / re-anchored chain). Surfaced on /healthz so an operator
// sees a restart-without-state discontinuity honestly.
func (c *ChainState) StateFileAbsent() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stateFileAbsent
}

// chainBlock is the JSON shape that lands at
// unmapped.iam_jit.audit_chain. seq is an int; prev_hash is a string or
// null; hash is a string.
type chainBlock struct {
	Seq      int64   `json:"seq"`
	PrevHash *string `json:"prev_hash"`
	Hash     string  `json:"hash"`
}

// StampJSON takes a marshaled OCSF event (the bytes the LogWriter would
// have written), computes the chain hash over the event WITHOUT any
// pre-existing chain block, injects the chain block at
// unmapped.iam_jit.audit_chain, and returns the augmented JSON bytes
// (compact, key-sorted — same canonical form the hash covers plus the
// chain block). It advances the chain state and periodically persists.
//
// Returning the canonical (key-sorted) JSON for the on-disk row means
// the verifier re-derives the exact same preimage by stripping the
// chain block — no dependency on the writer's struct field order.
func (c *ChainState) StampJSON(eventJSON []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	tree, err := decodeJSONNumber(eventJSON)
	if err != nil {
		return nil, fmt.Errorf("audit chain: decode event: %w", err)
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("audit chain: event is not a JSON object")
	}
	// Ensure unmapped.iam_jit exists as a map, and strip any existing
	// chain block so the hash never chases its own tail (idempotency).
	iamJit := ensureIamJit(obj)
	delete(iamJit, ChainField)

	seq := c.nextSeq
	prev := c.lastHash
	h, err := hashEvent(prev, seq, tree)
	if err != nil {
		return nil, err
	}
	// Inject the chain block. Use json.Number for seq so re-marshal
	// keeps it an integer.
	block := map[string]any{
		ChainSeqField:      jsonInt(seq),
		ChainPrevHashField: prevHashAny(prev),
		ChainHashField:     h,
	}
	iamJit[ChainField] = block

	// Write the canonical (key-sorted, compact, ASCII-escaped, no HTML
	// escape) on-disk form so the row is byte-identical regardless of
	// which bouncer wrote it AND so the verifier re-derives the exact
	// preimage by stripping the chain block.
	out, err := canonicalJSON(tree)
	if err != nil {
		return nil, err
	}

	hh := h
	c.lastHash = &hh
	c.nextSeq = seq + 1
	c.eventsSinceSave++
	if c.eventsSinceSave >= c.saveEveryN {
		// Fail-soft: a state-save error does not stop the chain. The
		// next save may succeed; verify re-derives from the JSONL.
		_ = c.saveLocked()
		c.eventsSinceSave = 0
	}
	return out, nil
}

// ensureIamJit returns obj["unmapped"]["iam_jit"] as a map[string]any,
// creating the path if absent or wrongly typed.
func ensureIamJit(obj map[string]any) map[string]any {
	unmapped, ok := obj["unmapped"].(map[string]any)
	if !ok {
		unmapped = map[string]any{}
		obj["unmapped"] = unmapped
	}
	iamJit, ok := unmapped["iam_jit"].(map[string]any)
	if !ok {
		iamJit = map[string]any{}
		unmapped["iam_jit"] = iamJit
	}
	return iamJit
}

// StatePath returns the chain-state file path for a log dir.
func StatePath(logDir string) string {
	return filepath.Join(logDir, ChainStateFilename)
}

// chainStateFile is the on-disk JSON shape. Matches the Python
// save_state payload (schema_version, next_seq, last_hash,
// saved_at_unix).
type chainStateFile struct {
	SchemaVersion int     `json:"schema_version"`
	NextSeq       int64   `json:"next_seq"`
	LastHash      *string `json:"last_hash"`
	SavedAtUnix   int64   `json:"saved_at_unix"`
}

// LoadChainState loads (or initializes) the chain state for logDir. A
// missing or corrupt state file yields a fresh state at seq 0 with
// StateFileAbsent() true, so the discontinuity surfaces on /healthz +
// the next verify rather than being silently swallowed.
func LoadChainState(logDir string, saveEveryN int) *ChainState {
	if saveEveryN <= 0 {
		saveEveryN = DefaultSaveEveryNEvents
	}
	st := &ChainState{
		logDir:     logDir,
		saveEveryN: saveEveryN,
	}
	raw, err := os.ReadFile(StatePath(logDir))
	if err != nil {
		st.stateFileAbsent = true
		return st
	}
	var f chainStateFile
	if err := json.Unmarshal(raw, &f); err != nil {
		st.stateFileAbsent = true
		return st
	}
	st.nextSeq = f.NextSeq
	st.lastHash = f.LastHash
	return st
}

// Save persists the current chain state (atomic write, 0o600). No-op
// when logDir is empty.
func (c *ChainState) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saveLocked()
}

func (c *ChainState) saveLocked() error {
	if c.logDir == "" {
		return nil
	}
	f := chainStateFile{
		SchemaVersion: ChainStateSchemaVersion,
		NextSeq:       c.nextSeq,
		LastHash:      c.lastHash,
		SavedAtUnix:   time.Now().Unix(),
	}
	// Match Python's json.dumps(sort_keys=True) + trailing newline.
	body, err := json.Marshal(f)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := os.MkdirAll(c.logDir, 0o700); err != nil {
		return err
	}
	target := StatePath(c.logDir)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}
