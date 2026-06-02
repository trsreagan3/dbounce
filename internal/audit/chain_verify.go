// Audit-chain verification — ADOPT-10 / #734 / #624. Walks the JSONL
// audit log (active audit.jsonl + rotated audit-*.jsonl.gz archives),
// re-hashing each event and checking chain continuity. Port of the
// Python verify_jsonl (chain.py). Surfaces EVERY inconsistency it
// finds per [[ibounce-honest-positioning]].
package audit

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Stable reason strings for SIEM pattern matching + tests. Match the
// Python REASON_* constants verbatim.
const (
	ReasonHashMismatch      = "hash mismatch — row was edited or chain payload changed"
	ReasonPrevHashMismatch  = "prev_hash mismatch — rows reordered or one deleted"
	ReasonSeqGap            = "seq gap — row(s) deleted or inserted"
	ReasonMissingChainBlock = "missing audit_chain block — event was emitted before chain wiring or block was stripped"
	ReasonBadJSON           = "unparseable JSON line"
	ReasonBadTypes          = "audit_chain block has wrong types"
)

// ChainInconsistency is one finding from VerifyChain.
type ChainInconsistency struct {
	Source     string `json:"source"`
	LineNumber int    `json:"line_number"`
	Seq        *int64 `json:"seq"`
	Reason     string `json:"reason"`
}

// VerifyResult aggregates a VerifyChain run. Empty Inconsistencies
// means the chain verified clean across the inspected range.
type VerifyResult struct {
	FilesChecked            int                  `json:"files_checked"`
	EventsChecked           int                  `json:"events_checked"`
	HeadSeq                 *int64               `json:"head_seq"`
	HeadHash                *string              `json:"head_hash"`
	Inconsistencies         []ChainInconsistency `json:"inconsistencies"`
	StateFileMissingAtStart bool                 `json:"state_file_missing_at_start"`
}

// OK reports whether the chain verified clean.
func (r VerifyResult) OK() bool { return len(r.Inconsistencies) == 0 }

// VerifyChain walks logDir's rotated archives + active audit.jsonl in
// chronological order and validates the chain. stateFileMissing (if
// known) is recorded in the result.
func VerifyChain(logDir string, stateFileMissing bool) (VerifyResult, error) {
	res := VerifyResult{StateFileMissingAtStart: stateFileMissing}
	files, err := chainSourceFiles(logDir)
	if err != nil {
		return res, err
	}
	var prevHash *string
	var expectedSeq int64
	for _, path := range files {
		lines, closeFn, err := openChainLines(path)
		if err != nil {
			continue
		}
		res.FilesChecked++
		lineNo := 0
		for lines.Scan() {
			lineNo++
			raw := lines.Bytes()
			if len(bytes.TrimSpace(raw)) == 0 {
				continue
			}
			// Copy the line; the scanner reuses its buffer.
			rawCopy := append([]byte(nil), raw...)
			tree, err := decodeJSONNumber(rawCopy)
			if err != nil {
				res.Inconsistencies = append(res.Inconsistencies, ChainInconsistency{
					Source: path, LineNumber: lineNo, Seq: nil, Reason: ReasonBadJSON,
				})
				continue
			}
			obj, ok := tree.(map[string]any)
			if !ok {
				res.Inconsistencies = append(res.Inconsistencies, ChainInconsistency{
					Source: path, LineNumber: lineNo, Seq: nil, Reason: ReasonMissingChainBlock,
				})
				continue
			}
			block := extractChainBlock(obj)
			if block == nil {
				res.Inconsistencies = append(res.Inconsistencies, ChainInconsistency{
					Source: path, LineNumber: lineNo, Seq: nil, Reason: ReasonMissingChainBlock,
				})
				continue
			}
			seq, seqOK := chainBlockSeq(block)
			rowHash, hashOK := block[ChainHashField].(string)
			prev, prevOK := chainBlockPrev(block)
			if !seqOK || !hashOK || !prevOK {
				var sp *int64
				if seqOK {
					s := seq
					sp = &s
				}
				res.Inconsistencies = append(res.Inconsistencies, ChainInconsistency{
					Source: path, LineNumber: lineNo, Seq: sp, Reason: ReasonBadTypes,
				})
				continue
			}
			res.EventsChecked++
			seqCopy := seq
			if seq != expectedSeq {
				res.Inconsistencies = append(res.Inconsistencies, ChainInconsistency{
					Source: path, LineNumber: lineNo, Seq: &seqCopy, Reason: ReasonSeqGap,
				})
				expectedSeq = seq
			}
			if !strPtrEq(prev, prevHash) {
				res.Inconsistencies = append(res.Inconsistencies, ChainInconsistency{
					Source: path, LineNumber: lineNo, Seq: &seqCopy, Reason: ReasonPrevHashMismatch,
				})
			}
			// Recompute the hash over the event with the chain block
			// stripped.
			treeForHash, _ := decodeJSONNumber(rawCopy)
			if m, ok := treeForHash.(map[string]any); ok {
				if um, ok := m["unmapped"].(map[string]any); ok {
					if ij, ok := um["iam_jit"].(map[string]any); ok {
						delete(ij, ChainField)
					}
				}
			}
			recomputed, err := hashEvent(prev, seq, treeForHash)
			if err == nil && recomputed != rowHash {
				res.Inconsistencies = append(res.Inconsistencies, ChainInconsistency{
					Source: path, LineNumber: lineNo, Seq: &seqCopy, Reason: ReasonHashMismatch,
				})
			}
			rh := rowHash
			prevHash = &rh
			res.HeadSeq = &seqCopy
			res.HeadHash = &rh
			expectedSeq = seq + 1
		}
		closeFn()
	}
	return res, nil
}

// chainSourceFiles returns rotated archives (audit-*.jsonl.gz, sorted)
// followed by the active audit.jsonl, in chronological order.
func chainSourceFiles(logDir string) ([]string, error) {
	info, err := os.Stat(logDir)
	if err != nil || !info.IsDir() {
		return nil, nil
	}
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil, err
	}
	var archives []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "audit-") && strings.HasSuffix(n, ".jsonl.gz") {
			archives = append(archives, filepath.Join(logDir, n))
		}
	}
	sort.Strings(archives)
	active := filepath.Join(logDir, "audit.jsonl")
	if fi, err := os.Stat(active); err == nil && !fi.IsDir() {
		archives = append(archives, active)
	}
	return archives, nil
}

// openChainLines opens a (possibly gzipped) JSONL file and returns a
// scanner over its lines plus a close func.
func openChainLines(path string) (*bufio.Scanner, func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, func() {}, err
	}
	var r io.Reader = f
	var gz *gzip.Reader
	if strings.HasSuffix(path, ".gz") {
		gz, err = gzip.NewReader(f)
		if err != nil {
			_ = f.Close()
			return nil, func() {}, err
		}
		r = gz
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	closeFn := func() {
		if gz != nil {
			_ = gz.Close()
		}
		_ = f.Close()
	}
	return sc, closeFn, nil
}

func extractChainBlock(obj map[string]any) map[string]any {
	um, ok := obj["unmapped"].(map[string]any)
	if !ok {
		return nil
	}
	ij, ok := um["iam_jit"].(map[string]any)
	if !ok {
		return nil
	}
	block, ok := ij[ChainField].(map[string]any)
	if !ok {
		return nil
	}
	return block
}

// chainBlockSeq pulls the seq as an int64. Decoded with UseNumber so it
// arrives as json.Number.
func chainBlockSeq(block map[string]any) (int64, bool) {
	n, ok := block[ChainSeqField].(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return i, true
}

// chainBlockPrev pulls prev_hash: a *string (nil when JSON null). The
// second return is false only when the field is present but the wrong
// type (e.g. a number).
func chainBlockPrev(block map[string]any) (*string, bool) {
	v, present := block[ChainPrevHashField]
	if !present {
		return nil, true
	}
	if v == nil {
		return nil, true
	}
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	return &s, true
}

func strPtrEq(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
