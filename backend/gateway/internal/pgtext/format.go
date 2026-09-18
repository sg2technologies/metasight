// Package pgtext formats Go values (as decoded by pgx from a real query
// result) back into Postgres's text wire format, since the gateway's
// client-facing protocol only implements text-format DataRow (Simple Query
// protocol never needs binary format). Every column goes through this —
// not just masked ones — so masking (internal/masking) operates on the
// same already-text-encoded strings a real Postgres backend would have
// sent, keeping the two packages' concerns separate.
//
// Not necessarily byte-for-byte identical to Postgres's own formatter in
// every edge case (e.g. exact numeric/interval formatting) — good enough
// for the values this product's rewriter/masking pipeline actually deals
// with, documented as a fast-follow if a mismatch ever matters.
package pgtext

import (
	"encoding/hex"
	"fmt"
	"time"
)

// Format converts a decoded Go value into its Postgres text representation.
// Returns nil for SQL NULL (the caller encodes that as a -1 length DataRow
// field, not an empty string).
func Format(v any) *string {
	if v == nil {
		return nil
	}
	var s string
	switch val := v.(type) {
	case bool:
		if val {
			s = "t"
		} else {
			s = "f"
		}
	case []byte:
		s = "\\x" + hex.EncodeToString(val)
	case time.Time:
		s = val.Format("2006-01-02 15:04:05.999999-07")
	case string:
		s = val
	case fmt.Stringer:
		s = val.String()
	default:
		s = fmt.Sprintf("%v", val)
	}
	return &s
}
