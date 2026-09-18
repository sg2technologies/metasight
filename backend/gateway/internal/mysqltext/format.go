// Package mysqltext formats Go values (as decoded by database/sql from a
// real MySQL query result) into text, the same way internal/pgtext does for
// Postgres — every column goes through this, not just masked ones, so
// masking (internal/masking) operates on the same already-text-encoded
// strings regardless of which wire protocol is fronting the query. Go
// strings are arbitrary byte sequences (not required to be valid UTF-8), so
// round-tripping a BLOB/BINARY column through *string and back to []byte is
// lossless — no hex-escaping needed the way Postgres's bytea literal syntax
// requires.
//
// Not necessarily byte-for-byte identical to MySQL's own text-protocol
// encoding in every edge case — good enough for the values this product's
// rewriter/masking pipeline actually deals with, same tradeoff pgtext
// documents.
package mysqltext

import (
	"fmt"
	"time"
)

// Format converts a decoded Go value into its MySQL text representation.
// Returns nil for SQL NULL.
func Format(v any) *string {
	if v == nil {
		return nil
	}
	var s string
	switch val := v.(type) {
	case bool:
		// MySQL has no native boolean wire type (TINYINT(1) is the
		// convention) — database/sql never actually hands us a Go bool from
		// a real column scan, but "1"/"0" matches MySQL's own convention
		// if one ever appears, unlike Postgres's "t"/"f".
		if val {
			s = "1"
		} else {
			s = "0"
		}
	case []byte:
		s = string(val)
	case time.Time:
		s = val.Format(time.DateTime) // "2006-01-02 15:04:05" — matches mysql.FormatTextValue's own convention
	case string:
		s = val
	case fmt.Stringer:
		s = val.String()
	default:
		s = fmt.Sprintf("%v", val)
	}
	return &s
}
