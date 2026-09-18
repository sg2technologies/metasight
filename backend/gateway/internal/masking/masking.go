// Package masking is a Go port of enterprise/sdk/metasight_sdk/masking.py's
// value-formatting functions, which are themselves a vendored, diff-checked
// copy of backend/app/services/masking.py. Masking must happen here,
// gateway-side, because the gateway (not the Python backend) executes the
// query and holds the raw rows — same reasoning as the SDK's client-side
// masking, just on the network-proxy side of the split instead of inside
// the application's own process.
//
// KEEP IN SYNC with backend/app/services/masking.py's per-type formatters —
// if that file's masking rules change, apply the same change here and in
// metasight_sdk/masking.py.
package masking

import (
	"regexp"
	"strings"
)

var nonDigit = regexp.MustCompile(`\D`)
var leadingDigits = regexp.MustCompile(`^\d+`)
var yyyymmdd = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})`)
var mmddyyyy = regexp.MustCompile(`^(\d{1,2})/(\d{1,2})/(\d{4})`)

// ── Partial masking helpers ──────────────────────────────────────────────────

func partialEmail(v string) string {
	parts := strings.SplitN(v, "@", 2)
	if len(parts) != 2 {
		if len(v) >= 3 {
			return v[:3] + "***"
		}
		return v + "***"
	}
	local, domain := parts[0], parts[1]
	shown := local
	if len(local) >= 2 {
		shown = local[:2]
	}
	stars := strings.Repeat("*", max0(len(local)-2))
	return shown + stars + "@" + domain
}

func partialPhone(v string) string {
	digits := nonDigit.ReplaceAllString(v, "")
	if len(digits) >= 7 {
		return digits[:3] + "-***-" + digits[len(digits)-4:]
	}
	return v
}

func partialSSN(v string) string {
	digits := nonDigit.ReplaceAllString(v, "")
	if len(digits) >= 4 {
		return "***-**-" + digits[len(digits)-4:]
	}
	return v
}

func partialCard(v string) string {
	digits := nonDigit.ReplaceAllString(v, "")
	if len(digits) >= 8 {
		return "****-****-" + digits[len(digits)-8:len(digits)-4] + "-" + digits[len(digits)-4:]
	}
	if len(v) >= 4 {
		return "****-" + v[len(v)-4:]
	}
	return "****-" + v
}

func partialName(v string) string {
	parts := strings.Fields(v)
	if len(parts) >= 2 {
		last := parts[len(parts)-1]
		return parts[0] + " " + last[:1] + "***"
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return v
}

func partialGeneric(v string) string {
	if v == "" {
		return v
	}
	if len(v) > 4 {
		return v[:2] + "***" + v[len(v)-2:]
	}
	if len(v) > 1 {
		return v[:1] + "***"
	}
	return "***"
}

// ── Per-type masking functions ───────────────────────────────────────────────

func maskEmail(v string) string {
	parts := strings.SplitN(v, "@", 2)
	if len(parts) != 2 {
		return "********"
	}
	local, domain := parts[0], parts[1]
	if local == "" {
		return "***@" + domain
	}
	return local[:1] + "***@" + domain
}

func maskPhone(v string) string {
	digits := nonDigit.ReplaceAllString(v, "")
	if len(digits) >= 4 {
		last4 := digits[len(digits)-4:]
		prefix := "***-***-"
		if len(v) > 4 {
			prefix = replaceDigitsWithStar(v[:len(v)-4])
		}
		return prefix + last4
	}
	return "***-***-" + digits
}

func replaceDigitsWithStar(s string) string {
	re := regexp.MustCompile(`\d`)
	return re.ReplaceAllString(s, "*")
}

func maskSSN(v string) string {
	digits := nonDigit.ReplaceAllString(v, "")
	if len(digits) >= 4 {
		return "***-**-" + digits[len(digits)-4:]
	}
	return "***-**-" + digits
}

func maskCreditCard(v string) string {
	digits := nonDigit.ReplaceAllString(v, "")
	if len(digits) >= 4 {
		return "****-****-****-" + digits[len(digits)-4:]
	}
	return "****-****-****-" + digits
}

func maskName(v string) string {
	parts := strings.Fields(v)
	if len(parts) == 0 {
		return "********"
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p[:1]+"***")
		}
	}
	if len(out) == 0 {
		return "********"
	}
	return strings.Join(out, " ")
}

func maskAddress(v string) string {
	masked := leadingDigits.ReplaceAllString(v, "***")
	if idx := strings.LastIndex(masked, ","); idx != -1 {
		return masked[:idx] + ", ***"
	}
	return masked
}

func maskIPAddress(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) == 4 {
		return parts[0] + "." + parts[1] + ".*.*"
	}
	if len(v) > 1 {
		return v[:len(v)/2] + "***"
	}
	return v + "***"
}

func maskAmount(_ string) string { return "***.**" }

func maskAccount(v string) string {
	if len(v) >= 4 {
		return "***" + v[len(v)-4:]
	}
	return "***" + v
}

func maskGovtID(v string) string {
	digits := nonDigit.ReplaceAllString(v, "")
	if len(digits) >= 4 {
		return "***" + digits[len(digits)-4:]
	}
	if len(v) >= 4 {
		return "***" + v[len(v)-4:]
	}
	return "***" + v
}

func maskSecret(_ string) string    { return "********" }
func maskLocation(_ string) string  { return "****, ****" }
func maskSensitive(_ string) string { return "********" }
func maskGeneric(_ string) string   { return "********" }

func maskDOB(v string) string {
	if m := yyyymmdd.FindStringSubmatch(v); m != nil {
		return "****-" + m[2] + "-**"
	}
	if m := mmddyyyy.FindStringSubmatch(v); m != nil {
		return m[1] + "/**/****"
	}
	return "****/**, ****"
}

// ── Dispatch tables ───────────────────────────────────────────────────────────

var maskFn = map[string]func(string) string{
	"EMAIL":       maskEmail,
	"PHONE":       maskPhone,
	"SSN":         maskSSN,
	"CREDIT_CARD": maskCreditCard,
	"NAME":        maskName,
	"ADDRESS":     maskAddress,
	"IP_ADDRESS":  maskIPAddress,
	"AMOUNT":      maskAmount,
	"ACCOUNT":     maskAccount,
	"GOVT_ID":     maskGovtID,
	"TAX_ID":      maskAccount,
	"SECRET":      maskSecret,
	"DOB":         maskDOB,
	"LOCATION":    maskLocation,
	"SENSITIVE":   maskSensitive,
}

var partialMaskFn = map[string]func(string) string{
	"EMAIL":       partialEmail,
	"PHONE":       partialPhone,
	"SSN":         partialSSN,
	"CREDIT_CARD": partialCard,
	"NAME":        partialName,
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// MaskValue masks a single text value according to its PII type and level
// ("raw", "partial", or "full" — anything else behaves like "full").
func MaskValue(value string, piiType string, level string) string {
	if level == "raw" {
		return value
	}
	if value == "" {
		return value
	}
	piiUpper := strings.ToUpper(piiType)
	var fn func(string) string
	if level == "partial" {
		if f, ok := partialMaskFn[piiUpper]; ok {
			fn = f
		} else if f, ok := maskFn[piiUpper]; ok {
			fn = f
		} else {
			fn = partialGeneric
		}
	} else {
		if f, ok := maskFn[piiUpper]; ok {
			fn = f
		} else {
			fn = maskGeneric
		}
	}
	return fn(value)
}

// MaskRow applies masking to the already-text-encoded columns named in
// maskedColumns, using columnPiiMap to choose the per-column strategy.
// row is a map of column name -> encoded text value (nil entries, i.e. SQL
// NULL, pass through untouched).
func MaskRow(row map[string]*string, maskedColumns []string, columnPiiMap map[string]string, level string) {
	for _, col := range maskedColumns {
		v, ok := row[col]
		if !ok || v == nil {
			continue
		}
		masked := MaskValue(*v, columnPiiMap[col], level)
		row[col] = &masked
	}
}
