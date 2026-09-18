package masking

import "testing"

// Diff-checked against the live test run of enterprise/sdk/metasight_sdk/masking.py
// earlier this session (real data through /sdk/prepare + psycopg2): Ravi/Jagan ->
// "R***"/"J***", dob "1990-05-01" -> "****-05-**", email masked with "***" present.
func TestMaskValueMatchesPythonBehavior(t *testing.T) {
	cases := []struct {
		value, piiType, level, want string
	}{
		{"Ravi", "NAME", "full", "R***"},
		{"Jagan", "NAME", "full", "J***"},
		{"1990-05-01", "DOB", "full", "****-05-**"},
		{"shreyaraghu33@gmail.com", "EMAIL", "full", "s***@gmail.com"},
		{"", "NAME", "full", ""},
	}
	for _, c := range cases {
		got := MaskValue(c.value, c.piiType, c.level)
		if got != c.want {
			t.Errorf("MaskValue(%q, %q, %q) = %q, want %q", c.value, c.piiType, c.level, got, c.want)
		}
	}
}

func TestMaskValueRawPassesThrough(t *testing.T) {
	if got := MaskValue("Ravi", "NAME", "raw"); got != "Ravi" {
		t.Errorf("raw level should pass through unchanged, got %q", got)
	}
}

func TestMaskValueUnknownPiiTypeFallsBackToGeneric(t *testing.T) {
	if got := MaskValue("something", "UNKNOWN_TYPE", "full"); got != "********" {
		t.Errorf("unknown PII type should fall back to generic mask, got %q", got)
	}
}

func TestMaskRowSkipsNulls(t *testing.T) {
	row := map[string]*string{"name": nil}
	MaskRow(row, []string{"name"}, map[string]string{"name": "NAME"}, "full")
	if row["name"] != nil {
		t.Errorf("NULL value should remain nil after masking, got %v", *row["name"])
	}
}
