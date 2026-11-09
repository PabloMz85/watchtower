package templates_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"text/template"

	"github.com/PabloMz85/watchtower/pkg/notifications/templates"
)

func executeHelper(t *testing.T, input string, value any) (string, error) {
	t.Helper()
	tpl, err := template.New("helpers").Funcs(templates.Funcs).Parse(input)
	if err != nil {
		t.Fatalf("parse helper template: %v", err)
	}
	var out strings.Builder
	err = tpl.Execute(&out, value)
	return out.String(), err
}

func TestStringHelpersThroughFuncMap(t *testing.T) {
	for _, tt := range []struct {
		name, input, value, want string
	}{
		{"upper", `{{ToUpper .}}`, "café mixed", "CAFÉ MIXED"},
		{"lower", `{{ToLower .}}`, "CAFÉ MIXED", "café mixed"},
		{"title", `{{Title .}}`, "hello world", "Hello World"},
		{"pipeline", `{{. | ToLower | Title | ToUpper}}`, "hELLO wORLD", "HELLO WORLD"},
		{"empty", `{{ToUpper .}}{{ToLower .}}{{Title .}}`, "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := executeHelper(t, tt.input, tt.value)
			if err != nil || got != tt.want {
				t.Fatalf("helper output = (%q, %v), want (%q, nil)", got, err, tt.want)
			}
		})
	}
	for _, name := range []string{"ToUpper", "ToLower", "Title"} {
		t.Run(name+" rejects non-string", func(t *testing.T) {
			if _, err := executeHelper(t, "{{"+name+" .}}", 12); err == nil {
				t.Fatal("string helper accepted an integer argument")
			}
		})
	}
}

func TestJSONHelperCompactScalarsAndPrettyObjects(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value any
		want  string
	}{
		{"null", nil, "null"},
		{"boolean", true, "true"},
		{"number", 42, "42"},
		{"string", "hello", `"hello"`},
		{"empty array", []string{}, "[]"},
		{"empty object", map[string]any{}, "{}"},
		{"object", map[string]any{"b": []int{2, 3}, "a": true}, "{\n  \"a\": true,\n  \"b\": [\n    2,\n    3\n  ]\n}"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := executeHelper(t, `{{. | ToJSON}}`, tt.value)
			if err != nil || got != tt.want {
				t.Fatalf("ToJSON = (%q, %v), want (%q, nil)", got, err, tt.want)
			}
			var compact bytes.Buffer
			if err := json.Compact(&compact, []byte(got)); err != nil {
				t.Fatalf("ToJSON produced invalid JSON: %v", err)
			}
			wantCompact, err := json.Marshal(tt.value)
			if err != nil || compact.String() != string(wantCompact) {
				t.Errorf("compacted output = %q, want %q (marshal error: %v)", compact.String(), wantCompact, err)
			}
		})
	}
}

func TestJSONHelperEscapesAndRoundTripsStringData(t *testing.T) {
	value := "<>&\n\"\\\u2028\u2029"
	got, err := executeHelper(t, `{{ToJSON .}}`, value)
	if err != nil {
		t.Fatal(err)
	}
	// These are JSON encoder escapes, not a claim about HTML template safety.
	for _, escape := range []string{`\u003c`, `\u003e`, `\u0026`, `\n`, `\"`, `\\`, `\u2028`, `\u2029`} {
		if !strings.Contains(got, escape) {
			t.Errorf("JSON %q missing escape %q", got, escape)
		}
	}
	var decoded string
	if err := json.Unmarshal([]byte(got), &decoded); err != nil || decoded != value {
		t.Fatalf("JSON round trip = (%q, %v), want %q", decoded, err, value)
	}
}

type failingMarshaler struct{}

func (failingMarshaler) MarshalJSON() ([]byte, error) {
	return nil, errors.New("deliberate marshal failure")
}

type invalidMarshaler struct{}

func (invalidMarshaler) MarshalJSON() ([]byte, error) {
	return []byte("not JSON"), nil
}

func TestJSONHelperReturnsDiagnosticsForUnmarshalableValues(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	for _, tt := range []struct {
		name    string
		value   any
		message string
	}{
		{"channel", make(chan int), "unsupported type"},
		{"function", func() {}, "unsupported type"},
		{"nonfinite number", math.NaN(), "unsupported value"},
		{"cycle", cycle, "cycle"},
		{"marshaler failure", failingMarshaler{}, "deliberate marshal failure"},
		{"invalid custom JSON", invalidMarshaler{}, "invalid character"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := executeHelper(t, `{{ToJSON .}}`, tt.value)
			if err != nil {
				t.Fatalf("marshal failure unexpectedly failed template execution: %v", err)
			}
			if !strings.HasPrefix(got, "failed to marshal JSON in notification template: ") || !strings.Contains(got, tt.message) {
				t.Fatalf("ToJSON diagnostic = %q, want marshal context and %q", got, tt.message)
			}
		})
	}
}
