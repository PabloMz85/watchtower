package preview_test

import (
	"strings"
	"testing"

	"github.com/PabloMz85/watchtower/pkg/notifications/preview"
	"github.com/PabloMz85/watchtower/pkg/notifications/preview/data"
)

func TestRenderEmptyAndStaticTemplates(t *testing.T) {
	for _, tt := range []struct {
		name, input, want string
	}{
		{"empty", "", ""},
		{"literal", "notification preview\n", "notification preview\n"},
		{"static data", "{{.StaticData.Title}}@{{.StaticData.Host}}", "Title@Host"},
		{"empty entries", "{{len .Entries}}:{{range .Entries}}{{.Level}}{{else}}no logs{{end}}", "0:no logs"},
		{"string helpers", `{{ToUpper .StaticData.Title}}|{{ToLower .StaticData.Host}}|{{Title "hello world"}}`, "TITLE|host|Hello World"},
		{"JSON helper", `{{ToJSON .StaticData}}`, "{\n  \"Title\": \"Title\",\n  \"Host\": \"Host\"\n}"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := preview.Render(tt.input, nil, nil)
			if err != nil || got != tt.want {
				t.Fatalf("Render() = (%q, %v), want (%q, nil)", got, err, tt.want)
			}
		})
	}
}

func TestRenderReportCountsAndStates(t *testing.T) {
	states := data.StatesFromString("cuuektf")
	input := `{{with .Report}}{{len .Scanned}}/{{len .Updated}}/{{len .Failed}}/{{len .Skipped}}/{{len .Stale}}/{{len .Fresh}}/{{len .All}};{{range .Scanned}}{{.State}} {{end}}{{range .Updated}}{{.State}} {{end}}{{range .Failed}}{{.State}} {{end}}{{range .Skipped}}{{.State}} {{end}}{{range .Stale}}{{.State}} {{end}}{{range .Fresh}}{{.State}} {{end}}{{end}}`
	want := "1/2/1/1/1/1/7;scanned updated updated failed skipped stale fresh "
	got, err := preview.Render(input, states, nil)
	if err != nil || got != want {
		t.Fatalf("Render() = (%q, %v), want (%q, nil)", got, err, want)
	}
}

func TestRenderLogLevelsPreserveOrderAndDuplicates(t *testing.T) {
	levels := data.LevelsFromString("tdivwefpd")
	got, err := preview.Render(`{{len .Entries}};{{range .Entries}}{{.Level.String}}:{{if .Message}}message{{end}};{{end}}`, nil, levels)
	want := "8;trace:message;debug:message;info:message;warning:message;error:message;fatal:message;panic:message;debug:message;"
	if err != nil || got != want {
		t.Fatalf("Render() = (%q, %v), want (%q, nil)", got, err, want)
	}
}

func TestRenderFailuresReturnNoPartialOutput(t *testing.T) {
	for _, tt := range []struct {
		name, input, stage string
	}{
		{"unclosed action", "prefix{{", "failed to parse"},
		{"unknown helper", "prefix{{MissingHelper .}}", "failed to parse"},
		{"missing field", "prefix{{.MissingField}}suffix", "failed to execute template"},
		{"invalid helper argument", "prefix{{ToUpper 12}}suffix", "failed to execute template"},
		{"invalid entry index", "prefix{{index .Entries 0}}suffix", "failed to execute template"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := preview.Render(tt.input, nil, nil)
			if err == nil || !strings.Contains(err.Error(), tt.stage) {
				t.Fatalf("Render() error = %v, want %q", err, tt.stage)
			}
			if got != "" {
				t.Fatalf("Render() leaked partial output %q after failure", got)
			}
		})
	}
}
