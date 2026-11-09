//go:build js && wasm

package main

import (
	"strings"
	"syscall/js"
	"testing"
)

func TestJSTemplatePreviewUsesIndependentSelectors(t *testing.T) {
	result := jsTplPrev(js.Undefined(), []js.Value{
		js.ValueOf("{{len .Report.Updated}}|{{len .Entries}}|{{(index .Entries 0).Level}}"),
		js.ValueOf("u"),
		js.ValueOf("i"),
	})
	if got, ok := result.(string); !ok || got != "1|1|info" {
		t.Fatalf("preview result = %v, want 1|1|info", result)
	}
}

func TestJSTemplatePreviewArraySelectors(t *testing.T) {
	result := jsTplPrev(js.Undefined(), []js.Value{
		js.ValueOf("{{len .Report.Updated}}|{{len .Report.Skipped}}|{{len .Entries}}|{{(index .Entries 0).Level}}|{{(index .Entries 1).Level}}"),
		js.ValueOf([]any{"updated", "skipped"}),
		js.ValueOf([]any{"warning", "info"}),
	})
	if got, ok := result.(string); !ok || got != "1|1|2|warning|info" {
		t.Fatalf("array preview result = %v, want 1|1|2|warning|info", result)
	}
}

func TestJSTemplatePreviewMissingArguments(t *testing.T) {
	for _, args := range [][]js.Value{nil, {js.ValueOf("text")}, {js.ValueOf("text"), js.ValueOf("u")}} {
		if got := jsTplPrev(js.Undefined(), args); got != "Requires 3 arguments passed" {
			t.Errorf("%d arguments: result = %v", len(args), got)
		}
	}
}

func TestJSTemplatePreviewErrors(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{name: "parse", input: "{{", want: "Error: failed to parse"},
		{name: "execute", input: "partial{{.MissingField}}", want: "Error: failed to execute template"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := jsTplPrev(js.Undefined(), []js.Value{js.ValueOf(tc.input), js.ValueOf(""), js.ValueOf("")})
			if got, ok := result.(string); !ok || !strings.HasPrefix(got, tc.want) {
				t.Fatalf("preview error = %v, want prefix %q", result, tc.want)
			}
		})
	}
}

func TestJSTemplatePreviewEmptySelectors(t *testing.T) {
	result := jsTplPrev(js.Undefined(), []js.Value{js.ValueOf("{{len .Entries}}"), js.ValueOf(""), js.ValueOf("")})
	if got, ok := result.(string); !ok || got != "0" {
		t.Fatalf("empty selector result = %v, want 0", result)
	}
}
