package auth

import (
	"reflect"
	"strings"
	"testing"
)

func TestCoverageHTTPParseChallengeValues(t *testing.T) {
	for _, test := range []struct {
		name, challenge string
		want            map[string]string
	}{
		{"escaped_opaque_values", `bEaReR ReAlM="https://example.test/Case",SeRvIcE="Mixed\"Case\\Value,Keep"`, map[string]string{"realm": "https://example.test/Case", "service": "Mixed\"Case\\Value,Keep"}},
		{"unquoted_values", `Bearer realm= https://example.test/Case , service= MixedCase `, map[string]string{"realm": "https://example.test/Case", "service": "MixedCase"}},
		{"legacy_extensions", `Bearer legacy,realm="https://example.test/Case",middle,service="Registry",trailing`, map[string]string{"realm": "https://example.test/Case", "service": "Registry"}},
		{"trailing_separators", `Bearer realm="https://example.test/Case", , `, map[string]string{"realm": "https://example.test/Case"}},
		{"empty_quoted_extension", `Bearer extension=""`, map[string]string{"extension": ""}},
		{"size_boundary", "Bearer extension=" + strings.Repeat("X", 16384-len("Bearer extension=")), map[string]string{"extension": strings.Repeat("X", 16384-len("Bearer extension="))}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseChallenge(test.challenge)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("parsed values = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestCoverageHTTPParseChallengeRejectsMalformed(t *testing.T) {
	for _, test := range []struct{ name, challenge, want string }{
		{"oversize", "Bearer extension=" + strings.Repeat("x", 16385-len("Bearer extension=")), "invalid registry challenge"},
		{"carriage_return", "Bearer service=private\rvalue", "invalid registry challenge"},
		{"newline", "Bearer service=private\nvalue", "invalid registry challenge"},
		{"nul", "Bearer service=private\x00value", "invalid registry challenge"},
		{"unsupported_scheme", `Basic realm="private"`, "unsupported registry challenge"},
		{"missing_parameters", "Bearer", "unsupported registry challenge"},
		{"unterminated_quote", `Bearer service="private`, "unterminated registry challenge value"},
		{"dangling_escape", `Bearer service="private\`, "unterminated registry challenge value"},
		{"missing_separator", `Bearer service="private" realm="https://example.test"`, "invalid registry challenge separator"},
		{"duplicate_case_insensitive", `Bearer service="first",SeRvIcE="private"`, "duplicate registry challenge parameter"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseChallenge(test.challenge)
			if err == nil || err.Error() != test.want || got != nil {
				t.Fatalf("parseChallenge returned %#v, %v; want nil, %q", got, err, test.want)
			}
		})
	}
}

func TestCoverageHTTPSecureURLPortAndQuery(t *testing.T) {
	for _, raw := range []string{
		"https://example.test:1/Case?Audience=AbC",
		"https://example.test:65535/Case?Audience=AbC",
		"https://[::1]:443/Case?Audience=AbC",
	} {
		t.Run(raw, func(t *testing.T) {
			got, err := secureURL(raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != raw || got.Query().Get("Audience") != "AbC" {
				t.Fatalf("endpoint changed: %v", got)
			}
		})
	}
	for _, test := range []struct{ name, raw, want string }{
		{"zero_port", "https://example.test:0/token", "invalid registry endpoint port"},
		{"port_overflow", "https://example.test:65536/token", "invalid registry endpoint port"},
		{"integer_overflow", "https://example.test:999999999999999999999999999/token", "invalid registry endpoint port"},
		{"bad_query_escape", "https://example.test/token?secret=%zz", "invalid registry endpoint query"},
		{"query_semicolon", "https://example.test/token?secret=one;two", "invalid registry endpoint query"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := secureURL(test.raw)
			if err == nil || err.Error() != test.want || got != nil {
				t.Fatalf("secureURL returned %v, %v; want nil, %q", got, err, test.want)
			}
		})
	}
}
