package meta

import (
	"fmt"
	"net/http"
	"testing"
)

func TestUserAgentUsesInitializedVersion(t *testing.T) {
	if Version == "" {
		t.Fatal("build version must not be empty")
	}
	want := fmt.Sprintf("Watchtower/%s", Version)
	if UserAgent != want {
		t.Fatalf("UserAgent = %q, want %q", UserAgent, want)
	}

	request, err := http.NewRequest(http.MethodGet, "https://example.invalid/", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	request.Header.Set("User-Agent", UserAgent)
	if got := request.UserAgent(); got != want {
		t.Fatalf("HTTP user agent = %q, want %q", got, want)
	}
}
