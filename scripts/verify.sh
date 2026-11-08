#!/usr/bin/env bash
set -euo pipefail

# Run from the repository root. Integration uses disposable scoped resources.
unformatted=$(gofmt -l cmd internal pkg integration)
if [ -n "$unformatted" ]; then
    printf 'FAIL: unformatted Go files\n%s\n' "$unformatted" >&2
    exit 1
fi

go mod verify
WATCHTOWER_INTEGRATION=0 go test -race ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
go build ./...

if [ "${WATCHTOWER_INTEGRATION:-0}" = "1" ]; then
    go test ./integration -v -count=1
    printf 'PASS: real Docker update and configuration preservation\n'
fi
printf 'PASS: unit tests, race detector, vet, staticcheck, vulnerability audit, and build\n'
