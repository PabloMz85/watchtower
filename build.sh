#!/bin/bash

BINFILE=watchtower
if [ -n "$MSYSTEM" ]; then
    BINFILE=watchtower.exe
fi
VERSION=$(git describe --tags)
echo "Building $VERSION..."
go build -o $BINFILE -ldflags "-X github.com/PabloMz85/watchtower/internal/meta.Version=$VERSION"
