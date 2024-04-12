#!/bin/sh

# force go modules
export GOPATH=""

# disable cgo
export CGO_ENABLED=0

set -e
set -x

# linux
GOOS=linux GOARCH=amd64 go build -o release/linux/amd64/drone-aws-oidc
GOOS=linux GOARCH=arm64 go build -o release/linux/arm64/drone-aws-oidc

# windows
GOOS=windows go build -o release/windows/amd64/drone-aws-oidc.exe