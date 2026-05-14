SHELL := /bin/bash
.SHELLFLAGS := -ec

.PHONY: test example

test:
	GOWORK=off GOCACHE=$(CURDIR)/.tmp-go-cache go test ./...

example:
	GOWORK=off GOCACHE=$(CURDIR)/.tmp-go-cache go run ./examples/minimal
