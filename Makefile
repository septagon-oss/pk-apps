SHELL := /bin/bash
.SHELLFLAGS := -ec
GO_ENV ?= GOWORK=off GOCACHE=$(CURDIR)/.tmp-go-cache GOTMPDIR=$(CURDIR)/.tmp-go-tmp
STATICCHECK ?= go run honnef.co/go/tools/cmd/staticcheck@latest
STATICCHECK_CACHE ?= $(CURDIR)/.tmp-staticcheck-cache
TMPDIRS := .tmp-go-cache .tmp-go-tmp .tmp-staticcheck-cache

.PHONY: test vet staticcheck race verify

$(TMPDIRS):
	@mkdir -p $@

test: | $(TMPDIRS)
	$(GO_ENV) go test ./...

vet: | $(TMPDIRS)
	$(GO_ENV) go vet ./...

staticcheck: | $(TMPDIRS)
	XDG_CACHE_HOME=$(STATICCHECK_CACHE) $(GO_ENV) GOFLAGS=-buildvcs=false $(STATICCHECK) ./...

race: | $(TMPDIRS)
	$(GO_ENV) go test -race -count=1 ./...

verify: test vet staticcheck race
