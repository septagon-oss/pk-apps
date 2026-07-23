SHELL := /bin/bash
.SHELLFLAGS := -ec
GOWORK_FILE := $(firstword $(wildcard ../go.work))
ifeq ($(GOWORK_FILE),)
GO_WORK := GOWORK=off
else
GO_WORK := GOWORK=$(abspath $(GOWORK_FILE))
endif
GO_ENV ?= $(GO_WORK) GOTMPDIR=$(CURDIR)/.tmp-go-tmp TMPDIR=$(CURDIR)/.tmp-go-tmp
STATICCHECK_VERSION ?= v0.7.0
STATICCHECK_BIN := $(CURDIR)/.tmp-tools/staticcheck
TMPDIRS := .tmp-go-tmp .tmp-tools

.PHONY: test vet staticcheck race verify

$(TMPDIRS):
	@mkdir -p $@

$(STATICCHECK_BIN): | $(TMPDIRS)
	$(GO_ENV) GOBIN=$(CURDIR)/.tmp-tools go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)

test: | $(TMPDIRS)
	$(GO_ENV) go test ./...

vet: | $(TMPDIRS)
	$(GO_ENV) go vet ./...

staticcheck: $(STATICCHECK_BIN) | $(TMPDIRS)
	$(GO_ENV) GOFLAGS=-buildvcs=false $(STATICCHECK_BIN) ./...

race: | $(TMPDIRS)
	$(GO_ENV) go test -race -count=1 ./...

verify: test vet staticcheck race
