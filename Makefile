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
STATICCHECK_BIN := $(CURDIR)/.tmp-tools/staticcheck-$(STATICCHECK_VERSION)
STATICCHECK ?= $(STATICCHECK_BIN)
TMPDIRS := .tmp-go-tmp .tmp-tools

ifeq ($(origin STATICCHECK),file)
STATICCHECK_PREREQ := $(STATICCHECK_BIN)
endif

.PHONY: test vet staticcheck race verify

$(TMPDIRS):
	@mkdir -p $@

$(STATICCHECK_BIN): | $(TMPDIRS)
	$(GO_ENV) GOBIN="$(CURDIR)/.tmp-tools" go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	mv "$(CURDIR)/.tmp-tools/staticcheck" "$@"

test: | $(TMPDIRS)
	$(GO_ENV) go test ./...

vet: | $(TMPDIRS)
	$(GO_ENV) go vet ./...

staticcheck: $(STATICCHECK_PREREQ) | $(TMPDIRS)
	@packages="$$( $(GO_ENV) GOFLAGS=-buildvcs=false go list ./... )"; \
	if [[ -z "$$packages" ]]; then \
		echo "staticcheck: go list returned no packages"; \
		exit 1; \
	fi; \
	if output="$$( $(GO_ENV) GOFLAGS=-buildvcs=false $(STATICCHECK) ./... 2>&1 )"; then \
		status=0; \
	else \
		status=$$?; \
	fi; \
	if [[ -n "$$output" ]]; then printf '%s\n' "$$output"; fi; \
	if [[ $$status -ne 0 ]]; then exit $$status; fi; \
	if [[ "$$output" == *"matched no packages"* ]]; then \
		echo "staticcheck: analyzer matched no packages"; \
		exit 1; \
	fi

race: | $(TMPDIRS)
	$(GO_ENV) go test -race -count=1 ./...

verify: test vet staticcheck race
