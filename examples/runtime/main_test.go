package main

// Validates: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
// main_test.go validates the runtime example through API flow definitions.
//
// ADR: ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).

import (
	"context"
	"testing"

	"github.com/septagon-oss/pk-shared/pkg/flowdef"
	"github.com/septagon-oss/pk-testkit/pkg/apitest"
	"github.com/septagon-oss/pk-testkit/pkg/flowtest"
)

func TestRuntimeExampleReadyFlow(t *testing.T) {
	t.Parallel()

	runtimeHost, err := newHost(context.Background())
	if err != nil {
		t.Fatalf("newHost() error = %v", err)
	}

	readyFlow := flowdef.Definition{
		ID:       "runtime.ready",
		Name:     "Runtime readiness",
		Module:   "runtime",
		Fulfills: []string{"REQ-RUNTIME-READY"},
		Channels: flowdef.Channels{API: &flowdef.APIChannel{Steps: []flowdef.APIStep{{
			OperationID:     "ready",
			Method:          "GET",
			Path:            "/ready",
			SuccessStatuses: []int{200},
		}}}},
	}

	coverage := flowtest.ValidateCoverage(
		[]flowtest.Requirement{{ID: "REQ-RUNTIME-READY", Critical: true}},
		[]flowdef.Definition{readyFlow},
	)
	if !coverage.OK() {
		t.Fatalf("coverage failed: %#v", coverage)
	}

	runner, err := apitest.NewRunner(runtimeHost)
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	result := runner.Run(context.Background(), readyFlow)
	if !result.Passed {
		t.Fatalf("ready flow failed: %#v", result)
	}
}
