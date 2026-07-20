package main

// Validates: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
// main_test.go validates the minimal OSS app composition example.
//
// ADR: ADR-0017 (composition through dependency injection), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).

import (
	"testing"

	"github.com/septagon-oss/pk-core/pkg/module"
	"github.com/septagon-oss/pk-modules/pkg/coremodules"
)

func TestMinimalAppComposes(t *testing.T) {
	t.Parallel()

	catalog := module.NewCatalog().Add(coremodules.Bundle()).MustBuild()
	plan, err := module.Compose(catalog)
	if err != nil {
		t.Fatalf("Compose() error = %v", err)
	}
	if len(plan.Modules) != 3 {
		t.Fatalf("len(plan.Modules) = %d, want 3", len(plan.Modules))
	}
}
