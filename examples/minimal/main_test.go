package main

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
