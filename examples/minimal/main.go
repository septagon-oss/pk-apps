package main

// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
// main.go demonstrates composing the minimal OSS PlatformKit module bundle.
//
// ADR: ADR-0017 (composition through dependency injection), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).

import (
	"fmt"
	"log"

	"github.com/septagon-oss/pk-core/pkg/module"
	"github.com/septagon-oss/pk-modules/pkg/coremodules"
)

func main() {
	catalog := module.NewCatalog().Add(coremodules.Bundle()).MustBuild()
	plan, err := module.Compose(catalog)
	if err != nil {
		log.Fatal(err)
	}

	for _, module := range plan.Modules {
		fmt.Println(module.Metadata().ID)
	}
}
