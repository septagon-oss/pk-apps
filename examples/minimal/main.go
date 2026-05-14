package main

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
