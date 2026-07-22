package main

// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
// main.go demonstrates wiring the low-level pk-runtime host around the
// coremodules TEACHING bundle (three stub modules, NOT the product). For a
// real, runnable app use starterapp.Run; to add your own module to it, see
// examples/custommodule.
//
// ADR: ADR-0017 (composition through dependency injection), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/septagon-oss/pk-core/pkg/module"
	"github.com/septagon-oss/pk-modules/pkg/coremodules"
	"github.com/septagon-oss/pk-runtime/pkg/host"
	"github.com/septagon-oss/pk-runtime/pkg/httpx"
)

func main() {
	runtimeHost, err := newHost(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	for _, metadata := range runtimeHost.ModuleMetadata() {
		fmt.Println(metadata.ID)
	}
}

func newHost(ctx context.Context) (*host.Host, error) {
	catalog := module.NewCatalog().Add(coremodules.Bundle()).MustBuild()
	return host.New(ctx, host.Input{
		Config:  host.Config{Name: "platformkit-oss-example", Version: "0.1.0"},
		Catalog: catalog,
		Routes: []httpx.Route{{
			ID:       "content.list",
			ModuleID: "content",
			Method:   http.MethodGet,
			Pattern:  "/content",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}),
		}},
	})
}
