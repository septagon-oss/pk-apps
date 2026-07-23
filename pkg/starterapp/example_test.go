// Package starterapp_test — example_test.go carries the pkg.go.dev examples
// for the two entry points a host touches first: Run (boot the composed
// nine-module app) and LoadConfig (fail-closed configuration loading).
//
// Validates: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
package starterapp_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/septagon-oss/pk-apps/pkg/starterapp"

	_ "modernc.org/sqlite"
)

// Example boots the full starter: SQLite store, nine modules, local bootstrap,
// and HTTP on :8080. This is the entire main function of the platformkit
// front door. (Compile-only: Run serves until the context is canceled.)
func Example() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	cfg := starterapp.DefaultConfig() // development mode: local bootstrap
	if err := starterapp.Run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}

// ExampleLoadConfig shows the fail-closed contract: asking to load a config
// file is a deployment signal, so a missing file resolves to the production
// environment (which refuses to boot without an explicit admin password)
// rather than silently falling back to the development bootstrap.
func ExampleLoadConfig() {
	dir, err := os.MkdirTemp("", "pk-example")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer os.RemoveAll(dir)

	cfg, err := starterapp.LoadConfig(filepath.Join(dir, "missing-config.yaml"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(cfg.Environment)
	// Output: production
}
