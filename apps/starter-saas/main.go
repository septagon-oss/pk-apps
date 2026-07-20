// Package main is pk-apps's thin wrapper around the importable starterapp
// package — the flagship "git clone and go run ." demo that composes all nine
// OSS PlatformKit modules (tenant, user, audit, health, auth, api_key, content,
// notification, admin) against a single SQLite database and serves them through
// one HTTP listener.
//
// All application logic — the module composition graph, the shared *sql.DB, the
// HTTP mux, the first-boot seed, and the serve loop — lives in
// github.com/septagon-oss/pk-apps/pkg/starterapp. This binary only loads the
// local config.yaml, installs the SQLite driver, and hands a signal context to
// starterapp.Run. The public front-door repo
// (github.com/septagon-oss/platformkit) is the same ~10-line wrapper over the
// same package, so there is one and only one source of truth for the app.
//
// ADR: ADR-0009 (ports-only module communication), ADR-0017 (composition
// through dependency injection), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package main

// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
import (
	"context"
	"log"
	"os/signal"
	"syscall"

	// Register the modernc.org/sqlite driver as "sqlite" so each module's
	// store can sql.Open against the same default driver.
	_ "modernc.org/sqlite"

	"github.com/septagon-oss/pk-apps/pkg/starterapp"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg, err := starterapp.LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("starter-saas: load config: %v", err)
	}

	if err := starterapp.Run(ctx, cfg); err != nil {
		log.Fatalf("starter-saas: %v", err)
	}
}
