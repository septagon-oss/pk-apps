// Package main wires the runnable starter-saas monolith — the flagship "git
// clone and go run ." demo that composes all nine OSS PlatformKit modules
// (tenant, user, audit, health, auth, api_key, content, notification, admin)
// against a single SQLite database and serves them through one HTTP listener.
//
// main.go owns the boot sequence: parse config, open SQLite, build the admin
// shell, construct every module with WithSQLiteDSN + WithAdminRegistrar, seed
// the first tenant + admin user on first boot, compose them through the
// module catalog, mount HTTP routes, and serve until SIGINT/SIGTERM.
//
// ADR: ADR-0009 (ports-only module communication), ADR-0017 (composition
// through dependency injection), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"strings"
	"syscall"

	// Register the modernc.org/sqlite driver as "sqlite" so each module's
	// WithSQLiteDSN call can sql.Open against the same default driver.
	_ "modernc.org/sqlite"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("starter-saas: load config: %v", err)
	}

	app, err := buildApp(ctx, cfg)
	if err != nil {
		log.Fatalf("starter-saas: build app: %v", err)
	}
	defer app.Close()

	mux, err := app.mux()
	if err != nil {
		log.Fatalf("starter-saas: build mux: %v", err)
	}

	printBanner(cfg, app)

	server := &http.Server{
		Addr:         cfg.HTTP.Addr,
		Handler:      mux,
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
	}

	serverErr := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	select {
	case <-ctx.Done():
		log.Println("starter-saas: shutdown signal received")
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("starter-saas: listen: %v", err)
		}
		return
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("starter-saas: graceful shutdown failed: %v", err)
	} else {
		log.Println("starter-saas: server stopped cleanly")
	}
}

// printBanner writes the operator-facing startup banner that tells humans
// exactly how to reach the admin UI and what credentials to type.
func printBanner(cfg *Config, app *App) {
	bar := "============================================================"
	fmt.Println(bar)
	fmt.Println(" starter-saas — PlatformKit OSS monolith")
	fmt.Printf("  listening:    http://localhost%s\n", cfg.HTTP.Addr)
	fmt.Printf("  admin UI:     http://localhost%s%s\n", cfg.HTTP.Addr, app.adminBasePath)
	fmt.Printf("  health:       http://localhost%s/healthz\n", cfg.HTTP.Addr)
	fmt.Printf("  metrics:      http://localhost%s/metrics\n", cfg.HTTP.Addr)
	fmt.Printf("  default login: %s / %s\n", app.seedEmail, app.seedPassword)
	fmt.Printf("  modules:      %d composed (%s)\n", len(app.modules), strings.Join(app.modules, ", "))
	fmt.Println(bar)
}
