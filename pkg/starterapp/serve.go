// Package starterapp — serve.go owns the boot-and-serve loop shared by every
// runnable wrapper. Main wraps the binary differently (config path, signals),
// but the serving semantics — build the mux, print the operator banner, listen,
// and shut down cleanly on SIGINT/SIGTERM — are identical everywhere and live
// here so there is no duplication between pk-apps's own binary and the
// front-door repo's main().
//
// Run is the one call a ~10-line main() needs: give it a context and a Config
// and it builds the App, serves until the context is cancelled, and releases
// the shared *sql.DB on every exit path (including build/listen failure), so a
// wrapper never has to remember to defer App.Close itself.
//
// ADR: ADR-0017 (composition through dependency injection),
// ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package starterapp

// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// Run builds the App from cfg and serves it until ctx is cancelled (typically
// by a SIGINT/SIGTERM signal context the caller owns). It returns an error
// instead of calling log.Fatal so deferred cleanup — notably App.Close, which
// releases the shared *sql.DB — runs on every failure path, not just on clean
// shutdown. A nil return means a clean shutdown.
func Run(ctx context.Context, cfg *Config, opts ...Option) error {
	app, err := BuildApp(ctx, cfg, opts...)
	if err != nil {
		return fmt.Errorf("build app: %w", err)
	}
	defer app.Close()

	mux, err := app.Mux()
	if err != nil {
		return fmt.Errorf("build mux: %w", err)
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
			return fmt.Errorf("listen: %w", err)
		}
		return nil
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("starter-saas: graceful shutdown failed: %v", err)
	} else {
		log.Println("starter-saas: server stopped cleanly")
	}
	return nil
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
	ids := app.AllModuleIDs()
	fmt.Printf("  modules:      %d composed (%s)\n", len(ids), strings.Join(ids, ", "))
	fmt.Println(bar)
	printDevelopmentWarning(cfg)
}

// printDevelopmentWarning emits a loud, unmissable notice when the app runs in
// the development environment. Development mode seeds a well-known admin
// password and RE-ASSERTS it on every boot (seed.Params.RepairPassword) — the
// exact v0.1.0 behavior that is dangerous if exposed. Making it noisy removes
// the "silent" failure mode: an operator who deploys without declaring
// environment=production sees this on every start.
func printDevelopmentWarning(cfg *Config) {
	if cfg.Environment != "development" {
		return
	}
	fmt.Println()
	fmt.Println("  ⚠  DEVELOPMENT MODE — NOT SAFE TO EXPOSE")
	fmt.Println("     • the admin password is a built-in demo default and is")
	fmt.Println("       RE-ASSERTED on every boot (a changed password reverts).")
	fmt.Println("     • a demo tenant + admin user are auto-seeded.")
	fmt.Println("     For any real or network-exposed deployment set")
	fmt.Println("     environment=production and seed.admin_password in config.yaml.")
	fmt.Println()
}
