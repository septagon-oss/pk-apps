// Package starterapp — serve.go owns the boot-and-serve loop shared by every
// runnable wrapper. Main wraps the binary differently (config path, signals),
// but the serving semantics — build the mux, print the operator banner, listen,
// and shut down cleanly on SIGINT/SIGTERM — are identical everywhere and live
// here so downstream wrappers do not duplicate lifecycle behavior.
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
	"net"
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
		log.Println("platformkit: shutdown signal received")
	case err := <-serverErr:
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
		return nil
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("platformkit: graceful shutdown failed: %v", err)
	} else {
		log.Println("platformkit: server stopped cleanly")
	}
	return nil
}

// printBanner writes the operator-facing startup banner that tells humans
// exactly how to reach the admin UI and what credentials to type.
func printBanner(cfg *Config, app *App) {
	bar := "============================================================"
	baseURL := displayURL(cfg.HTTP.Addr)
	fmt.Println(bar)
	fmt.Println(" PlatformKit OSS")
	fmt.Printf("  listening:    %s\n", baseURL)
	fmt.Printf("  admin UI:     %s%s\n", baseURL, app.adminBasePath)
	fmt.Printf("  health:       %s/healthz\n", baseURL)
	fmt.Printf("  OpenAPI:      %s/openapi/extensions.json\n", baseURL)
	if cfg.Environment == "development" {
		fmt.Printf("  local tenant: %s\n", app.seedTenantID)
		fmt.Printf("  local login:  %s / %s\n", app.seedEmail, app.seedPassword)
	} else {
		fmt.Println("  admin login:  configured seed account (password is never printed)")
	}
	ids := app.AllModuleIDs()
	fmt.Printf("  modules:      %d composed (%s)\n", len(ids), strings.Join(ids, ", "))
	fmt.Println(bar)
	printDevelopmentWarning(cfg)
}

// displayURL turns a listen address into a browser-friendly local URL. Wildcard
// bind addresses are represented as loopback because 0.0.0.0 and :: are listen
// targets, not useful navigation hosts.
func displayURL(addr string) string {
	addr = strings.TrimSpace(addr)
	if strings.HasPrefix(addr, ":") {
		return "http://127.0.0.1" + addr
	}
	hostName, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	switch hostName {
	case "", "0.0.0.0", "::":
		hostName = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(hostName, port)
}

// printDevelopmentWarning emits a loud, unmissable notice when the app runs in
// the development environment. Development mode seeds a well-known local
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
	fmt.Println("     • the local administrator password is built in and is")
	fmt.Println("       RE-ASSERTED on every boot (a changed password reverts).")
	fmt.Println("     • a local tenant + administrator are auto-seeded.")
	fmt.Println("     For any real or network-exposed deployment set")
	fmt.Println("     environment=production and seed.admin_password in config.yaml.")
	fmt.Println()
}
