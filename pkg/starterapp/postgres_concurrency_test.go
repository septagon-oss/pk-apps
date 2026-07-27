// Validates: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package starterapp

// postgres_concurrency_test.go pins the multi-replica boot, which is how the
// production profile is actually deployed: a rollout starts several pods at
// once, and on a new database they all reach schema creation simultaneously.
//
// This test failed 5 of 6 replicas before the schema lock existed. CREATE TABLE
// IF NOT EXISTS reads as idempotent but is not concurrency-safe on Postgres —
// competing backends collide inside the system catalog and lose with
// "duplicate key value violates unique constraint pg_type_typname_nsp_index".
// Without the lock, a first deploy crash-loops until one replica happens to win.

import (
	"context"
	"strings"
	"sync"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresConcurrentReplicaBoot(t *testing.T) {
	dsn := postgresDSN(t)
	resetPostgres(t, dsn)

	const replicas = 6
	var wg sync.WaitGroup
	errs := make([]error, replicas)

	for i := range replicas {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			cfg := DefaultConfig()
			cfg.Database.Driver = "postgres"
			cfg.Database.DSN = dsn
			app, err := BuildApp(context.Background(), cfg)
			if err != nil {
				errs[n] = err
				return
			}
			_ = app.Close()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("replica %d failed to boot concurrently: %v", i, err)
			if strings.Contains(err.Error(), "pg_type_typname_nsp_index") {
				t.Errorf("  ^ this is the unserialized CREATE TABLE race the schema lock exists to prevent")
			}
		}
	}
}

// TestPostgresConcurrentBootOnPopulatedDatabase covers the ordinary rollout:
// replicas restarting against a database whose schema already exists. Every
// replica must still boot, and the seeded identity must not be duplicated.
func TestPostgresConcurrentBootOnPopulatedDatabase(t *testing.T) {
	dsn := postgresDSN(t)
	resetPostgres(t, dsn)

	cfg := DefaultConfig()
	cfg.Database.Driver = "postgres"
	cfg.Database.DSN = dsn
	first, err := BuildApp(context.Background(), cfg)
	if err != nil {
		t.Fatalf("initial boot: %v", err)
	}
	_ = first.Close()

	const replicas = 6
	var wg sync.WaitGroup
	errs := make([]error, replicas)
	for i := range replicas {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			c := DefaultConfig()
			c.Database.Driver = "postgres"
			c.Database.DSN = dsn
			app, err := BuildApp(context.Background(), c)
			if err != nil {
				errs[n] = err
				return
			}
			_ = app.Close()
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("replica %d failed to restart: %v", i, err)
		}
	}
}
