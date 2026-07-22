// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

// main.go is the canonical example of extending the batteries-included starter
// with your OWN module. It boots the full nine-module app via starterapp.Run
// and contributes one custom, tenant-scoped "widgets" module through
// starterapp.WithModules. The custom routes are mounted on the same mux as the
// built-ins, so they inherit the identity middleware, the anonymous-mutation
// gate, and the request-body cap for free — a body-supplied tenant is ignored;
// attribution comes from the authenticated principal via portslib.RequestActor.
//
// Run it, then:
//
//	SID=$(curl -s -X POST localhost:8080/api/v1/auth/sessions \
//	  -d '{"tenant_id":"tenant_acme","email":"admin@local.test","password":"changeme"}' | jq -r .id)
//	curl -s -X POST localhost:8080/api/v1/widgets -H "Authorization: Bearer $SID" -d '{"name":"gadget"}'
//	curl -s        localhost:8080/api/v1/widgets -H "Authorization: Bearer $SID"
//
// ADR: ADR-0017 (composition through dependency injection), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/septagon-oss/pk-apps/pkg/starterapp"
	"github.com/septagon-oss/pk-modules/pkg/portslib"

	_ "modernc.org/sqlite"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	cfg := starterapp.DefaultConfig()
	if err := starterapp.Run(ctx, cfg, starterapp.WithModules(widgetModule)); err != nil {
		log.Fatal(err)
	}
}

// widgetModule is an ExtraModule: it builds its store on the starter's shared
// *sql.DB and returns a plugin that mounts the widget routes. It supplies no
// Compose (this module has no cross-module dependencies to validate), so it is
// a routes-only contribution.
func widgetModule(env starterapp.ModuleEnv) (starterapp.ModulePlugin, error) {
	store, err := newWidgetStore(env.DB)
	if err != nil {
		return starterapp.ModulePlugin{}, err
	}
	return starterapp.ModulePlugin{
		ID:             "widget",
		RegisterRoutes: (&widgetHandler{store: store}).RegisterRoutes,
	}, nil
}

// --- a tiny tenant-scoped store on the shared DB ---

type widget struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	OwnerID  string `json:"owner_id"`
	Name     string `json:"name"`
}

type widgetStore struct{ db *sql.DB }

func newWidgetStore(db *sql.DB) (*widgetStore, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS widgets (
		id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, owner_id TEXT NOT NULL, name TEXT NOT NULL)`)
	if err != nil {
		return nil, fmt.Errorf("widget schema: %w", err)
	}
	return &widgetStore{db: db}, nil
}

var errNotFound = errors.New("widget: not found")

func (s *widgetStore) create(w *widget) error {
	_, err := s.db.Exec(`INSERT INTO widgets (id, tenant_id, owner_id, name) VALUES (?, ?, ?, ?)`,
		w.ID, w.TenantID, w.OwnerID, w.Name)
	return err
}

func (s *widgetStore) list(tenantID string) ([]*widget, error) {
	rows, err := s.db.Query(`SELECT id, tenant_id, owner_id, name FROM widgets WHERE tenant_id = ? ORDER BY id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*widget{}
	for rows.Next() {
		wg := &widget{}
		if err := rows.Scan(&wg.ID, &wg.TenantID, &wg.OwnerID, &wg.Name); err != nil {
			return nil, err
		}
		out = append(out, wg)
	}
	return out, rows.Err()
}

func (s *widgetStore) get(tenantID, id string) (*widget, error) {
	wg := &widget{}
	err := s.db.QueryRow(`SELECT id, tenant_id, owner_id, name FROM widgets WHERE id = ? AND tenant_id = ?`, id, tenantID).
		Scan(&wg.ID, &wg.TenantID, &wg.OwnerID, &wg.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return wg, err
}

// --- the HTTP surface: RequestActor binds tenant + owner from the principal ---

type widgetHandler struct{ store *widgetStore }

func (h *widgetHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/api/v1/widgets", h)
	mux.Handle("/api/v1/widgets/", h)
}

func (h *widgetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tenant, owner, ok := portslib.RequestActor(w, r)
	if !ok {
		return // 401 written by RequestActor
	}
	id := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/api/v1/widgets"), "/")
	switch {
	case id == "" && r.Method == http.MethodGet:
		items, err := h.store.list(tenant)
		writeJSON(w, http.StatusOK, items, err)
	case id == "" && r.Method == http.MethodPost:
		var wg widget
		if json.NewDecoder(r.Body).Decode(&wg) != nil || strings.TrimSpace(wg.Name) == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		wg.TenantID, wg.OwnerID = tenant, owner // server owns identity
		wg.ID = strconv.FormatInt(time.Now().UnixNano(), 36)
		writeJSON(w, http.StatusCreated, &wg, h.store.create(&wg))
	case id != "" && r.Method == http.MethodGet:
		wg, err := h.store.get(tenant, id)
		writeJSON(w, http.StatusOK, wg, err)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any, err error) {
	if errors.Is(err, errNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
