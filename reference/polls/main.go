// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

// main.go is the second reference for extending the batteries-included starter
// with your OWN module. Where reference/custommodule shows the smallest useful
// shape of the seam, this one shows what a fully-formed domain module looks
// like: append-only migrations with legacy-schema adoption, a draft → published
// → closed → archived lifecycle, author ownership plus a moderator scope, an
// audit outbox committed atomically with each mutation, server-signed anonymous
// voter identity, per-network throttling, module counters on /metrics, and a
// public browser surface alongside the JSON API.
//
// It is intentionally outside pkg/: it is not installed by the starter, not a
// product template, and not another supported composition.
//
// Run it, then:
//
//	SID=$(curl -s -X POST localhost:8080/api/v1/auth/sessions \
//	  -d '{"tenant_id":"tenant_local","email":"operator@local.test","password":"local-development-only"}' | jq -r .id)
//	curl -s -X POST localhost:8080/api/v1/polls -H "Authorization: Bearer $SID" -d '{"question":"tabs or spaces?"}'
//
// This remains a product poll, not an election system: clearing browser state
// can eventually mint another voter identity, and the throttle is per-process.
//
// ADR: ADR-0017 (composition through dependency injection), ADR-0029 (file purpose declaration).
// Convention: C-14 (every Go file declares its purpose).
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	_ "modernc.org/sqlite"

	"github.com/septagon-oss/pk-apps/pkg/starterapp"
	"github.com/septagon-oss/pk-apps/reference/polls/pollmodule"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	cfg := starterapp.DefaultConfig()
	cfg.AppName = "platformkit-polls"
	starterapp.ApplyAddressOverrides(cfg, os.Getenv)
	if err := starterapp.Run(ctx, cfg, starterapp.WithModules(buildPollModule)); err != nil {
		log.Fatalf("platformkit polls: %v", err)
	}
}

func buildPollModule(env starterapp.ModuleEnv) (starterapp.ModulePlugin, error) {
	polls, err := pollmodule.NewModule(
		pollmodule.WithDB(env.DB),
		pollmodule.WithAdminRegistrar(env.Admin),
		pollmodule.WithHealthRegistrar(env.Health),
		pollmodule.WithAuditService(env.Audit),
	)
	if err != nil {
		return starterapp.ModulePlugin{}, fmt.Errorf("poll module: %w", err)
	}
	return starterapp.ModulePlugin{
		ID:                   pollmodule.ModuleID,
		Compose:              polls.Compose,
		RegisterRoutes:       polls.HTTPHandler().RegisterRoutes,
		RegisterPublicRoutes: polls.HTTPHandler().RegisterPublicRoutes,
		OpenAPI:              pollOpenAPIOperations(),
		APIKeyScopes:         pollmodule.APIKeyScopes(),
	}, nil
}

func pollOpenAPIOperations() []starterapp.OpenAPIOperation {
	return []starterapp.OpenAPIOperation{
		{OperationID: "polls.list", Method: http.MethodGet, Path: "/api/v1/polls", Summary: "List polls", Tags: []string{"polls"}},
		{OperationID: "polls.create", Method: http.MethodPost, Path: "/api/v1/polls", Summary: "Create a draft poll", Tags: []string{"polls"}},
		{OperationID: "polls.get", Method: http.MethodGet, Path: "/api/v1/polls/{id}", Summary: "Get a poll", Tags: []string{"polls"}},
		{OperationID: "polls.update", Method: http.MethodPut, Path: "/api/v1/polls/{id}", Summary: "Update a draft poll", Tags: []string{"polls"}},
		{OperationID: "polls.delete", Method: http.MethodDelete, Path: "/api/v1/polls/{id}", Summary: "Delete a draft poll", SuccessStatus: http.StatusNoContent, Tags: []string{"polls"}},
		{OperationID: "polls.publish", Method: http.MethodPost, Path: "/api/v1/polls/{id}/publish", Summary: "Publish a poll", SuccessStatus: http.StatusOK, Tags: []string{"polls"}},
		{OperationID: "polls.close", Method: http.MethodPost, Path: "/api/v1/polls/{id}/close", Summary: "Close voting", SuccessStatus: http.StatusOK, Tags: []string{"polls"}},
		{OperationID: "polls.archive", Method: http.MethodPost, Path: "/api/v1/polls/{id}/archive", Summary: "Archive a poll", SuccessStatus: http.StatusOK, Tags: []string{"polls"}},
		{OperationID: "polls.publicGet", Method: http.MethodGet, Path: "/api/v1/public/polls/{slug}", Summary: "Read a public poll and results", Public: true, Tags: []string{"public polls"}},
		{OperationID: "polls.publicVote", Method: http.MethodPost, Path: "/api/v1/public/polls/{slug}/votes", Summary: "Create or change a public ballot", Public: true, SuccessStatus: http.StatusOK, Tags: []string{"public polls"}},
	}
}
