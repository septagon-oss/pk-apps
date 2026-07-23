// Package starterapp — openapi.go validates extension operation declarations
// and renders their aggregate OpenAPI 3.1 discovery document.
//
// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.
package starterapp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
)

var openAPIOperationIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]*$`)

func validateOpenAPIOperations(
	moduleID string,
	operations []OpenAPIOperation,
	seenRoutes map[string]string,
	seenOperationIDs map[string]string,
) error {
	for i := range operations {
		op := &operations[i]
		op.Method = strings.ToUpper(strings.TrimSpace(op.Method))
		op.Path = strings.TrimSpace(op.Path)
		op.OperationID = strings.TrimSpace(op.OperationID)
		op.Summary = strings.TrimSpace(op.Summary)

		switch op.Method {
		case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			return fmt.Errorf(
				"contributed module %q OpenAPI operation %q: unsupported method %q",
				moduleID, op.OperationID, op.Method,
			)
		}
		if op.Path == "" ||
			!strings.HasPrefix(op.Path, "/") ||
			strings.ContainsAny(op.Path, "?# \t\r\n") ||
			path.Clean(op.Path) != op.Path {
			return fmt.Errorf(
				"contributed module %q OpenAPI operation %q: invalid canonical path %q",
				moduleID, op.OperationID, op.Path,
			)
		}
		if !openAPIOperationIDPattern.MatchString(op.OperationID) {
			return fmt.Errorf(
				"contributed module %q OpenAPI operation: invalid operation ID %q",
				moduleID, op.OperationID,
			)
		}
		if owner, exists := seenOperationIDs[op.OperationID]; exists {
			return fmt.Errorf(
				"contributed module %q OpenAPI operation ID %q is already owned by %q",
				moduleID, op.OperationID, owner,
			)
		}
		seenOperationIDs[op.OperationID] = moduleID
		if op.Summary == "" {
			return fmt.Errorf(
				"contributed module %q OpenAPI operation %q: summary is required",
				moduleID, op.OperationID,
			)
		}
		if op.SuccessStatus == 0 {
			if op.Method == http.MethodPost {
				op.SuccessStatus = http.StatusCreated
			} else {
				op.SuccessStatus = http.StatusOK
			}
		}
		if op.SuccessStatus < 100 || op.SuccessStatus > 599 {
			return fmt.Errorf(
				"contributed module %q OpenAPI operation %q: invalid success status %d",
				moduleID, op.OperationID, op.SuccessStatus,
			)
		}

		key := op.Method + " " + op.Path
		if owner, exists := seenRoutes[key]; exists {
			return fmt.Errorf(
				"contributed module %q OpenAPI operation %q duplicates %s owned by %q",
				moduleID, op.OperationID, key, owner,
			)
		}
		seenRoutes[key] = moduleID
	}
	return nil
}

type openAPIInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type openAPISecurityRequirement map[string][]string

type openAPIOperationDocument struct {
	OperationID string                       `json:"operationId"`
	Summary     string                       `json:"summary"`
	Description string                       `json:"description,omitempty"`
	Tags        []string                     `json:"tags,omitempty"`
	Security    []openAPISecurityRequirement `json:"security"`
	Responses   map[string]openAPIResponse   `json:"responses"`
}

type openAPIResponse struct {
	Description string `json:"description"`
}

type openAPISecurityScheme struct {
	Type         string `json:"type"`
	Scheme       string `json:"scheme"`
	BearerFormat string `json:"bearerFormat"`
}

type openAPIComponents struct {
	SecuritySchemes map[string]openAPISecurityScheme `json:"securitySchemes"`
}

type extensionOpenAPIDocument struct {
	OpenAPI    string                                         `json:"openapi"`
	Info       openAPIInfo                                    `json:"info"`
	Paths      map[string]map[string]openAPIOperationDocument `json:"paths"`
	Components openAPIComponents                              `json:"components"`
}

func (a *App) extensionOpenAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	doc := extensionOpenAPIDocument{
		OpenAPI: "3.1.0",
		Info: openAPIInfo{
			Title:   a.appName + " extension API",
			Version: a.appVersion,
		},
		Paths: make(map[string]map[string]openAPIOperationDocument),
		Components: openAPIComponents{
			SecuritySchemes: map[string]openAPISecurityScheme{
				"bearerAuth": {
					Type:         "http",
					Scheme:       "bearer",
					BearerFormat: "session or API key",
				},
			},
		},
	}
	for _, op := range a.openAPIOperations {
		security := []openAPISecurityRequirement{{"bearerAuth": {}}}
		if op.Public {
			security = []openAPISecurityRequirement{}
		}
		if doc.Paths[op.Path] == nil {
			doc.Paths[op.Path] = make(map[string]openAPIOperationDocument)
		}
		doc.Paths[op.Path][strings.ToLower(op.Method)] = openAPIOperationDocument{
			OperationID: op.OperationID,
			Summary:     op.Summary,
			Description: strings.TrimSpace(op.Description),
			Tags:        append([]string(nil), op.Tags...),
			Security:    security,
			Responses: map[string]openAPIResponse{
				strconv.Itoa(op.SuccessStatus): {Description: "Successful response"},
			},
		}
	}

	w.Header().Set("Content-Type", "application/vnd.oai.openapi+json;version=3.1.0")
	w.Header().Set("Cache-Control", "public, max-age=60")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		http.Error(w, "encode OpenAPI document", http.StatusInternalServerError)
	}
}
