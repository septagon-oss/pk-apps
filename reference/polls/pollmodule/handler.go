// Implements: REQ-016.
// Per: ADR-0017.
// Discipline: C-14.

package pollmodule

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/septagon-oss/pk-core/pkg/security/identity"
)

const publicAPIPath = "/api/v1/public/polls"

// Handler exposes scoped poll management, a public JSON API, and a
// browser-native voting page.
type Handler struct {
	service     *Service
	voterSecret []byte
	limiter     *voteLimiter
}

// NewHandler creates a poll HTTP handler with a persisted voter-cookie secret.
func NewHandler(service *Service, voterSecret []byte) (*Handler, error) {
	if service == nil {
		return nil, errors.New("poll: handler requires a service")
	}
	if len(voterSecret) != 32 {
		return nil, errors.New("poll: handler requires a 32-byte voter secret")
	}
	return &Handler{
		service:     service,
		voterSecret: append([]byte(nil), voterSecret...),
		limiter:     newVoteLimiter(),
	}, nil
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle(APIPath, h)
	mux.Handle(APIPath+"/", h)
}

func (h *Handler) RegisterPublicRoutes(mux *http.ServeMux) {
	mux.Handle("/polls/", http.HandlerFunc(h.servePublicPage))
	mux.Handle(publicAPIPath+"/", http.HandlerFunc(h.servePublicAPI))
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	segments := pathSegments(strings.TrimPrefix(r.URL.Path, APIPath))
	if len(segments) == 0 {
		h.serveCollection(w, r)
		return
	}
	if len(segments) == 1 {
		h.serveItem(w, r, segments[0])
		return
	}
	if len(segments) == 2 && r.Method == http.MethodPost {
		switch segments[1] {
		case "publish":
			h.transition(w, r, segments[0], StatusPublished)
		case "close":
			h.transition(w, r, segments[0], StatusClosed)
		case "archive":
			h.transition(w, r, segments[0], StatusArchived)
		default:
			http.NotFound(w, r)
		}
		return
	}
	http.NotFound(w, r)
}

func (h *Handler) serveCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		principal, ok := requirePollScope(w, r, ScopeRead)
		if ok {
			h.list(w, r, principal)
		}
	case http.MethodPost:
		principal, ok := requirePollScope(w, r, ScopeWrite)
		if ok {
			h.create(w, r, principal)
		}
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

func (h *Handler) serveItem(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		principal, ok := requirePollScope(w, r, ScopeRead)
		if ok {
			h.get(w, r, principal, id)
		}
	case http.MethodPut:
		principal, ok := requirePollScope(w, r, ScopeWrite)
		if ok {
			h.update(w, r, principal, id)
		}
	case http.MethodDelete:
		principal, ok := requirePollScope(w, r, ScopeWrite)
		if ok {
			h.delete(w, r, principal, id)
		}
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request, principal identity.Principal) {
	limit, err := queryInt(r, "limit", 25)
	if err != nil {
		writeClientError(w, err.Error())
		return
	}
	offset, err := queryInt(r, "offset", 0)
	if err != nil {
		writeClientError(w, err.Error())
		return
	}
	page, err := h.service.List(r.Context(), principal.TenantID, limit, offset)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request, principal identity.Principal) {
	var input PollUpdate
	if err := decodeJSON(r, &input); err != nil {
		writeClientError(w, "invalid JSON: "+err.Error())
		return
	}
	poll := &Poll{
		TenantID:    principal.TenantID,
		AuthorID:    principal.Subject,
		Slug:        input.Slug,
		Title:       input.Title,
		Description: input.Description,
		Options:     input.Options,
		ClosesAt:    input.ClosesAt,
	}
	if err := h.service.Create(r.Context(), poll); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, poll)
}

func (h *Handler) get(
	w http.ResponseWriter,
	r *http.Request,
	principal identity.Principal,
	id string,
) {
	poll, err := h.service.Get(r.Context(), principal.TenantID, id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, poll)
}

func (h *Handler) update(
	w http.ResponseWriter,
	r *http.Request,
	principal identity.Principal,
	id string,
) {
	var input PollUpdate
	if err := decodeJSON(r, &input); err != nil {
		writeClientError(w, "invalid JSON: "+err.Error())
		return
	}
	poll, err := h.service.Update(
		r.Context(),
		principal.TenantID,
		principal.Subject,
		isPollModerator(principal),
		id,
		input,
	)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, poll)
}

func (h *Handler) transition(
	w http.ResponseWriter,
	r *http.Request,
	id,
	target string,
) {
	principal, ok := requirePollScope(w, r, ScopeWrite)
	if !ok {
		return
	}
	poll, err := h.service.Transition(
		r.Context(),
		principal.TenantID,
		principal.Subject,
		isPollModerator(principal),
		id,
		target,
	)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, poll)
}

func (h *Handler) delete(
	w http.ResponseWriter,
	r *http.Request,
	principal identity.Principal,
	id string,
) {
	err := h.service.Delete(
		r.Context(),
		principal.TenantID,
		principal.Subject,
		isPollModerator(principal),
		id,
	)
	if err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) servePublicPage(w http.ResponseWriter, r *http.Request) {
	segments := pathSegments(strings.TrimPrefix(r.URL.Path, "/polls/"))
	switch {
	case len(segments) == 1 && r.Method == http.MethodGet:
		h.renderPublicPoll(w, r, segments[0], "", http.StatusOK)
	case len(segments) == 2 && segments[1] == "vote" && r.Method == http.MethodPost:
		h.publicFormVote(w, r, segments[0])
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) servePublicAPI(w http.ResponseWriter, r *http.Request) {
	segments := pathSegments(strings.TrimPrefix(r.URL.Path, publicAPIPath+"/"))
	switch {
	case len(segments) == 1 && r.Method == http.MethodGet:
		h.publicJSONView(w, r, segments[0])
	case len(segments) == 2 && segments[1] == "votes" && r.Method == http.MethodPost:
		h.publicJSONVote(w, r, segments[0])
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) publicJSONView(w http.ResponseWriter, r *http.Request, slug string) {
	poll, counts, err := h.publicResult(r, slug)
	if err != nil {
		writeError(w, err)
		return
	}
	addMetric("public_views_total", 1)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"poll":  publicPoll(poll, h.service.now()),
		"votes": counts,
		"total": sumCounts(counts),
	})
}

func (h *Handler) publicJSONVote(w http.ResponseWriter, r *http.Request, slug string) {
	var input struct {
		OptionIndex int    `json:"option_index"`
		Company     string `json:"company,omitempty"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeClientError(w, "invalid JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(input.Company) != "" {
		addMetric("honeypot_rejections_total", 1)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if !h.allowVote(w, r, true, slug) {
		return
	}
	voterID, err := h.voterIdentity(w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	_, counts, err := h.service.Vote(r.Context(), slug, input.OptionIndex, voterID)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"votes": counts,
		"total": sumCounts(counts),
	})
}

func (h *Handler) publicFormVote(w http.ResponseWriter, r *http.Request, slug string) {
	if err := r.ParseForm(); err != nil {
		h.renderPublicPoll(w, r, slug, "We could not read that ballot. Please try again.", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(r.PostForm.Get("company")) != "" {
		addMetric("honeypot_rejections_total", 1)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if !h.allowVote(w, r, false, slug) {
		return
	}
	optionIndex, err := strconv.Atoi(r.PostForm.Get("option_index"))
	if err != nil {
		h.renderPublicPoll(w, r, slug, "Choose one option before submitting.", http.StatusBadRequest)
		return
	}
	voterID, err := h.voterIdentity(w, r)
	if err != nil {
		h.renderPublicPoll(w, r, slug, "We could not create a ballot identity. Please try again.", http.StatusInternalServerError)
		return
	}
	if _, _, err := h.service.Vote(r.Context(), slug, optionIndex, voterID); err != nil {
		status, message := publicFormError(err)
		h.renderPublicPoll(w, r, slug, message, status)
		return
	}
	// slug reached Service.Vote and therefore resolves to a stored,
	// validation-conforming slug. Construct the local redirect explicitly so
	// no request-controlled scheme or host can enter Location.
	w.Header().Set("Location", "/polls/"+slug+"?voted=1")
	w.WriteHeader(http.StatusSeeOther)
}

func (h *Handler) renderPublicPoll(
	w http.ResponseWriter,
	r *http.Request,
	slug,
	message string,
	status int,
) {
	poll, counts, err := h.publicResult(r, slug)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writePublicUnavailable(
				w,
				http.StatusNotFound,
				"Poll unavailable",
				"This decision room does not exist, is still a draft, or has been archived.",
			)
			return
		}
		writePublicUnavailable(
			w,
			http.StatusInternalServerError,
			"Could not load this poll",
			"The decision room is temporarily unavailable. Please try again.",
		)
		return
	}
	voterID := h.existingVoterIdentity(r)
	choice, hasChoice, err := h.service.CurrentVote(r.Context(), poll.ID, voterID)
	if err != nil {
		writeError(w, err)
		return
	}
	view := buildPublicPageView(poll, counts, choice, hasChoice, h.service.now())
	view.Voted = r.URL.Query().Get("voted") == "1"
	view.Error = message
	addMetric("public_views_total", 1)
	writePublicPage(w, status, view)
}

func (h *Handler) publicResult(
	r *http.Request,
	slug string,
) (*Poll, map[int]int, error) {
	poll, err := h.service.GetPublicBySlug(r.Context(), slug)
	if err != nil {
		return nil, nil, err
	}
	counts, err := h.service.Results(r.Context(), poll)
	if err != nil {
		return nil, nil, err
	}
	return poll, counts, nil
}

func (h *Handler) allowVote(
	w http.ResponseWriter,
	r *http.Request,
	jsonResponse bool,
	slug string,
) bool {
	allowed, retry := h.limiter.allow(h.voteRateKey(r), h.service.now())
	if allowed {
		return true
	}
	addMetric("rate_limited_votes_total", 1)
	seconds := int(retry.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	if jsonResponse {
		writeError(w, ErrRateLimited)
	} else {
		h.renderPublicPoll(
			w,
			r,
			slug,
			"Too many ballots were submitted from this network. Please wait a minute and try again.",
			http.StatusTooManyRequests,
		)
	}
	return false
}

func requirePollScope(
	w http.ResponseWriter,
	r *http.Request,
	scope string,
) (identity.Principal, bool) {
	principal := identity.PrincipalFromContext(r.Context())
	if principal.IsAnonymous() || principal.TenantID == "" || principal.Subject == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "authentication with a tenant and subject is required",
		})
		return identity.Principal{}, false
	}
	if !principal.HasScope("admin") && !principal.HasScope(scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": scope + " scope is required",
		})
		return identity.Principal{}, false
	}
	return principal, true
}

func isPollModerator(principal identity.Principal) bool {
	return principal.HasScope("admin") || principal.HasScope(ScopeAdmin)
}

func decodeJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "poll not found"})
	case errors.Is(err, ErrDuplicate):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "poll slug is already in use"})
	case errors.Is(err, ErrValidation):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "poll ownership or moderator scope is required"})
	case isLifecycleError(err):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrRateLimited):
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many vote attempts; retry later"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
	}
}

func writeClientError(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func sumCounts(counts map[int]int) int {
	total := 0
	for _, count := range counts {
		total += count
	}
	return total
}

func pathSegments(value string) []string {
	value = strings.Trim(value, "/")
	if value == "" {
		return nil
	}
	segments := strings.Split(value, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return []string{"__invalid__", "__invalid__", "__invalid__"}
		}
	}
	return segments
}

func queryInt(r *http.Request, name string, fallback int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", name)
	}
	return value, nil
}

func publicFormError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrClosed):
		return http.StatusConflict, "Voting has closed for this poll."
	case errors.Is(err, ErrValidation):
		return http.StatusBadRequest, "That choice is not available."
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, "This poll is not available."
	default:
		return http.StatusInternalServerError, "We could not record that ballot. Please try again."
	}
}
