package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/emberaio/embercheckouts/internal/auth"
	"github.com/emberaio/embercheckouts/internal/crypto"
	"github.com/emberaio/embercheckouts/internal/domain"
	"github.com/emberaio/embercheckouts/internal/store"
	"github.com/google/uuid"
)

const maxBodyBytes = 1 << 20

var allowedOutcomes = map[string]bool{
	"import_succeeded":          true,
	"import_partial":            true,
	"invalid_payload":           true,
	"permissions_denied":        true,
	"cookies_failed":            true,
	"local_storage_failed":      true,
	"session_storage_failed":    true,
	"proxy_failed":              true,
	"navigation_failed":         true,
	"unsupported_browser_state": true,
}

type DataStore interface {
	Ready(context.Context) error
	CreateCheckout(context.Context, domain.Identity, domain.CheckoutMetadata, crypto.Envelope) error
	GetCheckout(context.Context, string) (store.Checkout, error)
	AddEvent(context.Context, string, string) error
}

type Config struct {
	Store              DataStore
	Verifier           auth.Verifier
	Keyring            *crypto.Keyring
	Logger             *slog.Logger
	PublicBaseURL      string
	AllowLocalhostHTTP bool
	RateLimitPerMinute int
	TrustedProxies     []netip.Prefix
}

type Server struct {
	store              DataStore
	verifier           auth.Verifier
	keyring            *crypto.Keyring
	logger             *slog.Logger
	publicBaseURL      string
	allowLocalhostHTTP bool
	limiter            *limiter
	proxies            []netip.Prefix
	handler            http.Handler
}

func New(cfg Config) *Server {
	s := &Server{
		store: cfg.Store, verifier: cfg.Verifier, keyring: cfg.Keyring, logger: cfg.Logger,
		publicBaseURL:      strings.TrimRight(cfg.PublicBaseURL, "/"),
		allowLocalhostHTTP: cfg.AllowLocalhostHTTP,
		limiter:            newLimiter(cfg.RateLimitPerMinute),
		proxies:            cfg.TrustedProxies,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /open", s.open)
	mux.HandleFunc("POST /v1/checkouts", s.createCheckout)
	mux.HandleFunc("GET /v1/checkouts/{checkoutID}", s.getCheckout)
	mux.HandleFunc("POST /v1/checkouts/{checkoutID}/events", s.addEvent)
	s.handler = s.middleware(mux)
	return s
}

func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if !s.keyring.Ready() || s.store.Ready(ctx) != nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "not_ready", "service is not ready")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) open(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = openPage.Execute(w, nil)
}

func (s *Server) createCheckout(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.authorize(w, r)
	if !ok || !s.allow(w, r, identity.SessionID) {
		return
	}
	var handoff domain.Handoff
	if !s.decode(w, r, &handoff) {
		return
	}
	now := time.Now().UTC()
	if err := domain.ValidateHandoff(&handoff, domain.ValidationOptions{
		Now: now, AllowLocalhostHTTP: s.allowLocalhostHTTP,
	}); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	plaintext, err := json.Marshal(handoff)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	checkoutID := uuid.NewString()
	envelope, err := s.keyring.Encrypt(identity.Subject, checkoutID, plaintext)
	clear(plaintext)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	metadata := domain.MetadataFor(checkoutID, handoff, now)
	if err := s.store.CreateCheckout(r.Context(), identity, metadata, envelope); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"checkout": metadata,
		"openUrl":  s.publicBaseURL + "/open#checkout=" + checkoutID,
	})
}

func (s *Server) getCheckout(w http.ResponseWriter, r *http.Request) {
	checkoutID := r.PathValue("checkoutID")
	if !validV4(checkoutID) {
		s.writeError(w, r, http.StatusNotFound, "not_found", "checkout not found")
		return
	}
	if !s.allow(w, r, checkoutID) {
		return
	}
	checkout, err := s.store.GetCheckout(r.Context(), checkoutID)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	plaintext, err := s.keyring.Decrypt(checkout.OwnerSubject, checkoutID, checkout.Envelope)
	if err != nil {
		s.internalError(w, r, errors.New("checkout envelope authentication failed"))
		return
	}
	defer clear(plaintext)
	var handoff domain.Handoff
	if err := json.Unmarshal(plaintext, &handoff); err != nil {
		s.internalError(w, r, errors.New("decrypted checkout is invalid"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"handoff": handoff, "expiresAt": checkout.ExpiresAt})
}

func (s *Server) addEvent(w http.ResponseWriter, r *http.Request) {
	checkoutID := r.PathValue("checkoutID")
	if !validV4(checkoutID) {
		s.writeError(w, r, http.StatusNotFound, "not_found", "checkout not found")
		return
	}
	if !s.allow(w, r, checkoutID) {
		return
	}
	var event struct {
		Outcome string `json:"outcome"`
	}
	if !s.decode(w, r, &event) {
		return
	}
	if !allowedOutcomes[event.Outcome] {
		s.writeError(w, r, http.StatusBadRequest, "validation_failed", "outcome is not allowed")
		return
	}
	if err := s.store.AddEvent(r.Context(), checkoutID, event.Outcome); err != nil {
		s.storeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) (domain.Identity, bool) {
	raw, err := bearer(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ember-checkouts"`)
		s.writeError(w, r, http.StatusUnauthorized, "unauthorized", "missing or invalid access token")
		return domain.Identity{}, false
	}
	identity, err := s.verifier.Verify(r.Context(), raw)
	if err != nil {
		if errors.Is(err, auth.ErrInsufficientScope) {
			s.writeError(w, r, http.StatusForbidden, "insufficient_scope", "access token lacks checkouts:write")
			return domain.Identity{}, false
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="ember-checkouts"`)
		s.writeError(w, r, http.StatusUnauthorized, "unauthorized", "missing or invalid access token")
		return domain.Identity{}, false
	}
	return identity, true
}

func bearer(header string) (string, error) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" ||
		len(token) > 16<<10 || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("invalid bearer token")
	}
	return token, nil
}

func validV4(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id.Version() == 4 && id.String() == strings.ToLower(value)
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.writeError(w, r, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds 1 MiB")
		} else {
			s.writeError(w, r, http.StatusBadRequest, "malformed_json", "request body must be valid JSON")
		}
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		s.writeError(w, r, http.StatusBadRequest, "malformed_json", "request body must contain one JSON object")
		return false
	}
	return true
}

func (s *Server) storeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.writeError(w, r, http.StatusNotFound, "not_found", "checkout not found")
	case errors.Is(err, store.ErrGone):
		s.writeError(w, r, http.StatusGone, "checkout_expired", "checkout has expired")
	case errors.Is(err, store.ErrEventCap):
		s.writeError(w, r, http.StatusTooManyRequests, "event_limit_reached", "checkout event limit reached")
	default:
		s.internalError(w, r, err)
	}
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.ErrorContext(r.Context(), "request failed", "request_id", requestID(r),
		"method", r.Method, "path", r.URL.Path, "error", err)
	s.writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{
		"code": code, "message": message, "requestId": requestID(r),
	}})
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestIDValue := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if _, err := uuid.Parse(requestIDValue); err != nil {
			requestIDValue = uuid.NewString()
		}
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, requestIDValue))
		w.Header().Set("X-Request-ID", requestIDValue)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.ErrorContext(r.Context(), "panic recovered",
					"request_id", requestIDValue, "panic", fmt.Sprint(recovered))
				s.writeError(recorder, r, http.StatusInternalServerError, "internal_error", "internal server error")
			}
			// Log the route pattern, never the path: it carries the checkout capability.
			s.logger.InfoContext(r.Context(), "request", "request_id", requestIDValue,
				"method", r.Method, "route", r.Pattern, "status", recorder.status,
				"duration_ms", time.Since(started).Milliseconds())
		}()
		next.ServeHTTP(recorder, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (s *Server) allow(w http.ResponseWriter, r *http.Request, key string) bool {
	if !s.limiter.Allow(key + "|" + s.clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		s.writeError(w, r, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded")
		return false
	}
	return true
}

// clientIP honours X-Forwarded-For only when the direct peer is a trusted proxy,
// taking the right-most hop that is not itself trusted.
func (s *Server) clientIP(r *http.Request) string {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		host, _, splitErr := net.SplitHostPort(r.RemoteAddr)
		if splitErr != nil {
			return r.RemoteAddr
		}
		return host
	}
	addr := peer.Addr().Unmap()
	if !s.trusted(addr) {
		return addr.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for index := len(hops) - 1; index >= 0; index-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[index]))
		if err != nil {
			break
		}
		addr = hop.Unmap()
		if !s.trusted(addr) {
			break
		}
	}
	return addr.String()
}

func (s *Server) trusted(addr netip.Addr) bool {
	for _, prefix := range s.proxies {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func requestID(r *http.Request) string {
	value, _ := r.Context().Value(requestIDKey{}).(string)
	return value
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type requestIDKey struct{}

type limiter struct {
	mu      sync.Mutex
	limit   int
	entries map[string]limitEntry
}

type limitEntry struct {
	window time.Time
	count  int
}

func newLimiter(limit int) *limiter {
	return &limiter{limit: limit, entries: make(map[string]limitEntry)}
}

func (l *limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	entry := l.entries[key]
	if entry.window.IsZero() || now.Sub(entry.window) >= time.Minute {
		entry = limitEntry{window: now}
	}
	entry.count++
	l.entries[key] = entry
	if len(l.entries) > 10000 {
		for candidate, value := range l.entries {
			if now.Sub(value.window) >= time.Minute {
				delete(l.entries, candidate)
			}
		}
	}
	return entry.count <= l.limit
}

var openPage = template.Must(template.New("open").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta name="referrer" content="no-referrer"><title>Ember Checkout</title></head><body>
<main><h1>Ember Checkout</h1><p>Open or refresh the Ember extension to continue this checkout.</p></main>
</body></html>`))
