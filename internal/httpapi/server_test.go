package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/emberaio/embercheckouts/internal/crypto"
	"github.com/emberaio/embercheckouts/internal/domain"
	"github.com/emberaio/embercheckouts/internal/store"
)

type fakeVerifier struct {
	identity domain.Identity
	err      error
}

func (f fakeVerifier) Verify(context.Context, string) (domain.Identity, error) {
	return f.identity, f.err
}

type fakeStore struct {
	created  domain.CheckoutMetadata
	identity domain.Identity
	envelope crypto.Envelope
	checkout store.Checkout
	event    string
	getErr   error
}

func (f *fakeStore) Ready(context.Context) error { return nil }
func (f *fakeStore) CreateCheckout(_ context.Context, identity domain.Identity, metadata domain.CheckoutMetadata, envelope crypto.Envelope) error {
	f.identity, f.created, f.envelope = identity, metadata, envelope
	return nil
}
func (f *fakeStore) GetCheckout(context.Context, string) (store.Checkout, error) {
	return f.checkout, f.getErr
}
func (f *fakeStore) AddEvent(_ context.Context, _ string, outcome string) error {
	f.event = outcome
	return nil
}

func testServer(t *testing.T) (*Server, *fakeStore, *crypto.Keyring) {
	t.Helper()
	keyring, err := crypto.NewKeyring("test", map[string][]byte{"test": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	identity := domain.Identity{
		Subject: "user-1", MembershipID: "membership-1",
		InstallationID: "installation-1", SessionID: "session-1",
	}
	data := &fakeStore{}
	server := New(Config{
		Store: data, Verifier: fakeVerifier{identity: identity}, Keyring: keyring,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		PublicBaseURL: "http://localhost:8080", RateLimitPerMinute: 100,
	})
	return server, data, keyring
}

func validBody() string {
	return `{
		"module":"skiddle","site":"skiddle","title":"Final Release",
		"targetUrl":"https://www.skiddle.com/basket/default.php",
		"cookies":[],"storage":{"local":[],"session":[]},
		"display":{"quantity":2,"price":"109.12","currency":"GBP"},
		"producerVersion":"1.2.3"
	}`
}

func TestCreateCheckoutEncryptsPayloadAndOwnsExpiry(t *testing.T) {
	server, data, keyring := testServer(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/checkouts", strings.NewReader(validBody()))
	request.Header.Set("Authorization", "Bearer signed.jwt.value")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if data.created.TargetHost != "www.skiddle.com" || len(data.envelope.Ciphertext) == 0 {
		t.Fatalf("checkout was not persisted as encrypted metadata: %+v", data.created)
	}
	if data.created.ExpiresAt.Sub(data.created.CreatedAt) != domain.CheckoutTTL {
		t.Fatalf("TTL = %s", data.created.ExpiresAt.Sub(data.created.CreatedAt))
	}
	if !strings.Contains(response.Body.String(), "/open#checkout=") ||
		strings.Contains(response.Body.String(), "signed.jwt.value") {
		t.Fatalf("unsafe create response: %s", response.Body.String())
	}
	plaintext, err := keyring.Decrypt(data.identity.Subject, data.created.ID, data.envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plaintext), "basket/default.php") {
		t.Fatal("decrypted handoff is incomplete")
	}
}

func TestCreateRejectsProducerExpiry(t *testing.T) {
	server, _, _ := testServer(t)
	body := strings.TrimSuffix(validBody(), "}") + `,"expiresAt":"2030-01-01T00:00:00Z"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/checkouts", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestAuthorizationRunsBeforeBodyValidation(t *testing.T) {
	server, _, _ := testServer(t)
	server.verifier = fakeVerifier{err: errorsForTest{}}
	request := httptest.NewRequest(http.MethodPost, "/v1/checkouts", strings.NewReader("{"))
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}

type errorsForTest struct{}

func (errorsForTest) Error() string { return "invalid" }

func TestGetCheckoutIsPublicAndReusable(t *testing.T) {
	server, data, keyring := testServer(t)
	id := "33333333-3333-4333-8333-333333333333"
	handoff := domain.Handoff{
		Module: "skiddle", Site: "skiddle", Title: "Final Release",
		TargetURL: "https://www.skiddle.com/basket/default.php",
		Cookies:   []domain.Cookie{}, Storage: domain.Storage{
			Local: []domain.StorageGroup{}, Session: []domain.StorageGroup{},
		},
		Display:         domain.Display{Quantity: 2, Price: "109.12", Currency: "GBP"},
		ProducerVersion: "1.2.3",
	}
	plaintext, _ := json.Marshal(handoff)
	envelope, err := keyring.Encrypt("user-1", id, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	data.checkout = store.Checkout{
		OwnerSubject: "user-1", ExpiresAt: time.Now().Add(time.Minute), Envelope: envelope,
	}
	for range 2 {
		request := httptest.NewRequest(http.MethodGet, "/v1/checkouts/"+id, nil)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Final Release") {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	}
}

func TestExpiredCheckoutAndEvents(t *testing.T) {
	server, data, _ := testServer(t)
	id := "33333333-3333-4333-8333-333333333333"
	data.getErr = store.ErrGone
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/checkouts/"+id, nil))
	if response.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", response.Code)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/checkouts/"+id+"/events",
		strings.NewReader(`{"outcome":"proxy_failed"}`))
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || data.event != "proxy_failed" {
		t.Fatalf("event status = %d, outcome = %q", response.Code, data.event)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/checkouts/"+id+"/events",
		strings.NewReader(`{"outcome":"failure: token=secret"}`))
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("arbitrary event status = %d", response.Code)
	}
}

func TestOpenPageAndNoWildcardCORS(t *testing.T) {
	server, _, _ := testServer(t)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/open", nil))
	if response.Code != http.StatusOK || response.Header().Get("Referrer-Policy") != "no-referrer" ||
		!strings.Contains(response.Body.String(), `name="referrer" content="no-referrer"`) {
		t.Fatalf("open page is missing no-referrer protection: status=%d header=%q body=%q",
			response.Code, response.Header().Get("Referrer-Policy"), response.Body.String())
	}

	id := "33333333-3333-4333-8333-333333333333"
	for _, method := range []string{http.MethodOptions, http.MethodGet} {
		response = httptest.NewRecorder()
		request := httptest.NewRequest(method, "/v1/checkouts/"+id, nil)
		request.Header.Set("Origin", "https://attacker.example")
		server.Handler().ServeHTTP(response, request)
		if response.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("%s returned a CORS allow-origin header", method)
		}
	}
}

func TestRequestLogOmitsCheckoutCapability(t *testing.T) {
	server, data, _ := testServer(t)
	var logs bytes.Buffer
	server.logger = slog.New(slog.NewTextHandler(&logs, nil))
	data.getErr = store.ErrGone
	id := "33333333-3333-4333-8333-333333333333"
	server.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/checkouts/"+id, nil))
	if strings.Contains(logs.String(), id) || !strings.Contains(logs.String(), "status=410") ||
		!strings.Contains(logs.String(), "/v1/checkouts/{checkoutID}") {
		t.Fatalf("request log = %q", logs.String())
	}
}

func TestRateLimitKeysOnForwardedClientOnlyBehindTrustedProxy(t *testing.T) {
	server, _, _ := testServer(t)
	server.proxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	request := httptest.NewRequest(http.MethodGet, "/v1/checkouts/x", nil)
	request.RemoteAddr = "10.0.0.5:443"
	request.Header.Set("X-Forwarded-For", "1.1.1.1, 198.51.100.7")
	if got := server.clientIP(request); got != "198.51.100.7" {
		t.Fatalf("behind trusted proxy clientIP = %q", got)
	}
	request.RemoteAddr = "203.0.113.9:443"
	if got := server.clientIP(request); got != "203.0.113.9" {
		t.Fatalf("untrusted peer clientIP = %q", got)
	}
}
