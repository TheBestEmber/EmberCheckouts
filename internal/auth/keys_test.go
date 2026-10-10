package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestJWKSVerifierValidatesClaimsAndAlgorithm(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := jwksServer(t, func() (string, ed25519.PublicKey) { return "key-1", publicKey }, nil)
	defer server.Close()
	verifier, err := NewJWKSVerifier(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	verifier.now = func() time.Time { return now }
	claims := map[string]any{
		"iss": server.URL, "sub": "user-1", "aud": Audience, "iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(), "scope": "runtime checkouts:write",
		"membership_id": "membership-1", "installation_id": "installation-1", "session_id": "session-1",
	}
	token := signToken(t, privateKey, "key-1", "EdDSA", claims)
	identity, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if identity.MembershipID != "membership-1" || identity.SessionID != "session-1" {
		t.Fatalf("identity = %+v", identity)
	}

	for name, mutate := range map[string]func(map[string]any){
		"wrong issuer":    func(c map[string]any) { c["iss"] = "https://other.example" },
		"extra audience":  func(c map[string]any) { c["aud"] = []string{Audience, "other"} },
		"expired":         func(c map[string]any) { c["exp"] = now.Unix() },
		"missing session": func(c map[string]any) { delete(c, "session_id") },
		"missing scope":   func(c map[string]any) { c["scope"] = "runtime" },
		"missing iat":     func(c map[string]any) { delete(c, "iat") },
		"older than 90s": func(c map[string]any) {
			c["iat"] = now.Add(-91 * time.Second).Unix()
			c["exp"] = now.Add(time.Hour).Unix()
		},
		"future iat": func(c map[string]any) { c["iat"] = now.Add(61 * time.Second).Unix() },
	} {
		t.Run(name, func(t *testing.T) {
			copy := cloneClaims(t, claims)
			mutate(copy)
			if _, err := verifier.Verify(context.Background(), signToken(t, privateKey, "key-1", "EdDSA", copy)); err == nil {
				t.Fatal("invalid token was accepted")
			}
		})
	}
	if _, err := verifier.Verify(context.Background(), signToken(t, privateKey, "key-1", "HS256", claims)); err == nil {
		t.Fatal("algorithm confusion token was accepted")
	}
}

func TestJWKSVerifierRefetchesUnknownKey(t *testing.T) {
	public1, private1, _ := ed25519.GenerateKey(rand.Reader)
	public2, private2, _ := ed25519.GenerateKey(rand.Reader)
	var current atomic.Int32
	var requests atomic.Int32
	server := jwksServer(t, func() (string, ed25519.PublicKey) {
		requests.Add(1)
		if current.Load() == 0 {
			return "key-1", public1
		}
		return "key-2", public2
	}, nil)
	defer server.Close()
	verifier, _ := NewJWKSVerifier(server.URL, server.Client())
	now := time.Now()
	verifier.now = func() time.Time { return now }
	claims := map[string]any{
		"iss": server.URL, "sub": "user-1", "aud": []string{Audience}, "iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(), "scopes": []string{"checkouts:write"},
		"membership_id": "membership-1", "installation_id": "installation-1", "session_id": "session-1",
	}
	if _, err := verifier.Verify(context.Background(), signToken(t, private1, "key-1", "EdDSA", claims)); err != nil {
		t.Fatal(err)
	}
	current.Store(1)
	if _, err := verifier.Verify(context.Background(), signToken(t, private2, "key-2", "EdDSA", claims)); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatalf("JWKS requests = %d, want 2", requests.Load())
	}
}

func TestJWKSVerifierSupportsSeparateDiscoveryURL(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	server := jwksServer(t, func() (string, ed25519.PublicKey) { return "key-1", publicKey }, nil)
	defer server.Close()
	issuer := "https://auth.example.com"
	verifier, err := NewJWKSVerifierAt(
		issuer, server.URL+"/.well-known/jwks.json", server.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	verifier.now = func() time.Time { return now }
	claims := map[string]any{
		"iss": issuer, "sub": "user-1", "aud": Audience, "iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(), "scope": "checkouts:write",
		"membership_id": "membership-1", "installation_id": "installation-1", "session_id": "session-1",
	}
	if _, err := verifier.Verify(
		context.Background(), signToken(t, privateKey, "key-1", "EdDSA", claims),
	); err != nil {
		t.Fatal(err)
	}
}

func jwksServer(t *testing.T, current func() (string, ed25519.PublicKey), requests *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests != nil {
			requests.Add(1)
		}
		kid, key := current()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": kid,
			"x": base64.RawURLEncoding.EncodeToString(key),
		}}})
	}))
}

func signToken(t *testing.T, key ed25519.PrivateKey, kid, algorithm string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": algorithm, "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(unsigned)))
}

func cloneClaims(t *testing.T, claims map[string]any) map[string]any {
	t.Helper()
	data, _ := json.Marshal(claims)
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
