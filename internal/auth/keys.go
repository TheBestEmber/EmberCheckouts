package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/emberaio/embercheckouts/internal/domain"
)

const (
	Audience = "ember-services"
	// EmberAuth never issues tokens longer than this, so older ones are copies.
	maxTokenAge  = 90 * time.Second
	maxClockSkew = 60 * time.Second
)

var (
	ErrInvalidToken      = errors.New("invalid access token")
	ErrInsufficientScope = errors.New("access token lacks checkouts:write")
)

type Verifier interface {
	Verify(context.Context, string) (domain.Identity, error)
}

type JWKSVerifier struct {
	issuer   string
	jwksURL  string
	client   *http.Client
	cacheTTL time.Duration
	now      func() time.Time

	mu                sync.RWMutex
	keys              map[string]ed25519.PublicKey
	fetchedAt         time.Time
	lastForcedRefresh time.Time
}

func NewJWKSVerifier(issuer string, client *http.Client) (*JWKSVerifier, error) {
	return NewJWKSVerifierAt(issuer, "", client)
}

// NewJWKSVerifierAt allows containers to fetch JWKS through an internal
// endpoint while continuing to validate the public issuer exactly.
func NewJWKSVerifierAt(issuer, jwksURL string, client *http.Client) (*JWKSVerifier, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return nil, errors.New("issuer is required")
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("issuer must be an absolute URL without credentials, query, or fragment")
	}
	host := strings.ToLower(parsed.Hostname())
	loopback := host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback) {
		return nil, errors.New("issuer must use HTTPS except on loopback")
	}
	if jwksURL == "" {
		jwksURL = issuer + "/.well-known/jwks.json"
	} else {
		jwksURL = strings.TrimSpace(jwksURL)
		if err := validateJWKSURL(jwksURL); err != nil {
			return nil, err
		}
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	ownedClient := *client
	ownedClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &JWKSVerifier{
		issuer: issuer, jwksURL: jwksURL, client: &ownedClient,
		cacheTTL: 5 * time.Minute, now: time.Now,
	}, nil
}

func validateJWKSURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Path != "/.well-known/jwks.json" {
		return errors.New("JWKS URL must be an absolute /.well-known/jwks.json URL")
	}
	host := strings.ToLower(parsed.Hostname())
	local := host == "localhost" || host == "host.docker.internal" ||
		net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && local) {
		return errors.New("JWKS URL must use HTTPS except for local development")
	}
	return nil
}

func (v *JWKSVerifier) Verify(ctx context.Context, raw string) (domain.Identity, error) {
	if len(raw) > 16<<10 {
		return domain.Identity{}, ErrInvalidToken
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return domain.Identity{}, ErrInvalidToken
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if err := decodePart(parts[0], &header); err != nil ||
		header.Algorithm != "EdDSA" || header.KeyID == "" || (header.Type != "" && header.Type != "JWT") {
		return domain.Identity{}, ErrInvalidToken
	}
	key, err := v.key(ctx, header.KeyID)
	if err != nil {
		return domain.Identity{}, ErrInvalidToken
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return domain.Identity{}, ErrInvalidToken
	}

	var claims tokenClaims
	if err := decodePart(parts[1], &claims); err != nil {
		return domain.Identity{}, ErrInvalidToken
	}
	now := v.now().UTC()
	issuedAt := time.Unix(claims.IssuedAt, 0)
	if claims.Issuer != v.issuer || len(claims.Audience) != 1 || claims.Audience[0] != Audience ||
		!validIdentityClaim(claims.Subject) || !validIdentityClaim(claims.MembershipID) ||
		!validIdentityClaim(claims.InstallationID) || !validIdentityClaim(claims.SessionID) ||
		claims.ExpiresAt == 0 || !now.Before(time.Unix(claims.ExpiresAt, 0)) ||
		claims.IssuedAt == 0 || now.Sub(issuedAt) > maxTokenAge || issuedAt.Sub(now) > maxClockSkew ||
		claims.NotBefore != 0 && now.Before(time.Unix(claims.NotBefore, 0)) {
		return domain.Identity{}, ErrInvalidToken
	}
	if !claims.hasScope("checkouts:write") {
		return domain.Identity{}, ErrInsufficientScope
	}
	return domain.Identity{
		Subject: claims.Subject, MembershipID: claims.MembershipID,
		InstallationID: claims.InstallationID, SessionID: claims.SessionID,
	}, nil
}

type tokenClaims struct {
	Issuer         string   `json:"iss"`
	Subject        string   `json:"sub"`
	Audience       audience `json:"aud"`
	ExpiresAt      int64    `json:"exp"`
	IssuedAt       int64    `json:"iat"`
	NotBefore      int64    `json:"nbf"`
	MembershipID   string   `json:"membership_id"`
	InstallationID string   `json:"installation_id"`
	SessionID      string   `json:"session_id"`
	Scope          string   `json:"scope"`
	Scopes         []string `json:"scopes"`
}

func (c tokenClaims) hasScope(required string) bool {
	for _, scope := range append(strings.Fields(c.Scope), c.Scopes...) {
		if scope == required {
			return true
		}
	}
	return false
}

func validIdentityClaim(value string) bool {
	return value != "" && len(value) <= 255 &&
		!strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var values []string
	if err := json.Unmarshal(data, &values); err == nil {
		*a = values
		return nil
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*a = []string{value}
	return nil
}

func (v *JWKSVerifier) key(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	v.mu.RLock()
	key, found := v.keys[kid]
	fresh := v.now().Sub(v.fetchedAt) < v.cacheTTL
	v.mu.RUnlock()
	if found && fresh {
		return key, nil
	}
	if err := v.refresh(ctx, !found && fresh); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	key, found = v.keys[kid]
	if !found {
		return nil, errors.New("unknown signing key")
	}
	return key, nil
}

func (v *JWKSVerifier) refresh(ctx context.Context, forced bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	if forced {
		if now.Sub(v.lastForcedRefresh) < time.Second {
			return nil
		}
		v.lastForcedRefresh = now
	} else if now.Sub(v.fetchedAt) < v.cacheTTL {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("fetch JWKS: status %d", resp.StatusCode)
	}
	var document struct {
		Keys []struct {
			KeyID     string `json:"kid"`
			KeyType   string `json:"kty"`
			Curve     string `json:"crv"`
			Use       string `json:"use"`
			Algorithm string `json:"alg"`
			X         string `json:"x"`
		} `json:"keys"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 256<<10))
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}
	keys := make(map[string]ed25519.PublicKey)
	for _, jwk := range document.Keys {
		if jwk.KeyID == "" || jwk.KeyType != "OKP" || jwk.Curve != "Ed25519" || jwk.Algorithm != "EdDSA" ||
			(jwk.Use != "" && jwk.Use != "sig") {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		keys[jwk.KeyID] = ed25519.PublicKey(append([]byte(nil), raw...))
	}
	if len(keys) == 0 {
		return errors.New("JWKS contains no usable Ed25519 signing keys")
	}
	v.keys, v.fetchedAt = keys, now
	return nil
}

func decodePart(part string, target any) error {
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}
