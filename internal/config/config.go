package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	embercrypto "github.com/emberaio/embercheckouts/internal/crypto"
)

type Config struct {
	Addr               string
	DatabaseURL        string
	PublicBaseURL      string
	EmberAuthURL       string
	EmberAuthJWKSURL   string
	Keyring            *embercrypto.Keyring
	TrustedProxies     []netip.Prefix
	CleanupInterval    time.Duration
	AllowLocalhostHTTP bool
	RateLimitPerMinute int
}

func Load() (Config, error) {
	keyring, err := embercrypto.ParseKey(
		env("ENCRYPTION_KEY_ID", "primary"), os.Getenv("ENCRYPTION_KEY"), os.Getenv("ENCRYPTION_KEYS"))
	if err != nil {
		return Config{}, fmt.Errorf("encryption config: %w", err)
	}
	proxies, err := parsePrefixes(os.Getenv("TRUSTED_PROXIES"))
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		Addr:             ":8080",
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		PublicBaseURL:    strings.TrimRight(env("PUBLIC_BASE_URL", "http://localhost:8080"), "/"),
		EmberAuthURL:     strings.TrimRight(env("EMBER_AUTH_URL", "http://localhost:8081"), "/"),
		EmberAuthJWKSURL: strings.TrimSpace(os.Getenv("EMBER_AUTH_JWKS_URL")),
		Keyring:          keyring,
		TrustedProxies:   proxies,
		CleanupInterval:  time.Minute,
		AllowLocalhostHTTP: strings.HasPrefix(env("PUBLIC_BASE_URL", "http://localhost:8080"), "http://localhost") ||
			strings.HasPrefix(env("PUBLIC_BASE_URL", "http://localhost:8080"), "http://127.0.0.1"),
		RateLimitPerMinute: 120,
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	return cfg, nil
}

// parsePrefixes accepts a comma-separated list of CIDRs or bare IPs.
func parsePrefixes(value string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !strings.Contains(item, "/") {
			addr, err := netip.ParseAddr(item)
			if err != nil {
				return nil, fmt.Errorf("TRUSTED_PROXIES entry %q is not an IP or CIDR", item)
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES entry %q is not an IP or CIDR", item)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
