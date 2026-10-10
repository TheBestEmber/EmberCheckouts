package domain

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var pricePattern = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,9})(?:\.[0-9]{1,4})?$`)

const (
	MaxCookies       = 300
	MaxStorageGroups = 50
	MaxStorageItems  = 500
	CheckoutTTL      = 10 * time.Minute
)

type Handoff struct {
	Module          string   `json:"module"`
	Site            string   `json:"site"`
	Title           string   `json:"title"`
	TargetURL       string   `json:"targetUrl"`
	ProxyURL        *string  `json:"proxyUrl,omitempty"`
	Cookies         []Cookie `json:"cookies"`
	Storage         Storage  `json:"storage"`
	Display         Display  `json:"display"`
	ProducerVersion string   `json:"producerVersion"`
}

type Cookie struct {
	Name         string         `json:"name"`
	Value        string         `json:"value"`
	Domain       string         `json:"domain"`
	Path         string         `json:"path"`
	Secure       bool           `json:"secure"`
	HTTPOnly     bool           `json:"httpOnly"`
	SameSite     string         `json:"sameSite"`
	ExpiresAt    *time.Time     `json:"expiresAt"`
	HostOnly     bool           `json:"hostOnly"`
	PartitionKey map[string]any `json:"partitionKey"`
}

type Storage struct {
	Local   []StorageGroup `json:"local"`
	Session []StorageGroup `json:"session"`
}

type StorageGroup struct {
	Origin string        `json:"origin"`
	Items  []StorageItem `json:"items"`
}

type StorageItem struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Display struct {
	Quantity int    `json:"quantity"`
	Price    string `json:"price"`
	Currency string `json:"currency"`
}

type CheckoutMetadata struct {
	ID              string    `json:"id"`
	Module          string    `json:"module"`
	Site            string    `json:"site"`
	Title           string    `json:"title"`
	Quantity        int       `json:"quantity"`
	Price           string    `json:"price"`
	Currency        string    `json:"currency"`
	ProducerVersion string    `json:"producerVersion"`
	TargetHost      string    `json:"targetHost"`
	ProxyUsed       bool      `json:"proxyUsed"`
	RetrievalCount  int64     `json:"retrievalCount"`
	CreatedAt       time.Time `json:"createdAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

type Identity struct {
	Subject        string
	MembershipID   string
	InstallationID string
	SessionID      string
}

type ValidationOptions struct {
	Now                time.Time
	AllowLocalhostHTTP bool
}

func ValidateHandoff(h *Handoff, opts ValidationOptions) error {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if err := slug("module", h.Module); err != nil {
		return err
	}
	if err := slug("site", h.Site); err != nil {
		return err
	}
	if err := bounded("title", strings.TrimSpace(h.Title), 1, 200); err != nil {
		return err
	}
	if strings.ContainsFunc(h.Title, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return errors.New("title must not contain control characters")
	}
	if len(h.TargetURL) > 4096 {
		return errors.New("targetUrl is too long")
	}
	_, err := validateWebURL(h.TargetURL, opts.AllowLocalhostHTTP)
	if err != nil {
		return fmt.Errorf("targetUrl %w", err)
	}
	if h.ProxyURL != nil {
		u, err := url.Parse(*h.ProxyURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("proxyUrl must use http or https and include a host")
		}
		if len(*h.ProxyURL) > 2048 {
			return errors.New("proxyUrl is too long")
		}
	}
	if len(h.Cookies) > MaxCookies {
		return fmt.Errorf("cookies must contain at most %d entries", MaxCookies)
	}
	for i := range h.Cookies {
		if err := validateCookie(&h.Cookies[i], opts.Now); err != nil {
			return fmt.Errorf("cookies[%d]: %w", i, err)
		}
	}
	if err := validateStorage("storage.local", h.Storage.Local, opts.AllowLocalhostHTTP); err != nil {
		return err
	}
	if err := validateStorage("storage.session", h.Storage.Session, opts.AllowLocalhostHTTP); err != nil {
		return err
	}
	if h.Display.Quantity < 0 || h.Display.Quantity > 100000 {
		return errors.New("display.quantity must be between 0 and 100000")
	}
	if err := bounded("display.price", h.Display.Price, 0, 32); err != nil {
		return err
	}
	if h.Display.Price != "" && !pricePattern.MatchString(h.Display.Price) {
		return errors.New("display.price must be a non-negative decimal amount")
	}
	if len(h.Display.Currency) != 0 && (len(h.Display.Currency) != 3 || strings.ToUpper(h.Display.Currency) != h.Display.Currency) {
		return errors.New("display.currency must be a three-letter uppercase code")
	}
	if err := bounded("producerVersion", strings.TrimSpace(h.ProducerVersion), 1, 64); err != nil {
		return err
	}
	if strings.ContainsFunc(h.ProducerVersion, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return errors.New("producerVersion must not contain control characters")
	}
	return nil
}

func MetadataFor(id string, h Handoff, createdAt time.Time) CheckoutMetadata {
	target, _ := url.Parse(h.TargetURL)
	return CheckoutMetadata{
		ID: id, Module: h.Module, Site: h.Site, Title: strings.TrimSpace(h.Title),
		Quantity: h.Display.Quantity, Price: h.Display.Price, Currency: h.Display.Currency,
		ProducerVersion: strings.TrimSpace(h.ProducerVersion), TargetHost: target.Hostname(),
		ProxyUsed: h.ProxyURL != nil, CreatedAt: createdAt, ExpiresAt: createdAt.Add(CheckoutTTL),
	}
}

func slug(name, value string) error {
	if err := bounded(name, strings.TrimSpace(value), 1, 64); err != nil {
		return err
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return fmt.Errorf("%s must contain only lowercase letters, numbers, hyphens, and underscores", name)
		}
	}
	return nil
}

func PermissionOrigins(h Handoff) []string {
	origins := make(map[string]struct{})
	addURL := func(raw string) {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			origins[u.Scheme+"://"+u.Host+"/*"] = struct{}{}
		}
	}
	addURL(h.TargetURL)
	for _, groups := range [][]StorageGroup{h.Storage.Local, h.Storage.Session} {
		for _, group := range groups {
			addURL(group.Origin)
		}
	}
	for _, cookie := range h.Cookies {
		domain := strings.TrimPrefix(strings.ToLower(cookie.Domain), ".")
		if domain == "" {
			continue
		}
		host := domain
		if !cookie.HostOnly {
			host = "*." + domain
		}
		scheme := "http"
		if cookie.Secure {
			scheme = "https"
		}
		origins[scheme+"://"+host+"/*"] = struct{}{}
	}
	result := make([]string, 0, len(origins))
	for origin := range origins {
		result = append(result, origin)
	}
	sort.Strings(result)
	return result
}

func validateCookie(c *Cookie, now time.Time) error {
	if err := bounded("name", c.Name, 1, 256); err != nil {
		return err
	}
	if !validCookieName(c.Name) {
		return errors.New("name contains invalid characters")
	}
	if len(c.Value) > 8192 {
		return errors.New("value is too long")
	}
	domain := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
	if domain == "" {
		return errors.New("domain is required")
	}
	if len(domain) > 253 || net.ParseIP(domain) == nil && !validHostname(domain) {
		return errors.New("domain is invalid")
	}
	if c.Path == "" || c.Path[0] != '/' || len(c.Path) > 2048 {
		return errors.New("path must begin with / and be at most 2048 bytes")
	}
	switch c.SameSite {
	case "unspecified", "no_restriction", "lax", "strict":
	default:
		return errors.New("sameSite is invalid")
	}
	if c.SameSite == "no_restriction" && !c.Secure {
		return errors.New("SameSite=None cookies must be secure")
	}
	if c.ExpiresAt != nil && !c.ExpiresAt.After(now) {
		return errors.New("expiresAt must be in the future")
	}
	return nil
}

func validateStorage(field string, groups []StorageGroup, allowLocalHTTP bool) error {
	if len(groups) > MaxStorageGroups {
		return fmt.Errorf("%s must contain at most %d origins", field, MaxStorageGroups)
	}
	total := 0
	for i, group := range groups {
		u, err := validateWebURL(group.Origin, allowLocalHTTP)
		if err != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("%s[%d].origin must be an exact http(s) origin", field, i)
		}
		total += len(group.Items)
		for j, item := range group.Items {
			if err := bounded(fmt.Sprintf("%s[%d].items[%d].name", field, i, j), item.Name, 1, 1024); err != nil {
				return err
			}
			if len(item.Value) > 262144 {
				return fmt.Errorf("%s[%d].items[%d].value is too long", field, i, j)
			}
		}
	}
	if total > MaxStorageItems {
		return fmt.Errorf("%s must contain at most %d items", field, MaxStorageItems)
	}
	return nil
}

func validateWebURL(raw string, allowLocalHTTP bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return nil, errors.New("must be an absolute URL without credentials")
	}
	if u.Scheme != "https" {
		host := strings.ToLower(u.Hostname())
		local := host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
		if u.Scheme != "http" || !allowLocalHTTP || !local {
			return nil, errors.New("must use https")
		}
	}
	return u, nil
}

func bounded(name, value string, min, max int) error {
	n := len(value)
	if n < min || n > max {
		return fmt.Errorf("%s must be between %d and %d bytes", name, min, max)
	}
	return nil
}

func validCookieName(name string) bool {
	for _, r := range name {
		if r < 0x21 || r > 0x7e || strings.ContainsRune("()<>@,;:\\\"/[]?={} \t", r) {
			return false
		}
	}
	return true
}

func validHostname(host string) bool {
	if len(host) == 0 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
