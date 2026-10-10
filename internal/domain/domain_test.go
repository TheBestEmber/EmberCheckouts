package domain

import (
	"strings"
	"testing"
	"time"
)

func validHandoff(now time.Time) Handoff {
	return Handoff{
		Module: "skiddle", Site: "skiddle", Title: "Final Release",
		TargetURL: "https://www.skiddle.com/basket/default.php",
		Cookies: []Cookie{{
			Name: "PHPSESSID", Value: "secret", Domain: "www.skiddle.com", Path: "/",
			Secure: true, HTTPOnly: true, SameSite: "unspecified", HostOnly: true,
		}},
		Storage: Storage{Local: []StorageGroup{{
			Origin: "https://www.skiddle.com",
			Items:  []StorageItem{{Name: "cart", Value: "opaque"}},
		}}},
		Display:         Display{Quantity: 2, Price: "109.12", Currency: "GBP"},
		ProducerVersion: "1.2.3",
	}
}

func TestValidateHandoff(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*Handoff)
		want   string
	}{
		{name: "valid"},
		{name: "insecure target", mutate: func(h *Handoff) { h.TargetURL = "http://example.com" }, want: "https"},
		{name: "bad module", mutate: func(h *Handoff) { h.Module = "Skiddle" }, want: "module"},
		{name: "missing cookie domain", mutate: func(h *Handoff) { h.Cookies[0].Domain = "" }, want: "domain"},
		{name: "bad same site", mutate: func(h *Handoff) { h.Cookies[0].SameSite = "None" }, want: "sameSite"},
		{name: "storage path", mutate: func(h *Handoff) { h.Storage.Local[0].Origin += "/path" }, want: "exact"},
		{name: "bad proxy", mutate: func(h *Handoff) { value := "socks5://localhost:9000"; h.ProxyURL = &value }, want: "proxyUrl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handoff := validHandoff(now)
			if tt.mutate != nil {
				tt.mutate(&handoff)
			}
			err := ValidateHandoff(&handoff, ValidationOptions{Now: now})
			if tt.want == "" && err != nil {
				t.Fatal(err)
			}
			if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestLocalhostHTTPRequiresOptIn(t *testing.T) {
	now := time.Now()
	handoff := validHandoff(now)
	handoff.TargetURL = "http://localhost:8081/cart"
	handoff.Cookies = nil
	handoff.Storage.Local = nil
	if err := ValidateHandoff(&handoff, ValidationOptions{
		Now: now, AllowLocalhostHTTP: true,
	}); err != nil {
		t.Fatal(err)
	}
	handoff.TargetURL = "http://192.0.2.1/cart"
	if err := ValidateHandoff(&handoff, ValidationOptions{
		Now: now, AllowLocalhostHTTP: true,
	}); err == nil {
		t.Fatal("non-loopback HTTP target was accepted")
	}
}

func TestPermissionOriginsDerived(t *testing.T) {
	handoff := validHandoff(time.Now())
	handoff.Cookies[0].Domain = ".skiddle.com"
	handoff.Cookies[0].HostOnly = false
	origins := PermissionOrigins(handoff)
	joined := strings.Join(origins, ",")
	for _, expected := range []string{"https://*.skiddle.com/*", "https://www.skiddle.com/*"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("%q missing from %v", expected, origins)
		}
	}
}

func FuzzValidateHandoff(f *testing.F) {
	f.Add("site", "title", "https://example.com/cart")
	f.Fuzz(func(t *testing.T, site, title, target string) {
		now := time.Now()
		handoff := validHandoff(now)
		handoff.Site, handoff.Title, handoff.TargetURL = site, title, target
		_ = ValidateHandoff(&handoff, ValidationOptions{Now: now})
	})
}
