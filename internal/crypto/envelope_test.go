package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestEnvelopeRoundTripAndRotation(t *testing.T) {
	oldKey := bytes.Repeat([]byte{1}, 32)
	newKey := bytes.Repeat([]byte{2}, 32)
	oldRing, err := NewKeyring("old", map[string][]byte{"old": oldKey})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := oldRing.Encrypt("user-1", "cart-1", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewKeyring("new", map[string][]byte{"old": oldKey, "new": newKey})
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := rotated.Decrypt("user-1", "cart-1", envelope)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "secret" {
		t.Fatalf("got %q", plaintext)
	}
	next, err := rotated.Encrypt("user-1", "cart-2", []byte("next"))
	if err != nil {
		t.Fatal(err)
	}
	if next.KeyID != "new" {
		t.Fatalf("new envelope used key %q", next.KeyID)
	}
}

func TestEnvelopeRejectsTamperingAndWrongAAD(t *testing.T) {
	ring, err := NewKeyring("v1", map[string][]byte{"v1": bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := ring.Encrypt("user-1", "cart-1", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Decrypt("user-2", "cart-1", envelope); err == nil {
		t.Fatal("wrong user AAD was accepted")
	}
	envelope.Ciphertext[0] ^= 0xff
	if _, err := ring.Decrypt("user-1", "cart-1", envelope); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestParseKeyDecryptsWithPreviousKeys(t *testing.T) {
	oldKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	newKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	before, err := ParseKey("primary", oldKey, "")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := before.Encrypt("user-1", "cart-1", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := ParseKey("v2", newKey, " primary:"+oldKey+" ")
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, err := after.Decrypt("user-1", "cart-1", envelope); err != nil || string(plaintext) != "secret" {
		t.Fatalf("previous key did not decrypt: %q %v", plaintext, err)
	}
	if next, _ := after.Encrypt("user-1", "cart-2", []byte("next")); next.KeyID != "v2" {
		t.Fatalf("new envelopes used key %q", next.KeyID)
	}
	if _, err := ParseKey("primary", newKey, "primary:"+oldKey); err == nil {
		t.Fatal("duplicate key ID was accepted")
	}
}

func TestKeyringValidation(t *testing.T) {
	if _, err := NewKeyring("missing", map[string][]byte{"v1": make([]byte, 32)}); err == nil {
		t.Fatal("missing active key was accepted")
	}
	if _, err := NewKeyring("v1", map[string][]byte{"v1": make([]byte, 31)}); err == nil {
		t.Fatal("short AES key was accepted")
	}
}
