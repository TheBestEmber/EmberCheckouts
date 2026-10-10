package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const Version = 1

type Envelope struct {
	Version    int
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
}

type Keyring struct {
	active string
	keys   map[string][]byte
}

func NewKeyring(active string, keys map[string][]byte) (*Keyring, error) {
	if active == "" {
		return nil, errors.New("active encryption key ID is required")
	}
	owned := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if id == "" || len(key) != 32 {
			return nil, fmt.Errorf("encryption key %q must be 32 bytes", id)
		}
		owned[id] = append([]byte(nil), key...)
	}
	if _, ok := owned[active]; !ok {
		return nil, errors.New("active encryption key is not in keyring")
	}
	return &Keyring{active: active, keys: owned}, nil
}

func ParseKeyring(active, encoded string) (*Keyring, error) {
	keys := make(map[string][]byte)
	for _, entry := range strings.Split(encoded, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, value, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, errors.New("ENCRYPTION_KEYS entries must be id:base64")
		}
		key, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("decode encryption key %q: %w", id, err)
		}
		if _, exists := keys[id]; exists {
			return nil, fmt.Errorf("encryption key ID %q is configured twice", id)
		}
		keys[id] = key
	}
	return NewKeyring(active, keys)
}

// ParseKey makes encoded the active key; previous "id:base64" entries only decrypt.
func ParseKey(activeID, encoded, previous string) (*Keyring, error) {
	return ParseKeyring(activeID, activeID+":"+strings.TrimSpace(encoded)+","+previous)
}

func (k *Keyring) Ready() bool {
	_, ok := k.keys[k.active]
	return ok
}

func (k *Keyring) Encrypt(userID, cartID string, plaintext []byte) (Envelope, error) {
	block, err := aes.NewCipher(k.keys[k.active])
	if err != nil {
		return Envelope{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, fmt.Errorf("generate nonce: %w", err)
	}
	return Envelope{
		Version: Version, KeyID: k.active, Nonce: nonce,
		Ciphertext: gcm.Seal(nil, nonce, plaintext, aad(Version, userID, cartID)),
	}, nil
}

func (k *Keyring) Decrypt(userID, cartID string, envelope Envelope) ([]byte, error) {
	if envelope.Version != Version {
		return nil, errors.New("unsupported envelope version")
	}
	key, ok := k.keys[envelope.KeyID]
	if !ok {
		return nil, errors.New("encryption key is unavailable")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(envelope.Nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid envelope nonce")
	}
	plaintext, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, aad(envelope.Version, userID, cartID))
	if err != nil {
		return nil, errors.New("decrypt envelope: authentication failed")
	}
	return plaintext, nil
}

func aad(version int, userID, cartID string) []byte {
	return []byte(fmt.Sprintf("ember-checkout:v%d:user:%s:cart:%s", version, userID, cartID))
}
