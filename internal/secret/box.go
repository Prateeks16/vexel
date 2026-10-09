package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

const boxVersion = "v1."

// Box encrypts small secrets (such as OIDC client secrets) before they are
// written to the database, using AES-256-GCM. The additional data binds a
// ciphertext to its owner, so a sealed value copied into another tenant's row
// will not open.
type Box struct {
	aead cipher.AEAD
}

func NewBox(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("secret: encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

func (b *Box) Seal(plaintext, aad string) string {
	nonce := make([]byte, b.aead.NonceSize())
	rand.Read(nonce)
	out := b.aead.Seal(nonce, nonce, []byte(plaintext), []byte(aad))
	return boxVersion + base64.RawURLEncoding.EncodeToString(out)
}

func (b *Box) Open(sealed, aad string) (string, error) {
	enc, ok := strings.CutPrefix(sealed, boxVersion)
	if !ok {
		return "", errors.New("secret: unknown ciphertext version")
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || len(raw) < b.aead.NonceSize() {
		return "", errors.New("secret: malformed ciphertext")
	}
	n := b.aead.NonceSize()
	pt, err := b.aead.Open(nil, raw[:n], raw[n:], []byte(aad))
	if err != nil {
		return "", errors.New("secret: decryption failed")
	}
	return string(pt), nil
}

func GenerateKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

func EncodeKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key) + "\n"
}

// LoadKey reads a base64-encoded 32-byte key written by EncodeKey.
func LoadKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("encryption key %s: %w", path, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key %s: must decode to 32 bytes", path)
	}
	return key, nil
}
