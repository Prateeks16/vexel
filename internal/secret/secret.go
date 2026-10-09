// Package secret generates and hashes the opaque bearer tokens used by edges
// and connectors. Only hashes are stored in configuration.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

const prefix = "vx_"

func Generate() string {
	return prefix + rand.Text()
}

func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ValidHash reports whether s looks like a value produced by Hash.
func ValidHash(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
