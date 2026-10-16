// Package softauthn is a software WebAuthn platform authenticator for tests.
// It answers the same JSON options a browser receives and produces the same
// JSON a browser would send back, so server code runs exactly as it does with
// a real TPM-backed authenticator.
package softauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified
	flagBE = 0x08 // backup eligible (syncable passkey)
	flagAT = 0x40 // attested credential data included
)

type Authenticator struct {
	Origin string // e.g. http://localhost:8081
	RPID   string // e.g. localhost

	// BackupEligible makes the credential look like a synced passkey.
	BackupEligible bool
	// AllowAny answers assertions even when not in allowCredentials, to test
	// that the server rejects unknown credentials itself.
	AllowAny bool

	key     *ecdsa.PrivateKey
	credID  []byte
	Counter uint32
}

func New(origin, rpID string) *Authenticator {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 32)
	rand.Read(id)
	return &Authenticator{Origin: origin, RPID: rpID, key: key, credID: id}
}

var b64 = base64.RawURLEncoding

func (a *Authenticator) CredentialID() string { return b64.EncodeToString(a.credID) }

type options struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		RPID             string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

func (a *Authenticator) flags() byte {
	f := byte(flagUP | flagUV)
	if a.BackupEligible {
		f |= flagBE
	}
	return f
}

func (a *Authenticator) clientData(typ, challenge string) []byte {
	cd, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return cd
}

func (a *Authenticator) authData(flags byte, attested []byte) []byte {
	rp := sha256.Sum256([]byte(a.RPID))
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.Counter)
	return append(out, attested...)
}

// Register answers navigator.credentials.create() options (JSON).
func (a *Authenticator) Register(optionsJSON []byte) ([]byte, error) {
	var o options
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return nil, err
	}
	if o.PublicKey.RP.ID != "" && o.PublicKey.RP.ID != a.RPID {
		return nil, fmt.Errorf("softauthn: rp id %q, want %q", o.PublicKey.RP.ID, a.RPID)
	}
	raw, err := a.key.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	enc, _ := cbor.CoreDetEncOptions().EncMode()
	cose, err := enc.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:65]})
	if err != nil {
		return nil, err
	}
	attested := make([]byte, 16) // AAGUID: zero for "none" attestation
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(a.credID)))
	attested = append(attested, a.credID...)
	attested = append(attested, cose...)

	attObj, err := enc.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(a.flags()|flagAT, attested)})
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": a.CredentialID(), "rawId": a.CredentialID(), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", o.PublicKey.Challenge)),
			"attestationObject": b64.EncodeToString(attObj),
			"transports":        []string{"internal"},
		},
	})
}

// Assert answers navigator.credentials.get() options (JSON).
func (a *Authenticator) Assert(optionsJSON []byte) ([]byte, error) {
	var o options
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return nil, err
	}
	allowed := a.AllowAny
	for _, c := range o.PublicKey.AllowCredentials {
		allowed = allowed || c.ID == a.CredentialID()
	}
	if !allowed {
		return nil, errors.New("softauthn: credential not in allowCredentials")
	}
	a.Counter++
	ad := a.authData(a.flags(), nil)
	cd := a.clientData("webauthn.get", o.PublicKey.Challenge)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": a.CredentialID(), "rawId": a.CredentialID(), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(ad),
			"signature":         b64.EncodeToString(sig),
		},
	})
}
