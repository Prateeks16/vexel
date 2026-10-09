package secret

import "testing"

func TestBox(t *testing.T) {
	b, err := NewBox(GenerateKey())
	if err != nil {
		t.Fatal(err)
	}
	sealed := b.Seal("client-secret", "tenant-a")
	if got, err := b.Open(sealed, "tenant-a"); err != nil || got != "client-secret" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if _, err := b.Open(sealed, "tenant-b"); err == nil {
		t.Fatal("ciphertext must not open under another tenant")
	}
	if sealed == b.Seal("client-secret", "tenant-a") {
		t.Fatal("sealing must be randomised")
	}
	other, _ := NewBox(GenerateKey())
	if _, err := other.Open(sealed, "tenant-a"); err == nil {
		t.Fatal("ciphertext must not open under another key")
	}
	if _, err := NewBox([]byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}
