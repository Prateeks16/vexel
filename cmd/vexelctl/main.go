// Command vexelctl is the operator CLI.
package main

import (
	"fmt"
	"os"

	"github.com/Prateeks16/vexel/internal/secret"
	"github.com/Prateeks16/vexel/internal/token"
)

const usage = `usage: vexelctl <command>

commands:
  token          generate a new edge/connector token and print its SHA-256 hash
  hash <token>   print the SHA-256 hash of an existing token
  keygen <file>  write a new ES256 signing key (PKCS#8 PEM) for the control plane
  enckey <file>  write a new AES-256 key for encrypting stored IdP secrets
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "vexelctl:", err)
		os.Exit(1)
	}
}

func run(cmd string, args []string) error {
	switch cmd {
	case "token":
		t := secret.Generate()
		fmt.Printf("token:        %s\ntoken_sha256: %s\n", t, secret.Hash(t))
		fmt.Fprintln(os.Stderr, "\nGive the token to the edge or connector; put only the hash in the control plane config.")
	case "hash":
		if len(args) != 1 {
			return fmt.Errorf("hash takes exactly one argument")
		}
		fmt.Println(secret.Hash(args[0]))
	case "keygen":
		if len(args) != 1 {
			return fmt.Errorf("keygen takes the output file path")
		}
		key, err := token.GenerateKey()
		if err != nil {
			return err
		}
		pemBytes, err := token.EncodeKey(key)
		if err != nil {
			return err
		}
		return writeNew(args[0], pemBytes)
	case "enckey":
		if len(args) != 1 {
			return fmt.Errorf("enckey takes the output file path")
		}
		return writeNew(args[0], []byte(secret.EncodeKey(secret.GenerateKey())))
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}

// writeNew writes a secret file, refusing to overwrite an existing one.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Println("wrote", path)
	return nil
}
