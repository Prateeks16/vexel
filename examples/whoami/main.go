// Command whoami is a demo upstream app. It verifies the Vexel assertion on
// every request and echoes back who the user is, the way a real app (such as
// a CRM) should consume Vexel identity.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/Prateeks16/vexel/internal/cli"
	"github.com/Prateeks16/vexel/pkg/jwks"
	"github.com/Prateeks16/vexel/pkg/vexelauth"
)

func main() {
	listen := flag.String("listen", cli.Env("WHOAMI_LISTEN", ":9000"), "listen address")
	jwksURL := flag.String("jwks", cli.Env("VEXEL_JWKS_URL", "http://localhost:8081/.well-known/jwks.json"), "control plane JWKS URL")
	issuer := flag.String("issuer", cli.Env("VEXEL_ISSUER", "http://localhost:8081"), "expected token issuer (control plane public URL)")
	audience := flag.String("audience", cli.Env("VEXEL_AUDIENCE", "whoami.acme.localhost"), "this app's hostname in Vexel")
	flag.Parse()

	v := &vexelauth.Verifier{Keys: jwks.NewCache(*jwksURL, nil), Issuer: *issuer}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           v.Middleware(*audience, http.HandlerFunc(whoami)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("whoami listening on %s", *listen)
	log.Fatal(srv.ListenAndServe())
}

func whoami(w http.ResponseWriter, r *http.Request) {
	c, _ := vexelauth.FromContext(r.Context())
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "Hello %s\ngroups: %v\nsession expires: %s\n\n", c.Email, c.Groups, c.ExpiresAt.Time.Format(time.RFC3339))
	fmt.Fprintf(w, "%s %s\n", r.Method, r.URL.RequestURI())
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := r.Header.Get(k)
		if k == vexelauth.AssertionHeader && len(v) > 24 {
			v = v[:24] + "..."
		}
		fmt.Fprintf(w, "%s: %s\n", k, v)
	}
}
