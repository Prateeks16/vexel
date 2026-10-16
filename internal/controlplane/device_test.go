package controlplane

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Prateeks16/vexel/internal/testutil/softauthn"
)

const (
	crmRD  = "http://crm.acme.localhost:8080/clients/42"
	rpID   = "auth.localhost" // host of testConfig's public_url
	crmApp = "crm.acme.localhost"
)

func newAuthenticator() *softauthn.Authenticator { return softauthn.New(publicOrigin, rpID) }

// deviceBrowser stops following redirects once they leave the control plane,
// i.e. at the hand-off to the edge.
func deviceBrowser(t *testing.T, s *testServer) *browser {
	b := newBrowser(t, s)
	host := strings.TrimPrefix(b.srv.URL, "http://")
	b.c.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host != host {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return b
}

func (b *browser) postJSON(path string, body []byte) (int, []byte) {
	b.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, b.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", publicOrigin)
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// issueEnrollment creates an enrollment link as an admin and returns its code.
func issueEnrollment(t *testing.T, s *testServer, email, name string) string {
	t.Helper()
	out, _ := apiClient{t: t, s: s, token: testAPIToken}.expect(http.StatusCreated, "POST", "/api/v1/device-enrollments", map[string]string{"email": email, "name": name})
	u, err := url.Parse(out["url"].(string))
	if err != nil || u.Path != "/device/enroll" {
		t.Fatalf("enrollment url = %v", out["url"])
	}
	return u.Query().Get("code")
}

// enrollDevice runs the enrollment ceremony on a fresh browser.
func enrollDevice(t *testing.T, s *testServer, auth *softauthn.Authenticator, code string) (int, []byte) {
	t.Helper()
	b := deviceBrowser(t, s)
	resp, err := b.c.Get(b.srv.URL + "/device/enroll?code=" + url.QueryEscape(code))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	code1, opts := b.postJSON("/device/enroll/begin", mustJSON(map[string]string{"code": code}))
	if code1 != http.StatusOK {
		return code1, opts
	}
	cred, err := auth.Register(opts)
	if err != nil {
		t.Fatal(err)
	}
	return b.postJSON("/device/enroll/finish", cred)
}

// requireDevice changes the seeded CRM app to need a trusted device.
func requireDevice(t *testing.T, s *testServer) {
	t.Helper()
	api := apiClient{t: t, s: s, token: testAPIToken}
	_, apps := api.expect(http.StatusOK, "GET", "/api/v1/apps", nil)
	app := apps[0].(map[string]any)
	id := app["id"].(string)
	app["policies"] = []map[string]any{{"name": "staff on company devices", "action": "allow",
		"include": []map[string]any{{"email_domain": "example.com"}}, "require": []map[string]any{{"trusted_device": true}}}}
	for _, k := range []string{"id", "created_at", "updated_at"} {
		delete(app, k)
	}
	api.expect(http.StatusOK, "PUT", "/api/v1/apps/"+id, app)
}

// signInToApp signs in through dev login and, if asked, completes the device
// check with auth. It returns the app token handed to the edge ("" if none).
func signInToApp(t *testing.T, s *testServer, b *browser, email string, auth *softauthn.Authenticator) (string, string) {
	t.Helper()
	appID := s.appID(t, crmApp)
	resp, err := b.c.PostForm(b.srv.URL+"/auth/dev-login", url.Values{"app": {appID}, "rd": {crmRD}, "email": {email}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Request.URL.Path == "/auth/device" {
		if auth == nil {
			return "", "device-check"
		}
		code, opts := b.postJSON("/auth/device/begin", mustJSON(map[string]string{"app": appID, "rd": crmRD}))
		if code != http.StatusOK {
			t.Fatalf("device begin: %d %s", code, opts)
		}
		assertion, err := auth.Assert(opts)
		if err != nil {
			t.Fatal(err)
		}
		code, out := b.postJSON("/auth/device/finish", assertion)
		if code != http.StatusOK {
			return "", "finish:" + string(out)
		}
		var next struct{ Next string }
		json.Unmarshal(out, &next)
		if resp, err = b.c.Get(b.srv.URL + next.Next); err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Path != "/.vexel/authorized" {
		t.Fatalf("expected hand-off to the edge, got %d %s", resp.StatusCode, loc)
	}
	return loc.Query().Get("token"), ""
}

func deviceClaim(t *testing.T, s *testServer, token string) string {
	t.Helper()
	claims, err := s.verifier.Verify(t.Context(), token, crmApp)
	if err != nil {
		t.Fatal(err)
	}
	return claims.DeviceID
}

func TestDeviceEnrollmentAndSignIn(t *testing.T) {
	s := newTestServer(t)
	api := apiClient{t: t, s: s, token: testAPIToken}
	laptop := newAuthenticator()

	code := issueEnrollment(t, s, "Alice@Example.com", "Alice's laptop")
	if status, out := enrollDevice(t, s, laptop, code); status != http.StatusOK {
		t.Fatalf("enroll: %d %s", status, out)
	}
	_, devs := api.expect(http.StatusOK, "GET", "/api/v1/devices", nil)
	if len(devs) != 1 {
		t.Fatalf("devices = %v", devs)
	}
	dev := devs[0].(map[string]any)
	if dev["user"] != "alice@example.com" || dev["name"] != "Alice's laptop" {
		t.Fatalf("device = %v", dev)
	}
	if _, pending := api.expect(http.StatusOK, "GET", "/api/v1/device-enrollments", nil); len(pending) != 0 {
		t.Fatalf("used enrollment still pending: %v", pending)
	}
	// Links are single use.
	if status, _ := enrollDevice(t, s, newAuthenticator(), code); status != http.StatusBadRequest {
		t.Fatalf("reused code: %d", status)
	}

	requireDevice(t, s)
	b := deviceBrowser(t, s)
	token, _ := signInToApp(t, s, b, "alice@example.com", laptop)
	if got := deviceClaim(t, s, token); got != dev["id"] {
		t.Fatalf("token device = %q, want %v", got, dev["id"])
	}
	// The proven device is part of the session: single sign-on (no new
	// primary sign-in) needs no second prompt.
	resp, err := b.c.Get(b.srv.URL + "/auth/login?" + url.Values{"app": {s.appID(t, crmApp)}, "rd": {crmRD}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Path != "/.vexel/authorized" || deviceClaim(t, s, loc.Query().Get("token")) != dev["id"] {
		t.Fatalf("SSO lost the device: %d %s", resp.StatusCode, loc)
	}
	// A fresh primary sign-in must prove the device again.
	if _, failure := signInToApp(t, s, b, "alice@example.com", nil); failure != "device-check" {
		t.Fatalf("fresh sign-in skipped the device check (%q)", failure)
	}

	_, audit := api.expect(http.StatusOK, "GET", "/api/v1/audit?limit=5", nil)
	found := false
	for _, a := range audit {
		found = found || a.(map[string]any)["action"] == "device.enroll"
	}
	if !found {
		t.Fatalf("enrollment not audited: %v", audit)
	}
}

func TestSyncedPasskeyRejected(t *testing.T) {
	s := newTestServer(t)
	synced := newAuthenticator()
	synced.BackupEligible = true
	code := issueEnrollment(t, s, "alice@example.com", "Phone passkey")
	status, out := enrollDevice(t, s, synced, code)
	if status != http.StatusBadRequest || !strings.Contains(string(out), "sync") {
		t.Fatalf("synced passkey: %d %s", status, out)
	}
	// The link stays usable for a proper device credential.
	if status, out := enrollDevice(t, s, newAuthenticator(), code); status != http.StatusOK {
		t.Fatalf("retry with platform credential: %d %s", status, out)
	}
}

func TestDeviceCeremoniesRefuseCrossSite(t *testing.T) {
	s := newTestServer(t)
	code := issueEnrollment(t, s, "alice@example.com", "Laptop")
	b := deviceBrowser(t, s)
	body := mustJSON(map[string]string{"code": code})

	req, _ := http.NewRequest(http.MethodPost, b.srv.URL+"/device/enroll/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	resp, _ := b.c.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin begin: %d", resp.StatusCode)
	}
	// A plain form post (what a cross-site page can send) is refused too.
	resp, _ = b.c.PostForm(b.srv.URL+"/device/enroll/begin", url.Values{"code": {code}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("form post begin: %d", resp.StatusCode)
	}
	// Finishing without a ceremony cookie fails.
	if status, _ := deviceBrowser(t, s).postJSON("/device/enroll/finish", []byte(`{}`)); status != http.StatusBadRequest {
		t.Fatalf("finish without begin: %d", status)
	}
}

func TestDeviceCheckRejectsWrongAndClonedCredentials(t *testing.T) {
	s := newTestServer(t)
	laptop := newAuthenticator()
	enrollDevice(t, s, laptop, issueEnrollment(t, s, "alice@example.com", "Laptop"))
	requireDevice(t, s)

	// A credential that was never enrolled.
	stranger := newAuthenticator()
	stranger.AllowAny = true
	if _, failure := signInToApp(t, s, deviceBrowser(t, s), "alice@example.com", stranger); !strings.HasPrefix(failure, "finish:") {
		t.Fatalf("unenrolled credential accepted (%q)", failure)
	}

	// A replayed signature counter suggests a cloned key.
	if token, _ := signInToApp(t, s, deviceBrowser(t, s), "alice@example.com", laptop); token == "" {
		t.Fatal("genuine device rejected")
	}
	laptop.Counter = 0
	if _, failure := signInToApp(t, s, deviceBrowser(t, s), "alice@example.com", laptop); !strings.Contains(failure, "cloned") {
		t.Fatalf("cloned credential accepted (%q)", failure)
	}
}

func TestRevokedDeviceDropsFromSession(t *testing.T) {
	s := newTestServer(t)
	api := apiClient{t: t, s: s, token: testAPIToken}
	laptop := newAuthenticator()
	enrollDevice(t, s, laptop, issueEnrollment(t, s, "alice@example.com", "Laptop"))
	requireDevice(t, s)
	b := deviceBrowser(t, s)
	token, _ := signInToApp(t, s, b, "alice@example.com", laptop)
	if deviceClaim(t, s, token) == "" {
		t.Fatal("no device claim")
	}

	_, devs := api.expect(http.StatusOK, "GET", "/api/v1/devices", nil)
	api.expect(http.StatusOK, "POST", "/api/v1/devices/"+devs[0].(map[string]any)["id"].(string)+"/revoke", nil)

	// Same browser session: the revoked device must not be vouched for
	// again. With no other device there is nothing to prove, so the token
	// carries no device and the edge's policy will refuse it.
	token, _ = signInToApp(t, s, b, "alice@example.com", nil)
	if got := deviceClaim(t, s, token); got != "" {
		t.Fatalf("revoked device still in token: %q", got)
	}
}

func TestNoDeviceNoPrompt(t *testing.T) {
	s := newTestServer(t)
	requireDevice(t, s)
	// Bob has no enrolled device: sign-in completes without a device check
	// (the edge then explains the requirement) rather than dead-ending.
	token, failure := signInToApp(t, s, deviceBrowser(t, s), "bob@example.com", nil)
	if token == "" || failure != "" || deviceClaim(t, s, token) != "" {
		t.Fatalf("token=%q failure=%q", token, failure)
	}
}

func TestEnrollmentValidation(t *testing.T) {
	s := newTestServer(t)
	api := apiClient{t: t, s: s, token: testAPIToken}
	api.expect(http.StatusBadRequest, "POST", "/api/v1/device-enrollments", map[string]string{"email": "nope", "name": "x"})
	api.expect(http.StatusBadRequest, "POST", "/api/v1/device-enrollments", map[string]string{"email": "a@example.com", "name": ""})
	out, _ := api.expect(http.StatusCreated, "POST", "/api/v1/device-enrollments", map[string]string{"email": "a@example.com", "name": "Laptop"})
	api.expect(http.StatusNoContent, "DELETE", "/api/v1/device-enrollments/"+out["id"].(string), nil)

	// A cancelled link no longer works.
	u, _ := url.Parse(out["url"].(string))
	resp, _ := http.Get(newBrowser(t, s).srv.URL + "/device/enroll?" + u.RawQuery)
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), "not valid") {
		t.Fatalf("cancelled link page: %s", page)
	}
}
