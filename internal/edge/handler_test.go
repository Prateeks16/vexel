package edge

import "testing"

func TestSafeRedirect(t *testing.T) {
	cases := map[string]string{
		"/clients/42?tab=docs": "/clients/42?tab=docs",
		"/":                    "/",
		"":                     "/",
		"https://evil.example": "/",
		"//evil.example/x":     "/",
		"/\\evil.example":      "/",
		"javascript:alert(1)":  "/",
		"/.vexel/logout":       "/",
	}
	for in, want := range cases {
		if got := safeRedirect(in); got != want {
			t.Errorf("safeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHostOnly(t *testing.T) {
	cases := map[string]string{
		"CRM.Example.com:8443": "crm.example.com",
		"crm.example.com.":     "crm.example.com",
		"crm.example.com":      "crm.example.com",
		"[::1]:8080":           "::1",
	}
	for in, want := range cases {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}
