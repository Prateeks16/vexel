package policy

import (
	"net/netip"
	"testing"
)

func TestEvaluate(t *testing.T) {
	set, err := Compile([]Policy{
		{
			Name:    "block contractors",
			Action:  Deny,
			Include: []Rule{{Group: "contractors"}},
		},
		{
			Name:    "staff from office or VPN",
			Action:  Allow,
			Include: []Rule{{EmailDomain: "example.com"}, {Email: "partner@other.org"}},
			Require: []Rule{{IPRange: "10.0.0.0/8"}},
			Exclude: []Rule{{Email: "suspended@example.com"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	office := netip.MustParseAddr("10.1.2.3")
	home := netip.MustParseAddr("203.0.113.9")

	tests := []struct {
		name       string
		id         Identity
		ip         netip.Addr
		wantAllow  bool
		wantPolicy string
	}{
		{"staff in office", Identity{Email: "Alice@Example.com"}, office, true, "staff from office or VPN"},
		{"named partner", Identity{Email: "partner@other.org"}, office, true, "staff from office or VPN"},
		{"staff outside range", Identity{Email: "alice@example.com"}, home, false, ""},
		{"excluded user", Identity{Email: "suspended@example.com"}, office, false, ""},
		{"contractor denied first", Identity{Email: "bob@example.com", Groups: []string{"Contractors"}}, office, false, "block contractors"},
		{"lookalike domain", Identity{Email: "eve@notexample.com"}, office, false, ""},
		{"unknown IP", Identity{Email: "alice@example.com"}, netip.Addr{}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := set.Evaluate(tt.id, Request{IP: tt.ip})
			if d.Allowed != tt.wantAllow || d.Policy != tt.wantPolicy {
				t.Fatalf("got allowed=%v policy=%q, want allowed=%v policy=%q", d.Allowed, d.Policy, tt.wantAllow, tt.wantPolicy)
			}
		})
	}
}

func TestEmptySetDenies(t *testing.T) {
	set, err := Compile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := set.Evaluate(Identity{Email: "a@example.com"}, Request{}); d.Allowed {
		t.Fatal("empty policy set must deny")
	}
}

func TestSingleIPRange(t *testing.T) {
	set, err := Compile([]Policy{{Name: "one host", Action: Allow, Include: []Rule{{IPRange: "192.0.2.10"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !set.Evaluate(Identity{}, Request{IP: netip.MustParseAddr("::ffff:192.0.2.10")}).Allowed {
		t.Fatal("IPv4-mapped address should match its IPv4 range")
	}
	if set.Evaluate(Identity{}, Request{IP: netip.MustParseAddr("192.0.2.11")}).Allowed {
		t.Fatal("neighbouring address must not match")
	}
}

func TestTrustedDevice(t *testing.T) {
	policies := []Policy{{
		Name: "staff on company laptops", Action: Allow,
		Include: []Rule{{EmailDomain: "example.com"}},
		Require: []Rule{{TrustedDevice: true}},
	}}
	set, err := Compile(policies)
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{Email: "alice@example.com"}
	if set.Evaluate(id, Request{}).Allowed {
		t.Fatal("no device must be denied")
	}
	if !set.Evaluate(id, Request{DeviceID: "dev-1"}).Allowed {
		t.Fatal("trusted device must be allowed")
	}
	if !UsesDevice(policies) || UsesDevice([]Policy{{Include: []Rule{{Everyone: true}}}}) {
		t.Fatal("UsesDevice")
	}
}

func TestCompileErrors(t *testing.T) {
	bad := []Policy{
		{Action: Allow, Include: []Rule{{Everyone: true}}},
		{Name: "x", Action: "maybe", Include: []Rule{{Everyone: true}}},
		{Name: "x", Action: Allow},
		{Name: "x", Action: Allow, Include: []Rule{{}}},
		{Name: "x", Action: Allow, Include: []Rule{{Email: "a@b.c", Group: "g"}}},
		{Name: "x", Action: Allow, Include: []Rule{{Everyone: true, TrustedDevice: true}}},
		{Name: "x", Action: Allow, Include: []Rule{{IPRange: "not-an-ip"}}},
	}
	for i, p := range bad {
		if _, err := Compile([]Policy{p}); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}
