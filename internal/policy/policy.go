// Package policy evaluates access policies for an application.
//
// A policy matches a request when at least one Include rule matches, every
// Require rule matches, and no Exclude rule matches. Policies are evaluated in
// order and the first match decides the outcome. If nothing matches, access is
// denied.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

// Rule is a single selector. Exactly one field must be set.
type Rule struct {
	Everyone    bool   `json:"everyone,omitempty" yaml:"everyone,omitempty"`
	Email       string `json:"email,omitempty" yaml:"email,omitempty"`
	EmailDomain string `json:"email_domain,omitempty" yaml:"email_domain,omitempty"`
	Group       string `json:"group,omitempty" yaml:"group,omitempty"`
	IPRange     string `json:"ip_range,omitempty" yaml:"ip_range,omitempty"`
	// TrustedDevice matches requests from an enrolled, unrevoked device of
	// the signed-in user, proven with its hardware-bound key at sign-in.
	TrustedDevice bool `json:"trusted_device,omitempty" yaml:"trusted_device,omitempty"`
}

type Policy struct {
	Name    string `json:"name" yaml:"name"`
	Action  Action `json:"action" yaml:"action"`
	Include []Rule `json:"include" yaml:"include"`
	Require []Rule `json:"require,omitempty" yaml:"require,omitempty"`
	Exclude []Rule `json:"exclude,omitempty" yaml:"exclude,omitempty"`
}

// Identity is the authenticated user making the request.
type Identity struct {
	Email  string
	Groups []string
}

// Request carries the per-request context policies can match on.
type Request struct {
	IP netip.Addr
	// DeviceID is the verified trusted device, or empty.
	DeviceID string
}

type Decision struct {
	Allowed bool
	Policy  string
	Reason  string
}

type matcher func(*Identity, *Request) bool

type compiled struct {
	name    string
	action  Action
	include []matcher
	require []matcher
	exclude []matcher
}

// Set is a compiled, ordered list of policies. It is safe for concurrent use.
type Set struct {
	policies []compiled
}

func Compile(policies []Policy) (*Set, error) {
	set := &Set{}
	for i, p := range policies {
		if p.Name == "" {
			return nil, fmt.Errorf("policy %d: name is required", i)
		}
		if p.Action != Allow && p.Action != Deny {
			return nil, fmt.Errorf("policy %q: action must be %q or %q", p.Name, Allow, Deny)
		}
		if len(p.Include) == 0 {
			return nil, fmt.Errorf("policy %q: at least one include rule is required", p.Name)
		}
		c := compiled{name: p.Name, action: p.Action}
		var err error
		if c.include, err = compileRules(p.Include); err != nil {
			return nil, fmt.Errorf("policy %q include: %w", p.Name, err)
		}
		if c.require, err = compileRules(p.Require); err != nil {
			return nil, fmt.Errorf("policy %q require: %w", p.Name, err)
		}
		if c.exclude, err = compileRules(p.Exclude); err != nil {
			return nil, fmt.Errorf("policy %q exclude: %w", p.Name, err)
		}
		set.policies = append(set.policies, c)
	}
	return set, nil
}

func (s *Set) Evaluate(id Identity, req Request) Decision {
	for _, p := range s.policies {
		if !anyMatch(p.include, &id, &req) || !allMatch(p.require, &id, &req) || anyMatch(p.exclude, &id, &req) {
			continue
		}
		return Decision{Allowed: p.action == Allow, Policy: p.name, Reason: "matched policy"}
	}
	return Decision{Allowed: false, Reason: "no policy matched"}
}

// UsesDevice reports whether any rule depends on a trusted device, so sign-in
// knows to ask for the device's proof.
func UsesDevice(policies []Policy) bool {
	for _, p := range policies {
		for _, rules := range [][]Rule{p.Include, p.Require, p.Exclude} {
			for _, r := range rules {
				if r.TrustedDevice {
					return true
				}
			}
		}
	}
	return false
}

func anyMatch(ms []matcher, id *Identity, req *Request) bool {
	for _, m := range ms {
		if m(id, req) {
			return true
		}
	}
	return false
}

func allMatch(ms []matcher, id *Identity, req *Request) bool {
	for _, m := range ms {
		if !m(id, req) {
			return false
		}
	}
	return true
}

func compileRules(rules []Rule) ([]matcher, error) {
	out := make([]matcher, 0, len(rules))
	for i, r := range rules {
		m, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		out = append(out, m)
	}
	return out, nil
}

func compileRule(r Rule) (matcher, error) {
	set := 0
	for _, ok := range []bool{r.Everyone, r.Email != "", r.EmailDomain != "", r.Group != "", r.IPRange != "", r.TrustedDevice} {
		if ok {
			set++
		}
	}
	if set != 1 {
		return nil, errors.New("exactly one selector must be set")
	}

	switch {
	case r.Everyone:
		return func(*Identity, *Request) bool { return true }, nil

	case r.TrustedDevice:
		return func(_ *Identity, req *Request) bool { return req.DeviceID != "" }, nil

	case r.Email != "":
		want := r.Email
		return func(id *Identity, _ *Request) bool { return strings.EqualFold(id.Email, want) }, nil

	case r.EmailDomain != "":
		suffix := "@" + strings.ToLower(strings.TrimPrefix(r.EmailDomain, "@"))
		return func(id *Identity, _ *Request) bool {
			return strings.HasSuffix(strings.ToLower(id.Email), suffix)
		}, nil

	case r.Group != "":
		want := r.Group
		return func(id *Identity, _ *Request) bool {
			return slices.ContainsFunc(id.Groups, func(g string) bool { return strings.EqualFold(g, want) })
		}, nil

	default:
		prefix, err := parsePrefix(r.IPRange)
		if err != nil {
			return nil, err
		}
		return func(_ *Identity, req *Request) bool {
			return req.IP.IsValid() && prefix.Contains(req.IP.Unmap())
		}, nil
	}
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid ip_range %q: %w", s, err)
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid ip_range %q: %w", s, err)
	}
	return netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()), nil
}
