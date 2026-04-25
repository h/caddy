// Copyright 2026 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package permissionproxy registers an on-demand TLS permission module
// (`tls.permission.reverse_proxy`) that decides whether a domain may
// have a certificate issued by dispatching a synthetic HTTP request
// through Caddy's own handler chain — i.e., the same route +
// reverse_proxy pipeline a real client would hit. If the configured
// upstream returns 2xx, the certificate is allowed. Anything else
// (non-2xx, no matching route, network error) denies it.
//
// To defend against backends that ignore the Host header (which would
// otherwise let an attacker mint unbounded certs against a wildcard
// zone), the module also performs a "spoof check": a second probe with
// a randomized first label. If that also returns 2xx, the cert is
// denied because the backend is not validating the hostname.
//
// If the matching automation policy already has an ACME issuer with a
// DNS challenge configured (e.g. via `acme_dns`), the probe is skipped
// entirely because DNS-01 doesn't need probe-based validation.
//
// This package lives outside the caddytls package because it depends
// on caddyhttp (which already depends on caddytls); the sub-package
// avoids the import cycle.
package permissionproxy

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(PermissionByReverseProxy{})
}

// PermissionByReverseProxy validates an on-demand TLS request by
// dispatching a synthetic HTTP request through Caddy's own handler
// chain. See the package doc for full details.
type PermissionByReverseProxy struct {
	// HTTP method for the probe. Default: "HEAD".
	Method string `json:"method,omitempty"`

	// Probe timeout. Default: 10s.
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// Whether to perform the random-subdomain spoof check.
	// Default: true.
	SpoofCheck *bool `json:"spoof_check,omitempty"`

	// Optional: explicit name of the http server to dispatch the
	// probe through. If empty, the module picks the first server
	// whose routes match the hostname.
	Server string `json:"server,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger

	// Test seams. Set by Provision in production; tests overwrite directly.
	dispatchFn  func(ctx context.Context, method, hostname, serverName string) (status int, matched bool, err error)
	dnsCoversFn func(name string) bool
}

const defaultMethod = "HEAD"
const defaultTimeout = 10 * time.Second

// CaddyModule returns the Caddy module information.
func (PermissionByReverseProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.permission.reverse_proxy",
		New: func() caddy.Module { return new(PermissionByReverseProxy) },
	}
}

// Provision wires up the production dispatch and DNS-challenge check.
func (p *PermissionByReverseProxy) Provision(ctx caddy.Context) error {
	p.ctx = ctx
	p.logger = ctx.Logger()

	if p.dispatchFn == nil {
		p.dispatchFn = p.dispatchViaHTTPApp
	}
	if p.dnsCoversFn == nil {
		p.dnsCoversFn = p.dnsChallengeCoversName
	}
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
//
//	permission reverse_proxy {
//	    method <method>
//	    timeout <duration>
//	    spoof_check <bool>
//	    server <server-name>
//	}
//
// All sub-directives are optional.
func (p *PermissionByReverseProxy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Consume the module name token (first call to Next() returns true on it).
	if !d.Next() {
		return nil
	}
	// No inline arguments are accepted.
	if d.NextArg() {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "method":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.Method = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
		case "timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing timeout: %v", err)
			}
			p.Timeout = caddy.Duration(dur)
			if d.NextArg() {
				return d.ArgErr()
			}
		case "spoof_check":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val := d.Val()
			var b bool
			switch strings.ToLower(val) {
			case "true", "on", "yes":
				b = true
			case "false", "off", "no":
				b = false
			default:
				return d.Errf("spoof_check must be true/false, got %q", val)
			}
			p.SpoofCheck = &b
			if d.NextArg() {
				return d.ArgErr()
			}
		case "server":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.Server = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
		default:
			return d.Errf("unrecognized directive %q", d.Val())
		}
	}
	return nil
}

// CertificateAllowed implements caddytls.OnDemandPermission.
func (p *PermissionByReverseProxy) CertificateAllowed(ctx context.Context, name string) error {
	// 1. DNS-01 short-circuit: if the matching automation policy has an
	//    ACME issuer with a DNS challenge configured, we skip the probe.
	//    DNS-01 already proves domain ownership via DNS API credentials.
	if p.dnsCoversFn != nil && p.dnsCoversFn(name) {
		if c := p.logger.Check(zapcore.DebugLevel, "skipping reverse-proxy probe; policy has DNS-01 issuer"); c != nil {
			c.Write(zap.String("domain", name))
		}
		return nil
	}

	// 2. Real probe: GET/HEAD <name> through the configured handler chain.
	probeCtx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()

	status, matched, err := p.dispatchFn(probeCtx, p.method(), name, p.Server)
	if err != nil {
		// Genuine errors (network failure, missing server) bubble up as
		// errors so they're elevated above mere denials in the logs.
		return fmt.Errorf("probing %s: %w", name, err)
	}
	if !matched {
		return fmt.Errorf("%s: %w (no route matches host)", name, caddytls.ErrPermissionDenied)
	}
	if status < 200 || status > 299 {
		return fmt.Errorf("%s: %w (probe got HTTP %d)", name, caddytls.ErrPermissionDenied, status)
	}

	// 3. Spoof check: probe a randomized variant. If the backend returns
	//    2xx for that, it isn't validating the Host header — refuse.
	if p.spoofCheckEnabled() {
		spoofName := randomizeFirstLabel(name)
		spoofStatus, spoofMatched, spoofErr := p.dispatchFn(probeCtx, p.method(), spoofName, p.Server)
		if spoofErr == nil && spoofMatched && spoofStatus >= 200 && spoofStatus <= 299 {
			return fmt.Errorf("%s: %w (Host-blind backend; spoof probe to %s returned HTTP %d)",
				name, caddytls.ErrPermissionDenied, spoofName, spoofStatus)
		}
	}

	return nil
}

func (p *PermissionByReverseProxy) method() string {
	if p.Method == "" {
		return defaultMethod
	}
	return p.Method
}

func (p *PermissionByReverseProxy) timeout() time.Duration {
	if p.Timeout == 0 {
		return defaultTimeout
	}
	return time.Duration(p.Timeout)
}

func (p *PermissionByReverseProxy) spoofCheckEnabled() bool {
	if p.SpoofCheck == nil {
		return true
	}
	return *p.SpoofCheck
}

// randomizeFirstLabel replaces the leftmost DNS label of name with a
// cryptographically random 16-character lowercase alphanumeric string.
// If name has no dots, the entire string is replaced.
func randomizeFirstLabel(name string) string {
	const labelLen = 16
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, labelLen)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand never returns an error in practice; if it ever did,
		// fall back to a deterministic-but-unique value.
		buf = []byte("aaaaaaaaaaaaaaaa")
	}
	out := make([]byte, labelLen)
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	rand := string(out)

	if i := strings.IndexByte(name, '.'); i >= 0 {
		return rand + name[i:]
	}
	return rand
}

// dispatchViaHTTPApp is the production dispatcher: it locates an HTTP
// server in the http app whose routes match the hostname, then sends a
// synthetic request through that server's full handler chain.
func (p *PermissionByReverseProxy) dispatchViaHTTPApp(ctx context.Context, method, hostname, serverName string) (int, bool, error) {
	httpAppIface, err := p.ctx.AppIfConfigured("http")
	if err != nil || httpAppIface == nil {
		return 0, false, fmt.Errorf("http app not available: %v", err)
	}
	httpApp, ok := httpAppIface.(*caddyhttp.App)
	if !ok {
		return 0, false, fmt.Errorf("http app has unexpected type %T", httpAppIface)
	}

	srv, matched := pickServer(httpApp, hostname, serverName)
	if srv == nil {
		if serverName != "" {
			return 0, false, fmt.Errorf("no http server named %q", serverName)
		}
		// No matching server is a denial-level outcome (no error), so the
		// module can return ErrPermissionDenied rather than a probe error.
		return 0, false, nil
	}
	if !matched {
		// Server was selected by name (or there's only one server) but
		// none of its routes match the hostname.
		return 0, false, nil
	}

	req := httptest.NewRequest(method, "/", nil)
	req.Host = hostname
	req.URL.Host = hostname
	req.URL.Scheme = "http"
	req.RemoteAddr = "127.0.0.1:0"
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec.Code, true, nil
}

// pickServer returns the http server that should service a probe for
// hostname, plus whether any of that server's routes have a Host
// matcher that covers hostname. If serverName is non-empty, only that
// server is considered.
func pickServer(app *caddyhttp.App, hostname, serverName string) (*caddyhttp.Server, bool) {
	if serverName != "" {
		srv, ok := app.Servers[serverName]
		if !ok {
			return nil, false
		}
		return srv, serverMatchesHost(srv, hostname)
	}
	for _, srv := range app.Servers {
		if serverMatchesHost(srv, hostname) {
			return srv, true
		}
	}
	return nil, false
}

// serverMatchesHost walks srv's routes looking for any caddyhttp.MatchHost
// matcher whose patterns cover hostname.
func serverMatchesHost(srv *caddyhttp.Server, hostname string) bool {
	for _, route := range srv.Routes {
		for _, ms := range route.MatcherSets {
			for _, m := range ms {
				hm, ok := m.(*caddyhttp.MatchHost)
				if !ok {
					continue
				}
				for _, pattern := range *hm {
					if certmagic.MatchWildcard(hostname, pattern) {
						return true
					}
				}
			}
		}
	}
	return false
}

// dnsChallengeCoversName checks whether the automation policy that
// applies to name has any ACME issuer with a DNS challenge configured.
// If so, the probe is skipped because DNS-01 already validates ownership.
func (p *PermissionByReverseProxy) dnsChallengeCoversName(name string) bool {
	tlsAppIface, err := p.ctx.AppIfConfigured("tls")
	if err != nil || tlsAppIface == nil {
		return false
	}
	tlsApp, ok := tlsAppIface.(*caddytls.TLS)
	if !ok {
		return false
	}
	ap := tlsApp.GetAutomationPolicyForName(name)
	if ap == nil {
		return false
	}
	for _, iss := range ap.Issuers {
		acmeIss, ok := iss.(*caddytls.ACMEIssuer)
		if !ok {
			continue
		}
		if acmeIss.Challenges != nil && acmeIss.Challenges.DNS != nil {
			return true
		}
	}
	return false
}

// Interface guards
var (
	_ caddytls.OnDemandPermission = (*PermissionByReverseProxy)(nil)
	_ caddy.Provisioner           = (*PermissionByReverseProxy)(nil)
	_ caddyfile.Unmarshaler       = (*PermissionByReverseProxy)(nil)
)
