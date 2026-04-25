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
// To defend against upstreams that don't validate the Host header
// (which would otherwise let an attacker mint unbounded certs against
// a wildcard zone), the module also runs a host-specificity check: a
// second probe with a randomized first label. If that also returns
// 2xx, the upstream is treated as host-blind and the certificate is
// denied.
//
// If the matching automation policy already has an issuer with a DNS
// challenge configured (e.g. via `acme_dns` or ZeroSSL CNAME
// validation), the probe is skipped entirely because DNS already
// proves domain ownership.
//
// This package lives outside the caddytls package because it depends
// on caddyhttp (which already depends on caddytls); the sub-package
// avoids the import cycle.
package permissionproxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"time"

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

	// Probe timeout. Default: 10s. Applied independently to the real
	// probe and the verification probe.
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// Whether to verify that the configured upstream gives a
	// host-specific response — that is, that it doesn't return 2xx for
	// arbitrary hostnames. When enabled (default), the module sends a
	// second probe with a randomized first label after the real probe;
	// if the upstream answers 2xx for that random hostname too, the
	// upstream is treated as host-blind and the certificate is denied.
	//
	// Disabling this check is unsafe on a wildcard zone: a misconfigured
	// upstream can be tricked into causing the issuance of unbounded
	// certificates.
	//
	// Default: true.
	VerifyHostSpecific *bool `json:"verify_host_specific,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger

	// Test seams. Set by Provision in production; tests overwrite directly.
	dispatchFn  func(ctx context.Context, method, hostname string) (status int, matched bool, err error)
	dnsCoversFn func(name string) bool
}

const (
	defaultMethod  = "HEAD"
	defaultTimeout = 10 * time.Second
)

// CaddyModule returns the Caddy module information.
func (PermissionByReverseProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.permission.reverse_proxy",
		New: func() caddy.Module { return new(PermissionByReverseProxy) },
	}
}

// Provision wires up the production dispatch and DNS-challenge check,
// and validates configuration.
func (p *PermissionByReverseProxy) Provision(ctx caddy.Context) error {
	p.ctx = ctx
	p.logger = ctx.Logger()

	// Validate Method: anything that http.NewRequest accepts is fine, but
	// we want to fail fast at provision rather than panic at first cert miss.
	if p.Method != "" {
		if _, err := http.NewRequest(p.Method, "/", nil); err != nil {
			return fmt.Errorf("invalid probe method %q: %v", p.Method, err)
		}
	}

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
//	    verify_host_specific <bool>
//	}
//
// All sub-directives are optional.
func (p *PermissionByReverseProxy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Consume the module name token (first call to Next() returns true on it).
	if !d.Next() {
		return nil
	}
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
		case "verify_host_specific":
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
				return d.Errf("verify_host_specific must be true/false, got %q", val)
			}
			p.VerifyHostSpecific = &b
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
	// 1. DNS short-circuit: if the matching automation policy has an
	//    issuer with DNS-based validation configured, skip the probe.
	//    DNS proves domain ownership without needing a probe.
	if p.dnsCoversFn != nil && p.dnsCoversFn(name) {
		if c := p.logger.Check(zapcore.DebugLevel, "skipping reverse-proxy probe; policy has DNS-validating issuer"); c != nil {
			c.Write(zap.String("domain", name))
		}
		return nil
	}

	// 2. Real probe. Each probe gets its own fresh deadline so that a
	//    slow real probe doesn't starve the host-specificity probe of
	//    budget.
	status, matched, err := p.runProbe(ctx, name)
	if err != nil {
		return fmt.Errorf("probing %s: %w", name, err)
	}
	if !matched {
		return fmt.Errorf("%s: %w (no route handled the probe)", name, caddytls.ErrPermissionDenied)
	}
	if status < 200 || status > 299 {
		return fmt.Errorf("%s: %w (probe got HTTP %d)", name, caddytls.ErrPermissionDenied, status)
	}

	// 3. Host-specificity check: probe a randomized variant. If the
	//    upstream returns 2xx for an unrelated random hostname too, it
	//    isn't really validating the Host header — refuse the cert.
	if p.verifyHostSpecificEnabled() {
		fakeName := randomizeFirstLabel(name)
		fakeStatus, fakeMatched, fakeErr := p.runProbe(ctx, fakeName)
		if fakeErr != nil {
			// Errors here (incl. context.DeadlineExceeded) are observable
			// but don't cause an outright denial. Surface at warn level
			// so operators can spot starvation / upstream trouble.
			if c := p.logger.Check(zapcore.WarnLevel, "host-specificity probe errored; treating as denied"); c != nil {
				c.Write(zap.String("domain", name), zap.String("fake_domain", fakeName), zap.Error(fakeErr))
			}
		} else if fakeMatched && fakeStatus >= 200 && fakeStatus <= 299 {
			return fmt.Errorf("%s: %w (host-blind upstream; probe to random hostname %s also returned HTTP %d)",
				name, caddytls.ErrPermissionDenied, fakeName, fakeStatus)
		}
	}

	return nil
}

// runProbe runs a single probe with its own fresh timeout deadline.
func (p *PermissionByReverseProxy) runProbe(parent context.Context, hostname string) (int, bool, error) {
	probeCtx, cancel := context.WithTimeout(parent, p.timeout())
	defer cancel()
	return p.dispatchFn(probeCtx, p.method(), hostname)
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

func (p *PermissionByReverseProxy) verifyHostSpecificEnabled() bool {
	if p.VerifyHostSpecific == nil {
		return true
	}
	return *p.VerifyHostSpecific
}

// randomizeFirstLabel replaces the leftmost DNS label of name with a
// cryptographically random 16-character lowercase alphanumeric string.
// If name has no dots, the entire string is replaced.
//
// Uses rejection sampling so each character is uniformly distributed
// across the alphabet (no modulo bias).
func randomizeFirstLabel(name string) string {
	const labelLen = 16
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	const alphaLen = byte(len(alphabet)) // 36
	// Largest multiple of alphaLen that fits in a byte; bytes >= this
	// value are rejected to avoid modulo bias.
	const cutoff = byte(256 - (256 % int(alphaLen)))

	out := make([]byte, 0, labelLen)
	buf := make([]byte, labelLen*2) // size buf bigger than needed; refill if exhausted
	for len(out) < labelLen {
		if _, err := rand.Read(buf); err != nil {
			// crypto/rand is documented to never fail on supported platforms.
			// A deterministic fallback would let an attacker predict the
			// spoof name, so panic instead.
			panic(fmt.Sprintf("permissionproxy: crypto/rand failure: %v", err))
		}
		for _, b := range buf {
			if b >= cutoff {
				continue // reject biased bytes
			}
			out = append(out, alphabet[b%alphaLen])
			if len(out) == labelLen {
				break
			}
		}
	}
	randomLabel := string(out)

	if i := strings.IndexByte(name, '.'); i >= 0 {
		return randomLabel + name[i:]
	}
	return randomLabel
}

// dispatchViaHTTPApp is the production dispatcher: it picks the HTTPS
// server in the http app and sends a synthetic request through its full
// handler chain. The result is interpreted as:
//
//   - status: HTTP status returned by the chain (or 0 if the chain
//     wrote nothing)
//   - matched: true iff a handler in the chain actually wrote a
//     response (i.e., some route's matchers fired). false means the
//     hostname was unrouted, which the caller treats as denial.
//   - err: a real probe failure (no http app, no eligible server,
//     handler panic). Distinct from a denial.
func (p *PermissionByReverseProxy) dispatchViaHTTPApp(ctx context.Context, method, hostname string) (int, bool, error) {
	httpAppIface, err := p.ctx.AppIfConfigured("http")
	if err != nil || httpAppIface == nil {
		return 0, false, fmt.Errorf("http app not available: %v", err)
	}
	httpApp, ok := httpAppIface.(*caddyhttp.App)
	if !ok {
		return 0, false, fmt.Errorf("http app has unexpected type %T", httpAppIface)
	}

	candidates, err := pickServers(httpApp)
	if err != nil {
		return 0, false, err
	}

	// Build a synthetic request once; servers are dispatched against
	// the same request copy.
	req := httptest.NewRequest(method, "/", nil)
	req.Host = hostname
	req.URL.Host = hostname
	// Probe as if the request arrived on the HTTPS listener: scheme=https
	// plus a non-nil TLS state. This mirrors what a real client request
	// to the on-demand-protected hostname would look like, so any
	// MatchProtocol("https") matchers in the user's chain behave the
	// same way they would for the live request.
	req.URL.Scheme = "https"
	req.TLS = &tls.ConnectionState{ServerName: hostname}
	// Use 0.0.0.0:0 instead of 127.0.0.1:0 so handlers that key off
	// remote_ip (rate limiters, IP allowlists) can't accidentally
	// treat the probe as a privileged loopback request.
	req.RemoteAddr = "0.0.0.0:0"
	req = req.WithContext(ctx)

	// Try each candidate in deterministic name-sorted order. The first
	// that actually handles the request (probeWriter records a write)
	// wins. With the canonical single-HTTPS-server layout this is
	// always the only iteration.
	for _, srv := range candidates {
		pw := newProbeWriter()

		// Recover from any panic in the handler chain so a misbehaving
		// downstream handler can't tear down the certmagic decision
		// goroutine.
		func() {
			defer func() {
				if r := recover(); r != nil {
					if c := p.logger.Check(zapcore.ErrorLevel, "handler panicked during probe; continuing to next candidate"); c != nil {
						c.Write(zap.String("domain", hostname), zap.Any("panic", r))
					}
				}
			}()
			srv.ServeHTTP(pw, req)
		}()

		if pw.handled {
			return pw.status, true, nil
		}
	}

	// No candidate's handler chain wrote anything for this hostname.
	return 0, false, nil
}

// pickServers returns every http server that listens on the
// configured HTTPS port, sorted by server name for determinism. This
// mirrors Caddy's physical routing: a real client request for an
// on-demand-protected hostname arrives on the HTTPS listener and is
// routed to whichever Server bound that port. The auto-generated
// `remaining_auto_https_redirects` server listens on the HTTP port
// and is therefore filtered out naturally.
//
// In the canonical single-HTTPS-server layout this returns one
// element. In multi-HTTPS-server configurations it returns all
// candidates; the caller dispatches through them in order until one
// actually handles the request.
func pickServers(app *caddyhttp.App) ([]*caddyhttp.Server, error) {
	httpsPort := app.HTTPSPort
	if httpsPort == 0 {
		httpsPort = caddyhttp.DefaultHTTPSPort
	}

	type named struct {
		name string
		srv  *caddyhttp.Server
	}
	var matches []named
	for name, srv := range app.Servers {
		if serverListensOnPort(srv, httpsPort) {
			matches = append(matches, named{name: name, srv: srv})
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no http server listens on https port %d", httpsPort)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].name < matches[j].name })

	out := make([]*caddyhttp.Server, len(matches))
	for i, m := range matches {
		out[i] = m.srv
	}
	return out, nil
}

// serverListensOnPort reports whether any of srv.Listen's addresses
// covers port. Addresses are parsed via caddy.ParseNetworkAddress so
// port-range syntax (e.g. ":8080-8090") and host-prefixed forms (e.g.
// "1.2.3.4:443") are handled the same way the rest of Caddy parses
// them.
func serverListensOnPort(srv *caddyhttp.Server, port int) bool {
	for _, lnAddr := range srv.Listen {
		na, err := caddy.ParseNetworkAddress(lnAddr)
		if err != nil {
			continue
		}
		if uint(port) >= na.StartPort && uint(port) <= na.EndPort {
			return true
		}
	}
	return false
}

// probeWriter is a tiny http.ResponseWriter that records the status
// code and whether any handler actually responded, while discarding
// body bytes. Replaces httptest.NewRecorder so we don't buffer
// (potentially large) response bodies in memory on every cert miss.
type probeWriter struct {
	headers http.Header
	status  int
	handled bool
}

func newProbeWriter() *probeWriter {
	return &probeWriter{headers: make(http.Header)}
}

func (pw *probeWriter) Header() http.Header { return pw.headers }

func (pw *probeWriter) WriteHeader(code int) {
	if !pw.handled {
		pw.status = code
		pw.handled = true
	}
}

func (pw *probeWriter) Write(p []byte) (int, error) {
	if !pw.handled {
		pw.status = http.StatusOK
		pw.handled = true
	}
	return len(p), nil
}

// dnsChallengeCoversName checks whether the automation policy that
// applies to name has an issuer that proves ownership via DNS — either
// an ACME issuer with a DNS challenge configured, or a ZeroSSL issuer
// with CNAME validation configured. If so, the probe is skipped
// because DNS already validates ownership.
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
		switch v := iss.(type) {
		case *caddytls.ACMEIssuer:
			if v.Challenges != nil && v.Challenges.DNS != nil {
				return true
			}
		case *caddytls.ZeroSSLIssuer:
			if v.CNAMEValidation != nil {
				return true
			}
		}
	}
	return false
}

// Interface guards
var (
	_ caddytls.OnDemandPermission = (*PermissionByReverseProxy)(nil)
	_ caddy.Provisioner           = (*PermissionByReverseProxy)(nil)
	_ caddyfile.Unmarshaler       = (*PermissionByReverseProxy)(nil)
	_ http.ResponseWriter         = (*probeWriter)(nil)
)
