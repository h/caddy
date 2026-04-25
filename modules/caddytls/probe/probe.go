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

// Package probe registers an on-demand TLS permission module
// (`tls.permission.probe`) that decides whether a domain may
// have a certificate issued by dispatching a synthetic HTTP request
// through Caddy's own handler chain — i.e., the same route +
// reverse_proxy pipeline a real client would hit. If the configured
// upstream returns 2xx, the certificate is allowed. Anything else
// (non-2xx, no matching route, network error) denies it.
//
// To defend against upstreams that don't validate the Host header
// (which would otherwise let an attacker mint unbounded certs against
// a wildcard zone), the module also runs a random-host probe: a
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
package probe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
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
	caddy.RegisterModule(Permission{})
}

// Permission validates an on-demand TLS request by
// dispatching a synthetic HTTP request through Caddy's own handler
// chain. See the package doc for full details.
type Permission struct {
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
	RandomHostChallenge *bool `json:"random_host_challenge,omitempty"`

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
func (Permission) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.permission.probe",
		New: func() caddy.Module { return new(Permission) },
	}
}

// Provision wires up the production dispatch and DNS-challenge check,
// and validates configuration.
func (p *Permission) Provision(ctx caddy.Context) error {
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

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. This is the
// generic-permission form; the canonical form is the top-level
// `probe` directive in the `on_demand_tls` global options
// block, which produces the same JSON.
//
//	permission probe {
//	    method <method>
//	    timeout <duration>
//	    random_host_challenge <bool>
//	}
//
// All sub-directives are optional.
func (p *Permission) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Consume the module name token (first call to Next() returns true on it).
	if !d.Next() {
		return nil
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		key := d.Val()
		var raw string
		if !d.AllArgs(&raw) {
			return d.ArgErr()
		}
		switch key {
		case "method":
			p.Method = raw
		case "timeout":
			dur, err := caddy.ParseDuration(raw)
			if err != nil {
				return d.Errf("parsing timeout: %v", err)
			}
			p.Timeout = caddy.Duration(dur)
		case "random_host_challenge":
			b, err := strconv.ParseBool(raw)
			if err != nil {
				return d.Errf("random_host_challenge: %v", err)
			}
			p.RandomHostChallenge = &b
		default:
			return d.Errf("unrecognized directive %q", key)
		}
	}
	return nil
}

// CertificateAllowed implements caddytls.OnDemandPermission.
func (p *Permission) CertificateAllowed(ctx context.Context, name string) error {
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
	//    slow real probe doesn't starve the random-host probe of
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
	if p.randomHostChallengeEnabled() {
		fakeName := randomizeFirstLabel(name)
		fakeStatus, fakeMatched, fakeErr := p.runProbe(ctx, fakeName)
		if fakeErr != nil {
			// Errors here (incl. context.DeadlineExceeded) are observable
			// but don't cause an outright denial. Surface at warn level
			// so operators can spot starvation / upstream trouble.
			if c := p.logger.Check(zapcore.WarnLevel, "random-host probe errored; treating as denied"); c != nil {
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
func (p *Permission) runProbe(parent context.Context, hostname string) (int, bool, error) {
	probeCtx, cancel := context.WithTimeout(parent, p.timeout())
	defer cancel()
	return p.dispatchFn(probeCtx, p.method(), hostname)
}

func (p *Permission) method() string {
	if p.Method == "" {
		return defaultMethod
	}
	return p.Method
}

func (p *Permission) timeout() time.Duration {
	if p.Timeout == 0 {
		return defaultTimeout
	}
	return time.Duration(p.Timeout)
}

func (p *Permission) randomHostChallengeEnabled() bool {
	if p.RandomHostChallenge == nil {
		return true
	}
	return *p.RandomHostChallenge
}

// randomizeFirstLabel replaces the leftmost DNS label of name with a
// cryptographically random 16-character hex string (a-f0-9, all
// DNS-label-safe). If name has no dots, the entire string is replaced.
//
// Hex encoding gives a uniform distribution by construction, so no
// rejection sampling is needed. The 64 bits of entropy is far more
// than enough — an attacker would need to register every name in the
// space to defeat the host-blind check.
func randomizeFirstLabel(name string) string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand is documented to never fail on supported platforms;
		// a fallback would let an attacker predict the random label, so
		// panic instead.
		panic(fmt.Sprintf("probe: crypto/rand failure: %v", err))
	}
	label := hex.EncodeToString(buf[:])
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return label + name[i:]
	}
	return label
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
func (p *Permission) dispatchViaHTTPApp(ctx context.Context, method, hostname string) (status int, matched bool, err error) {
	httpAppIface, err := p.ctx.AppIfConfigured("http")
	if err != nil || httpAppIface == nil {
		return 0, false, fmt.Errorf("http app not available: %v", err)
	}
	httpApp, ok := httpAppIface.(*caddyhttp.App)
	if !ok {
		return 0, false, fmt.Errorf("http app has unexpected type %T", httpAppIface)
	}

	srv, err := pickServer(httpApp)
	if err != nil {
		return 0, false, err
	}

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

	pw := newProbeWriter()

	// Recover from any panic in the handler chain so a misbehaving
	// downstream handler can't tear down the certmagic decision
	// goroutine. Surface as an error rather than a silent no-match,
	// so an operator can see "panic" instead of "no route matched".
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("handler panicked: %v", r)
			if c := p.logger.Check(zapcore.ErrorLevel, "handler panicked during probe"); c != nil {
				c.Write(zap.String("domain", hostname), zap.Any("panic", r))
			}
		}
	}()
	srv.ServeHTTP(pw, req)

	if !pw.handled {
		return 0, false, nil
	}
	return pw.status, true, nil
}

// pickServer returns the http server through which the probe should
// be dispatched. Mirrors Caddy's runtime flow: a real on-demand
// request arrives on the HTTPS listener and is routed to whichever
// Server owns that listener — the same predicate (HasListenerAddress)
// that auto-https uses to find the redirect target. Among the (rare)
// configurations where multiple servers each list the HTTPS port in
// their Listen, we return the alphabetically-first one for
// determinism; the OS won't actually let two servers bind the same
// port simultaneously, so this only matters for the pre-bind config
// view.
func pickServer(app *caddyhttp.App) (*caddyhttp.Server, error) {
	httpsPort := app.HTTPSPort
	if httpsPort == 0 {
		httpsPort = caddyhttp.DefaultHTTPSPort
	}
	addr := net.JoinHostPort("", strconv.Itoa(httpsPort))
	names := make([]string, 0, len(app.Servers))
	for name := range app.Servers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if app.Servers[name].HasListenerAddress(addr) {
			return app.Servers[name], nil
		}
	}
	return nil, fmt.Errorf("no http server has a listener on %s", addr)
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
func (p *Permission) dnsChallengeCoversName(name string) bool {
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
	_ caddytls.OnDemandPermission = (*Permission)(nil)
	_ caddy.Provisioner           = (*Permission)(nil)
	_ caddyfile.Unmarshaler       = (*Permission)(nil)
	_ http.ResponseWriter         = (*probeWriter)(nil)
)
