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

package routeprobe

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

// stubDispatch is a programmable replacement for the production
// dispatch path. Each invocation appends to calls and returns the
// fields produced by respond().
type stubDispatch struct {
	mu      sync.Mutex
	calls   []dispatchCall
	respond func(call dispatchCall) dispatchResp
}

type dispatchCall struct {
	method   string
	hostname string
}

type dispatchResp struct {
	status  int
	matched bool
	err     error
}

func (s *stubDispatch) fn() func(ctx context.Context, method, hostname string) (int, bool, error) {
	return func(ctx context.Context, method, hostname string) (int, bool, error) {
		call := dispatchCall{method: method, hostname: hostname}
		s.mu.Lock()
		s.calls = append(s.calls, call)
		s.mu.Unlock()
		r := s.respond(call)
		return r.status, r.matched, r.err
	}
}

func (s *stubDispatch) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// newPerm produces a PermissionByRouteProbe with sensible defaults
// for testing: HEAD method, 1s timeout, random-host probe on, no
// DNS coverage, and a logger that drops everything.
func newPerm(t *testing.T, dispatch *stubDispatch) *PermissionByRouteProbe {
	t.Helper()
	tr := true
	return &PermissionByRouteProbe{
		Method:             "HEAD",
		Timeout:            caddy.Duration(time.Second),
		RandomHostProbe: &tr,
		logger:             zap.NewNop(),
		dispatchFn:         dispatch.fn(),
		dnsCoversFn:        func(string) bool { return false },
	}
}

// always returns the same response regardless of call.
func always(status int, matched bool, err error) func(dispatchCall) dispatchResp {
	return func(dispatchCall) dispatchResp {
		return dispatchResp{status: status, matched: matched, err: err}
	}
}

// byRandomHost returns one response for the canonical name and a different
// one for the random-host probe (which uses a randomized first label).
func byRandomHost(canonical string, real, randomHost dispatchResp) func(dispatchCall) dispatchResp {
	return func(c dispatchCall) dispatchResp {
		if c.hostname == canonical {
			return real
		}
		return randomHost
	}
}

// ============================================================
// CertificateAllowed: probe outcomes
// ============================================================

func TestCertificateAllowed_AllowsValidSubdomain(t *testing.T) {
	stub := &stubDispatch{respond: byRandomHost(
		"foo.example.com",
		dispatchResp{status: 200, matched: true},
		dispatchResp{status: 404, matched: true}, // probe denied
	)}
	p := newPerm(t, stub)

	if err := p.CertificateAllowed(context.Background(), "foo.example.com"); err != nil {
		t.Fatalf("expected allow, got error: %v", err)
	}
	if got := stub.callCount(); got != 2 {
		t.Errorf("expected 2 dispatch calls (real + random-host), got %d", got)
	}
}

func TestCertificateAllowed_DeniesOn404(t *testing.T) {
	stub := &stubDispatch{respond: always(404, true, nil)}
	p := newPerm(t, stub)

	err := p.CertificateAllowed(context.Background(), "foo.example.com")
	if !errors.Is(err, caddytls.ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
	if got := stub.callCount(); got != 1 {
		t.Errorf("expected 1 dispatch call (no random-host probe on denial), got %d", got)
	}
}

func TestCertificateAllowed_DeniesOn5xx(t *testing.T) {
	stub := &stubDispatch{respond: always(502, true, nil)}
	p := newPerm(t, stub)

	if err := p.CertificateAllowed(context.Background(), "foo.example.com"); !errors.Is(err, caddytls.ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied for 502, got %v", err)
	}
}

func TestCertificateAllowed_DeniesOn3xx(t *testing.T) {
	// 301 is not a 2xx and Caddy's existing PermissionByHTTP also rejects redirects.
	stub := &stubDispatch{respond: always(301, true, nil)}
	p := newPerm(t, stub)

	if err := p.CertificateAllowed(context.Background(), "foo.example.com"); !errors.Is(err, caddytls.ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied for 301, got %v", err)
	}
}

func TestCertificateAllowed_DeniesWhenNoRouteMatches(t *testing.T) {
	// Even if status is 200 (Caddy's default for unrouted), matched=false should deny.
	stub := &stubDispatch{respond: always(200, false, nil)}
	p := newPerm(t, stub)

	err := p.CertificateAllowed(context.Background(), "foo.example.com")
	if !errors.Is(err, caddytls.ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied when no route matches, got %v", err)
	}
}

func TestCertificateAllowed_PropagatesDispatchError(t *testing.T) {
	want := errors.New("simulated network failure")
	stub := &stubDispatch{respond: always(0, false, want)}
	p := newPerm(t, stub)

	err := p.CertificateAllowed(context.Background(), "foo.example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Errors from the probe itself are reported as errors (not ErrPermissionDenied)
	// to elevate them above mere denials, matching the existing PermissionByHTTP convention.
	if errors.Is(err, caddytls.ErrPermissionDenied) {
		t.Fatalf("dispatch errors should not be wrapped as ErrPermissionDenied; got: %v", err)
	}
	if !strings.Contains(err.Error(), "simulated network failure") {
		t.Fatalf("error should mention root cause; got: %v", err)
	}
}

// ============================================================
// CertificateAllowed: random-host probe
// ============================================================

func TestCertificateAllowed_DeniesWhenRandomHostProbeAlsoSucceeds(t *testing.T) {
	// Backend returns 200 for any host — classic Host-blind misconfiguration.
	stub := &stubDispatch{respond: always(200, true, nil)}
	p := newPerm(t, stub)

	err := p.CertificateAllowed(context.Background(), "foo.example.com")
	if !errors.Is(err, caddytls.ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied when backend ignores Host header, got %v", err)
	}
	if got := stub.callCount(); got != 2 {
		t.Errorf("expected 2 dispatch calls (real + random-host) before denying, got %d", got)
	}
	if stub.calls[0].hostname == stub.calls[1].hostname {
		t.Errorf("random-host probe should use a different hostname; both were %q", stub.calls[0].hostname)
	}
}

func TestCertificateAllowed_AllowsWhenRandomHostProbeDisabled(t *testing.T) {
	// Even if backend would return 200 for any host, with the
	// random-host probe disabled we allow.
	stub := &stubDispatch{respond: always(200, true, nil)}
	fl := false
	p := newPerm(t, stub)
	p.RandomHostProbe = &fl

	if err := p.CertificateAllowed(context.Background(), "foo.example.com"); err != nil {
		t.Fatalf("expected allow with random_host_probe=false, got: %v", err)
	}
	if got := stub.callCount(); got != 1 {
		t.Errorf("expected 1 dispatch call when random-host probe is disabled, got %d", got)
	}
}

func TestCertificateAllowed_AllowsWhenRandomHostProbeReturnsNon2xx(t *testing.T) {
	stub := &stubDispatch{respond: byRandomHost(
		"foo.example.com",
		dispatchResp{status: 200, matched: true},
		dispatchResp{status: 404, matched: true},
	)}
	p := newPerm(t, stub)

	if err := p.CertificateAllowed(context.Background(), "foo.example.com"); err != nil {
		t.Fatalf("expected allow, got: %v", err)
	}
}

func TestCertificateAllowed_AllowsWhenRandomHostProbeErrors(t *testing.T) {
	// Real probe 2xx, random-host probe network error → backend isn't responding to fake
	// hosts at all, which is *good*. Allow the cert.
	stub := &stubDispatch{respond: byRandomHost(
		"foo.example.com",
		dispatchResp{status: 200, matched: true},
		dispatchResp{status: 0, matched: true, err: errors.New("connection refused")},
	)}
	p := newPerm(t, stub)

	if err := p.CertificateAllowed(context.Background(), "foo.example.com"); err != nil {
		t.Fatalf("expected allow when random-host probe errors, got: %v", err)
	}
}

// ============================================================
// CertificateAllowed: DNS-01 short-circuit
// ============================================================

func TestCertificateAllowed_AllowsWhenDNSChallengeConfigured(t *testing.T) {
	stub := &stubDispatch{respond: always(0, false, errors.New("should not be called"))}
	p := newPerm(t, stub)
	p.dnsCoversFn = func(string) bool { return true }

	if err := p.CertificateAllowed(context.Background(), "foo.example.com"); err != nil {
		t.Fatalf("expected allow when DNS-01 is configured, got: %v", err)
	}
	if got := stub.callCount(); got != 0 {
		t.Errorf("expected 0 dispatch calls when DNS-01 short-circuits; got %d", got)
	}
}

func TestCertificateAllowed_ProbesWhenDNSChallengeNotConfigured(t *testing.T) {
	stub := &stubDispatch{respond: byRandomHost(
		"foo.example.com",
		dispatchResp{status: 200, matched: true},
		dispatchResp{status: 404, matched: true},
	)}
	p := newPerm(t, stub)
	// dnsCoversFn returns false (the default we set in newPerm)

	if err := p.CertificateAllowed(context.Background(), "foo.example.com"); err != nil {
		t.Fatalf("expected allow, got: %v", err)
	}
	if got := stub.callCount(); got < 1 {
		t.Errorf("expected dispatch when DNS-01 is not configured; got %d calls", got)
	}
}

// ============================================================
// CertificateAllowed: timeout
// ============================================================

func TestCertificateAllowed_AppliesTimeout(t *testing.T) {
	stub := &stubDispatch{
		respond: func(dispatchCall) dispatchResp {
			return dispatchResp{status: 0, matched: false, err: context.DeadlineExceeded}
		},
	}
	p := newPerm(t, stub)
	p.Timeout = caddy.Duration(50 * time.Millisecond)

	start := time.Now()
	err := p.CertificateAllowed(context.Background(), "foo.example.com")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from timed-out probe")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("CertificateAllowed took %v; expected to be bounded by timeout", elapsed)
	}
}

// ============================================================
// Method, timeout, and random_host_probe defaults
// ============================================================

func TestMethodDefault(t *testing.T) {
	p := &PermissionByRouteProbe{}
	if got := p.method(); got != "HEAD" {
		t.Errorf("default method: got %q, want %q", got, "HEAD")
	}
}

func TestMethodOverride(t *testing.T) {
	p := &PermissionByRouteProbe{Method: "GET"}
	if got := p.method(); got != "GET" {
		t.Errorf("method override: got %q, want %q", got, "GET")
	}
}

func TestTimeoutDefault(t *testing.T) {
	p := &PermissionByRouteProbe{}
	if got := p.timeout(); got != 10*time.Second {
		t.Errorf("default timeout: got %v, want 10s", got)
	}
}

func TestTimeoutOverride(t *testing.T) {
	p := &PermissionByRouteProbe{Timeout: caddy.Duration(3 * time.Second)}
	if got := p.timeout(); got != 3*time.Second {
		t.Errorf("timeout override: got %v, want 3s", got)
	}
}

func TestRandomHostProbeEnabled_NilDefaultsTrue(t *testing.T) {
	p := &PermissionByRouteProbe{}
	if !p.randomHostProbeEnabled() {
		t.Error("expected random-host probe to default to enabled when RandomHostProbe is nil")
	}
}

func TestRandomHostProbeEnabled_ExplicitTrue(t *testing.T) {
	tr := true
	p := &PermissionByRouteProbe{RandomHostProbe: &tr}
	if !p.randomHostProbeEnabled() {
		t.Error("expected random-host probe to be enabled when RandomHostProbe=true")
	}
}

func TestRandomHostProbeEnabled_ExplicitFalse(t *testing.T) {
	fl := false
	p := &PermissionByRouteProbe{RandomHostProbe: &fl}
	if p.randomHostProbeEnabled() {
		t.Error("expected random-host probe to be disabled when RandomHostProbe=false")
	}
}

// ============================================================
// randomizeFirstLabel
// ============================================================

func TestRandomizeFirstLabel_PreservesSuffix(t *testing.T) {
	got := randomizeFirstLabel("foo.example.com")
	if !strings.HasSuffix(got, ".example.com") {
		t.Errorf("expected suffix .example.com to be preserved; got %q", got)
	}
	if strings.HasPrefix(got, "foo.") {
		t.Errorf("expected first label to be replaced; got %q", got)
	}
}

func TestRandomizeFirstLabel_HandlesMultiLevel(t *testing.T) {
	got := randomizeFirstLabel("foo.app.example.com")
	if !strings.HasSuffix(got, ".app.example.com") {
		t.Errorf("expected only the leftmost label to be replaced; got %q", got)
	}
}

func TestRandomizeFirstLabel_GeneratesDifferentValues(t *testing.T) {
	// Sample multiple pairs and assert at least two distinct results.
	// A single pair is theoretically flaky (1 in 36^16 ≈ 8e24); 8 samples
	// makes the per-run failure probability completely negligible for any
	// future RNG that's even loosely uniform.
	const samples = 8
	seen := make(map[string]struct{}, samples)
	for i := 0; i < samples; i++ {
		seen[randomizeFirstLabel("foo.example.com")] = struct{}{}
	}
	if len(seen) < 2 {
		t.Errorf("expected at least 2 distinct results across %d samples; got %d (%v)", samples, len(seen), seen)
	}
}

func TestRandomizeFirstLabel_LowercaseAlphanumericOnly(t *testing.T) {
	got := randomizeFirstLabel("foo.example.com")
	first := strings.SplitN(got, ".", 2)[0]
	if !regexp.MustCompile(`^[a-z0-9]+$`).MatchString(first) {
		t.Errorf("expected first label to be lowercase alphanumeric; got %q", first)
	}
	if len(first) < 8 {
		t.Errorf("expected first label to have decent entropy; got length %d (%q)", len(first), first)
	}
}

func TestRandomizeFirstLabel_HandlesBareHostname(t *testing.T) {
	// A name with no dots is unusual at the cert layer, but we shouldn't panic.
	got := randomizeFirstLabel("localhost")
	if got == "localhost" {
		t.Errorf("bare hostname should be replaced or rejected; got %q", got)
	}
}

// ============================================================
// UnmarshalCaddyfile
// ============================================================

func TestUnmarshalCaddyfile_EmptyBlock(t *testing.T) {
	d := caddyfile.NewTestDispenser(`reverse_proxy {
    }`)
	p := &PermissionByRouteProbe{}
	if err := p.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("expected empty block to parse cleanly; got: %v", err)
	}
	if p.method() != "HEAD" {
		t.Errorf("default method after empty parse: got %q want HEAD", p.method())
	}
	if !p.randomHostProbeEnabled() {
		t.Error("random_host_probe should default to true after empty parse")
	}
}

func TestUnmarshalCaddyfile_FullBlock(t *testing.T) {
	d := caddyfile.NewTestDispenser(`reverse_proxy {
        method GET
        timeout 5s
        random_host_probe false
    }`)
	p := &PermissionByRouteProbe{}
	if err := p.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if p.Method != "GET" {
		t.Errorf("Method: got %q, want GET", p.Method)
	}
	if time.Duration(p.Timeout) != 5*time.Second {
		t.Errorf("Timeout: got %v, want 5s", time.Duration(p.Timeout))
	}
	if p.RandomHostProbe == nil || *p.RandomHostProbe {
		t.Errorf("RandomHostProbe: got %v, want explicit false", p.RandomHostProbe)
	}
}

func TestUnmarshalCaddyfile_UnknownDirective(t *testing.T) {
	d := caddyfile.NewTestDispenser(`reverse_proxy {
        wat unknown
    }`)
	p := &PermissionByRouteProbe{}
	if err := p.UnmarshalCaddyfile(d); err == nil {
		t.Error("expected error for unknown directive, got nil")
	}
}

// ============================================================
// Module registration sanity
// ============================================================

func TestModuleID(t *testing.T) {
	info := PermissionByRouteProbe{}.CaddyModule()
	if info.ID != "tls.permission.route_probe" {
		t.Errorf("module ID: got %q, want tls.permission.route_probe", info.ID)
	}
}

func TestImplementsOnDemandPermission(t *testing.T) {
	var _ caddytls.OnDemandPermission = (*PermissionByRouteProbe)(nil)
}

// ============================================================
// pickServers
// ============================================================

// httpsServer returns a minimal *caddyhttp.Server that listens on
// `:443` (the default HTTPS port).
func httpsServer() *caddyhttp.Server {
	return &caddyhttp.Server{Listen: []string{":443"}}
}

// httpRedirectServer returns a minimal *caddyhttp.Server that listens
// on `:80` only — i.e., a `remaining_auto_https_redirects`-style
// server that pickServers should filter out.
func httpRedirectServer() *caddyhttp.Server {
	return &caddyhttp.Server{Listen: []string{":80"}}
}

func httpsAppWith(servers map[string]*caddyhttp.Server) *caddyhttp.App {
	return &caddyhttp.App{Servers: servers}
}

func TestPickServers_FiltersOutRedirectServer(t *testing.T) {
	// Canonical auto-HTTPS scenario. The user-defined HTTPS server
	// (`srv0`) listens on :443 and the auto-generated redirect server
	// (`remaining_auto_https_redirects`) listens on :80. The redirect
	// server must never appear in the candidate list.
	tlsSrv := httpsServer()
	app := httpsAppWith(map[string]*caddyhttp.Server{
		"srv0":                           tlsSrv,
		"remaining_auto_https_redirects": httpRedirectServer(),
	})
	for i := 0; i < 20; i++ {
		got, err := pickServers(app)
		if err != nil {
			t.Fatalf("pickServers error: %v", err)
		}
		if len(got) != 1 || got[0] != tlsSrv {
			t.Fatalf("expected exactly the HTTPS server; got %d candidates", len(got))
		}
	}
}

func TestPickServers_HonorsCustomHTTPSPort(t *testing.T) {
	// User overrides https_port to 9443. The HTTPS server should be
	// selected based on the configured port, not the default 443.
	tlsSrv := &caddyhttp.Server{Listen: []string{":9443"}}
	app := &caddyhttp.App{
		HTTPSPort: 9443,
		Servers: map[string]*caddyhttp.Server{
			"srv0":                           tlsSrv,
			"remaining_auto_https_redirects": &caddyhttp.Server{Listen: []string{":9080"}},
		},
	}
	got, err := pickServers(app)
	if err != nil {
		t.Fatalf("pickServers error: %v", err)
	}
	if len(got) != 1 || got[0] != tlsSrv {
		t.Error("expected the server listening on the custom https_port")
	}
}

func TestPickServers_HonorsPortRangeListen(t *testing.T) {
	tlsSrv := &caddyhttp.Server{Listen: []string{":8000-9000"}}
	app := &caddyhttp.App{
		HTTPSPort: 8443,
		Servers:   map[string]*caddyhttp.Server{"srv0": tlsSrv},
	}
	got, err := pickServers(app)
	if err != nil {
		t.Fatalf("pickServers error: %v", err)
	}
	if len(got) != 1 || got[0] != tlsSrv {
		t.Error("expected port-range listen to be matched")
	}
}

func TestPickServers_ErrorsWhenNoServerListensOnHTTPS(t *testing.T) {
	app := httpsAppWith(map[string]*caddyhttp.Server{
		"remaining_auto_https_redirects": httpRedirectServer(),
	})
	if _, err := pickServers(app); err == nil {
		t.Error("expected error when no server listens on https port; got nil")
	}
}

func TestPickServers_ReturnsAllHTTPSServersInNameOrder(t *testing.T) {
	// Multiple servers that listen on the HTTPS port: pickServers must
	// return all of them, deterministically sorted by name. The
	// dispatcher will then try each in order until one handles the
	// hostname.
	a := &caddyhttp.Server{Listen: []string{":443"}}
	b := &caddyhttp.Server{Listen: []string{":443"}}
	c := &caddyhttp.Server{Listen: []string{":443"}}
	app := httpsAppWith(map[string]*caddyhttp.Server{
		"srv2": c,
		"srv0": a,
		"srv1": b,
	})
	for i := 0; i < 20; i++ {
		got, err := pickServers(app)
		if err != nil {
			t.Fatalf("pickServers error: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("expected 3 candidates; got %d", len(got))
		}
		if got[0] != a || got[1] != b || got[2] != c {
			t.Errorf("expected name-sorted order [srv0, srv1, srv2]; got different order on iteration %d", i)
		}
	}
}

func TestServerListensOnPort_RejectsMalformedListen(t *testing.T) {
	srv := &caddyhttp.Server{Listen: []string{"not a valid address"}}
	if serverListensOnPort(srv, 443) {
		t.Error("malformed listen address should not match")
	}
}

// ============================================================
// probeWriter
// ============================================================

func TestProbeWriter_RecordsStatusFromWriteHeader(t *testing.T) {
	pw := newProbeWriter()
	pw.WriteHeader(404)
	if !pw.handled {
		t.Error("WriteHeader should mark handled=true")
	}
	if pw.status != 404 {
		t.Errorf("status: got %d, want 404", pw.status)
	}
}

func TestProbeWriter_WriteImpliesHandled200(t *testing.T) {
	pw := newProbeWriter()
	n, err := pw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != 5 {
		t.Errorf("Write: got n=%d, want 5", n)
	}
	if !pw.handled {
		t.Error("Write should mark handled=true")
	}
	if pw.status != http.StatusOK {
		t.Errorf("status without WriteHeader: got %d, want 200", pw.status)
	}
}

func TestProbeWriter_WriteHeaderIsIdempotent(t *testing.T) {
	pw := newProbeWriter()
	pw.WriteHeader(201)
	pw.WriteHeader(500)
	if pw.status != 201 {
		t.Errorf("status: got %d, want 201 (first call wins)", pw.status)
	}
}

func TestProbeWriter_DiscardsBody(t *testing.T) {
	pw := newProbeWriter()
	pw.WriteHeader(200)
	// Write a "large" payload; probeWriter must not buffer.
	big := make([]byte, 1<<20) // 1 MiB
	n, err := pw.Write(big)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(big) {
		t.Errorf("Write returned n=%d, want %d", n, len(big))
	}
	// probeWriter has no body field at all; we just need to confirm no panic
	// and that Write honors the io.Writer contract (return len(p), nil).
}

func TestProbeWriter_NoCallsLeavesUnhandled(t *testing.T) {
	pw := newProbeWriter()
	if pw.handled {
		t.Error("fresh probeWriter should have handled=false")
	}
	if pw.status != 0 {
		t.Errorf("fresh probeWriter status: got %d, want 0", pw.status)
	}
	// Calling Header() alone shouldn't change anything.
	_ = pw.Header()
	if pw.handled {
		t.Error("Header() should not mark handled")
	}
}

func TestProbeWriter_HeaderReturnsMutableMap(t *testing.T) {
	pw := newProbeWriter()
	pw.Header().Set("X-Foo", "bar")
	if got := pw.Header().Get("X-Foo"); got != "bar" {
		t.Errorf("Header().Get: got %q, want bar", got)
	}
}
