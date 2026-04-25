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

package permissionproxy

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
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
	method     string
	hostname   string
	serverName string
}

type dispatchResp struct {
	status  int
	matched bool
	err     error
}

func (s *stubDispatch) fn() func(ctx context.Context, method, hostname, serverName string) (int, bool, error) {
	return func(ctx context.Context, method, hostname, serverName string) (int, bool, error) {
		call := dispatchCall{method: method, hostname: hostname, serverName: serverName}
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

// newPerm produces a PermissionByReverseProxy with sensible defaults
// for testing: HEAD method, 1s timeout, spoof check on, no DNS coverage,
// and a logger that drops everything.
func newPerm(t *testing.T, dispatch *stubDispatch) *PermissionByReverseProxy {
	t.Helper()
	tr := true
	return &PermissionByReverseProxy{
		Method:      "HEAD",
		Timeout:     caddy.Duration(time.Second),
		SpoofCheck:  &tr,
		logger:      zap.NewNop(),
		dispatchFn:  dispatch.fn(),
		dnsCoversFn: func(string) bool { return false },
	}
}

// always returns the same response regardless of call.
func always(status int, matched bool, err error) func(dispatchCall) dispatchResp {
	return func(dispatchCall) dispatchResp {
		return dispatchResp{status: status, matched: matched, err: err}
	}
}

// bySpoof returns one response for the canonical name and a different one
// for the spoofed (random-first-label) probe.
func bySpoof(canonical string, real, spoof dispatchResp) func(dispatchCall) dispatchResp {
	return func(c dispatchCall) dispatchResp {
		if c.hostname == canonical {
			return real
		}
		return spoof
	}
}

// ============================================================
// CertificateAllowed: probe outcomes
// ============================================================

func TestCertificateAllowed_AllowsValidSubdomain(t *testing.T) {
	stub := &stubDispatch{respond: bySpoof(
		"foo.example.com",
		dispatchResp{status: 200, matched: true},
		dispatchResp{status: 404, matched: true}, // spoof denied
	)}
	p := newPerm(t, stub)

	if err := p.CertificateAllowed(context.Background(), "foo.example.com"); err != nil {
		t.Fatalf("expected allow, got error: %v", err)
	}
	if got := stub.callCount(); got != 2 {
		t.Errorf("expected 2 dispatch calls (real + spoof), got %d", got)
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
		t.Errorf("expected 1 dispatch call (no spoof on denial), got %d", got)
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
// CertificateAllowed: spoof check
// ============================================================

func TestCertificateAllowed_DeniesWhenSpoofProbeAlsoSucceeds(t *testing.T) {
	// Backend returns 200 for any host — classic Host-blind misconfiguration.
	stub := &stubDispatch{respond: always(200, true, nil)}
	p := newPerm(t, stub)

	err := p.CertificateAllowed(context.Background(), "foo.example.com")
	if !errors.Is(err, caddytls.ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied when backend ignores Host header, got %v", err)
	}
	if got := stub.callCount(); got != 2 {
		t.Errorf("expected 2 dispatch calls (real + spoof) before denying, got %d", got)
	}
	if stub.calls[0].hostname == stub.calls[1].hostname {
		t.Errorf("spoof probe should use a different hostname; both were %q", stub.calls[0].hostname)
	}
}

func TestCertificateAllowed_AllowsWhenSpoofCheckDisabled(t *testing.T) {
	// Even if backend would return 200 for a spoofed host, with spoof check off we allow.
	stub := &stubDispatch{respond: always(200, true, nil)}
	fl := false
	p := newPerm(t, stub)
	p.SpoofCheck = &fl

	if err := p.CertificateAllowed(context.Background(), "foo.example.com"); err != nil {
		t.Fatalf("expected allow with spoof_check=false, got: %v", err)
	}
	if got := stub.callCount(); got != 1 {
		t.Errorf("expected 1 dispatch call when spoof check is disabled, got %d", got)
	}
}

func TestCertificateAllowed_AllowsWhenSpoofProbeReturnsNon2xx(t *testing.T) {
	stub := &stubDispatch{respond: bySpoof(
		"foo.example.com",
		dispatchResp{status: 200, matched: true},
		dispatchResp{status: 404, matched: true},
	)}
	p := newPerm(t, stub)

	if err := p.CertificateAllowed(context.Background(), "foo.example.com"); err != nil {
		t.Fatalf("expected allow, got: %v", err)
	}
}

func TestCertificateAllowed_AllowsWhenSpoofProbeErrors(t *testing.T) {
	// Real probe 2xx, spoof probe network error → backend isn't responding to fake
	// hosts at all, which is *good*. Allow the cert.
	stub := &stubDispatch{respond: bySpoof(
		"foo.example.com",
		dispatchResp{status: 200, matched: true},
		dispatchResp{status: 0, matched: true, err: errors.New("connection refused")},
	)}
	p := newPerm(t, stub)

	if err := p.CertificateAllowed(context.Background(), "foo.example.com"); err != nil {
		t.Fatalf("expected allow when spoof probe errors, got: %v", err)
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
	stub := &stubDispatch{respond: bySpoof(
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
// CertificateAllowed: server selection
// ============================================================

func TestCertificateAllowed_PassesExplicitServerName(t *testing.T) {
	var seen atomic.Pointer[string]
	stub := &stubDispatch{
		respond: func(c dispatchCall) dispatchResp {
			s := c.serverName
			seen.Store(&s)
			return dispatchResp{status: 200, matched: true}
		},
	}
	p := newPerm(t, stub)
	p.Server = "srv0"
	fl := false
	p.SpoofCheck = &fl // simplify: avoid extra calls

	if err := p.CertificateAllowed(context.Background(), "foo.example.com"); err != nil {
		t.Fatalf("expected allow, got: %v", err)
	}
	if got := seen.Load(); got == nil || *got != "srv0" {
		t.Errorf("expected serverName=srv0 to be passed to dispatch, got %v", got)
	}
}

// ============================================================
// Method, timeout, and spoof_check defaults
// ============================================================

func TestMethodDefault(t *testing.T) {
	p := &PermissionByReverseProxy{}
	if got := p.method(); got != "HEAD" {
		t.Errorf("default method: got %q, want %q", got, "HEAD")
	}
}

func TestMethodOverride(t *testing.T) {
	p := &PermissionByReverseProxy{Method: "GET"}
	if got := p.method(); got != "GET" {
		t.Errorf("method override: got %q, want %q", got, "GET")
	}
}

func TestTimeoutDefault(t *testing.T) {
	p := &PermissionByReverseProxy{}
	if got := p.timeout(); got != 10*time.Second {
		t.Errorf("default timeout: got %v, want 10s", got)
	}
}

func TestTimeoutOverride(t *testing.T) {
	p := &PermissionByReverseProxy{Timeout: caddy.Duration(3 * time.Second)}
	if got := p.timeout(); got != 3*time.Second {
		t.Errorf("timeout override: got %v, want 3s", got)
	}
}

func TestSpoofCheckEnabled_NilDefaultsTrue(t *testing.T) {
	p := &PermissionByReverseProxy{}
	if !p.spoofCheckEnabled() {
		t.Error("expected spoof check to default to enabled when SpoofCheck is nil")
	}
}

func TestSpoofCheckEnabled_ExplicitTrue(t *testing.T) {
	tr := true
	p := &PermissionByReverseProxy{SpoofCheck: &tr}
	if !p.spoofCheckEnabled() {
		t.Error("expected spoof check to be enabled when SpoofCheck=true")
	}
}

func TestSpoofCheckEnabled_ExplicitFalse(t *testing.T) {
	fl := false
	p := &PermissionByReverseProxy{SpoofCheck: &fl}
	if p.spoofCheckEnabled() {
		t.Error("expected spoof check to be disabled when SpoofCheck=false")
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
	p := &PermissionByReverseProxy{}
	if err := p.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("expected empty block to parse cleanly; got: %v", err)
	}
	if p.method() != "HEAD" {
		t.Errorf("default method after empty parse: got %q want HEAD", p.method())
	}
	if !p.spoofCheckEnabled() {
		t.Error("spoof_check should default to true after empty parse")
	}
}

func TestUnmarshalCaddyfile_FullBlock(t *testing.T) {
	d := caddyfile.NewTestDispenser(`reverse_proxy {
        method GET
        timeout 5s
        spoof_check false
        server srv0
    }`)
	p := &PermissionByReverseProxy{}
	if err := p.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if p.Method != "GET" {
		t.Errorf("Method: got %q, want GET", p.Method)
	}
	if time.Duration(p.Timeout) != 5*time.Second {
		t.Errorf("Timeout: got %v, want 5s", time.Duration(p.Timeout))
	}
	if p.SpoofCheck == nil || *p.SpoofCheck {
		t.Errorf("SpoofCheck: got %v, want explicit false", p.SpoofCheck)
	}
	if p.Server != "srv0" {
		t.Errorf("Server: got %q, want srv0", p.Server)
	}
}

func TestUnmarshalCaddyfile_UnknownDirective(t *testing.T) {
	d := caddyfile.NewTestDispenser(`reverse_proxy {
        wat unknown
    }`)
	p := &PermissionByReverseProxy{}
	if err := p.UnmarshalCaddyfile(d); err == nil {
		t.Error("expected error for unknown directive, got nil")
	}
}

// ============================================================
// Module registration sanity
// ============================================================

func TestModuleID(t *testing.T) {
	info := PermissionByReverseProxy{}.CaddyModule()
	if info.ID != "tls.permission.reverse_proxy" {
		t.Errorf("module ID: got %q, want tls.permission.reverse_proxy", info.ID)
	}
}

func TestImplementsOnDemandPermission(t *testing.T) {
	var _ caddytls.OnDemandPermission = (*PermissionByReverseProxy)(nil)
}

// ============================================================
// pickServer
// ============================================================

// httpsServer returns a minimal *caddyhttp.Server that listens on
// `:443` (the default HTTPS port) — i.e., one that pickServer should
// treat as the HTTPS server.
func httpsServer() *caddyhttp.Server {
	return &caddyhttp.Server{Listen: []string{":443"}}
}

// httpRedirectServer returns a minimal *caddyhttp.Server that listens
// on `:80` only — i.e., a `remaining_auto_https_redirects`-style
// server that pickServer should filter out.
func httpRedirectServer() *caddyhttp.Server {
	return &caddyhttp.Server{Listen: []string{":80"}}
}

func httpsAppWith(servers map[string]*caddyhttp.Server) *caddyhttp.App {
	return &caddyhttp.App{Servers: servers}
}

func TestPickServer_PrefersHTTPSServerOverRedirectServer(t *testing.T) {
	// The canonical auto-HTTPS scenario. The user-defined HTTPS server
	// (`srv0`) listens on :443 and the auto-generated redirect server
	// (`remaining_auto_https_redirects`) listens on :80. The probe must
	// always go to the HTTPS one regardless of map iteration order.
	tlsSrv := httpsServer()
	app := httpsAppWith(map[string]*caddyhttp.Server{
		"srv0":                           tlsSrv,
		"remaining_auto_https_redirects": httpRedirectServer(),
	})
	// Run several times to defeat any chance the test could pass by
	// luck of iteration order.
	for i := 0; i < 20; i++ {
		got, err := pickServer(app, "")
		if err != nil {
			t.Fatalf("pickServer error: %v", err)
		}
		if got != tlsSrv {
			t.Fatalf("expected pickServer to choose the HTTPS server every time; got the redirect server")
		}
	}
}

func TestPickServer_HonorsCustomHTTPSPort(t *testing.T) {
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
	got, err := pickServer(app, "")
	if err != nil {
		t.Fatalf("pickServer error: %v", err)
	}
	if got != tlsSrv {
		t.Error("expected the server listening on the custom https_port")
	}
}

func TestPickServer_HonorsPortRangeListen(t *testing.T) {
	tlsSrv := &caddyhttp.Server{Listen: []string{":8000-9000"}}
	app := &caddyhttp.App{
		HTTPSPort: 8443,
		Servers:   map[string]*caddyhttp.Server{"srv0": tlsSrv},
	}
	got, err := pickServer(app, "")
	if err != nil {
		t.Fatalf("pickServer error: %v", err)
	}
	if got != tlsSrv {
		t.Error("expected port-range listen to be matched")
	}
}

func TestPickServer_ErrorsWhenNoServerListensOnHTTPS(t *testing.T) {
	app := httpsAppWith(map[string]*caddyhttp.Server{
		"remaining_auto_https_redirects": httpRedirectServer(),
	})
	if _, err := pickServer(app, ""); err == nil {
		t.Error("expected error when no server listens on https port; got nil")
	}
}

func TestPickServer_ErrorsWhenMultipleHTTPSServers(t *testing.T) {
	app := httpsAppWith(map[string]*caddyhttp.Server{
		"srv0": httpsServer(),
		"srv1": httpsServer(),
	})
	_, err := pickServer(app, "")
	if err == nil {
		t.Fatal("expected error with multiple https servers")
	}
	if !strings.Contains(err.Error(), "set `server`") {
		t.Errorf("error should suggest setting the `server` field; got: %v", err)
	}
}

func TestPickServer_ExplicitName_Selected(t *testing.T) {
	// Explicit `server` overrides the port-based filter — even a server
	// that doesn't listen on the HTTPS port can be chosen this way.
	tlsSrv := httpRedirectServer() // intentionally not on :443
	app := httpsAppWith(map[string]*caddyhttp.Server{
		"srv0":                           httpsServer(),
		"remaining_auto_https_redirects": tlsSrv,
	})
	got, err := pickServer(app, "remaining_auto_https_redirects")
	if err != nil {
		t.Fatalf("pickServer error: %v", err)
	}
	if got != tlsSrv {
		t.Error("expected explicit name to return the named server regardless of port")
	}
}

func TestPickServer_ExplicitName_Missing(t *testing.T) {
	app := httpsAppWith(map[string]*caddyhttp.Server{"srv0": httpsServer()})
	if _, err := pickServer(app, "nope"); err == nil {
		t.Error("expected error when explicit server name doesn't exist")
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
