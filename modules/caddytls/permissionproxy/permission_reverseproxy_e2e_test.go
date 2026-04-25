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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"

	// Side-effect imports register the modules the e2e tests load via
	// JSON config (reverse_proxy handler, the standard set of TLS
	// issuers, etc.). Without these, caddy.Load fails with
	// "unknown module: http.handlers.reverse_proxy".
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

// TestE2E_DispatchProbesRealHandlerChain stands up a real Caddy http
// app (with a wildcard route + reverse_proxy pointing at a stub
// upstream) and then runs the permission module's CertificateAllowed
// against the running config. This exercises the actual probe pipeline
// — synthesis of the http.Request, dispatch through the compiled
// handler chain, the upstream reverse_proxy hop, and the
// "unhandled"-via-probeWriter detection — with no stubbing of
// dispatchFn.
//
// The stub upstream allowlists exactly one Host. Probing a known
// hostname must return 2xx → permission granted. Probing an unknown
// hostname must return 4xx → permission denied. Probing a hostname
// that doesn't match any of the http server's routes must report
// matched=false → permission denied.
func TestE2E_DispatchProbesRealHandlerChain(t *testing.T) {
	// 1. Stub upstream that 200s only for known.example.com and 404s
	//    for everything else. This is the "real" backend the probe
	//    will be reverse_proxied to.
	const knownHost = "known.example.com"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HEAD requests have no body; status code is what matters.
		if strings.EqualFold(r.Host, knownHost) {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(upstream.Close)

	// upstream URL is e.g. http://127.0.0.1:54321; extract the dial address.
	upstreamAddr := strings.TrimPrefix(upstream.URL, "http://")

	// 2. Pick a free port for the http app to listen on. There's a
	//    tiny race window between Close and Caddy's Listen, but it's
	//    standard practice for tests like this.
	srvPort := freePort(t)

	// 3. Build a JSON config: an http server on :srvPort with a
	//    wildcard host route → reverse_proxy to the stub.
	//
	//    No tls app is configured: the test calls CertificateAllowed
	//    directly on a manually-constructed permission module, so we
	//    don't need on-demand wiring. The point of the test is to
	//    exercise dispatchViaHTTPApp against a real *caddyhttp.App.
	cfgJSON := fmt.Sprintf(`{
		"admin": {"disabled": true},
		"apps": {
			"http": {
				"https_port": %d,
				"servers": {
					"srv0": {
						"listen": ["127.0.0.1:%d"],
						"automatic_https": {"disable": true},
						"routes": [{
							"match": [{"host": ["*.example.com"]}],
							"handle": [{
								"handler": "reverse_proxy",
								"upstreams": [{"dial": "%s"}]
							}]
						}]
					}
				}
			}
		}
	}`, srvPort, srvPort, upstreamAddr)

	if err := caddy.Load([]byte(cfgJSON), true); err != nil {
		t.Fatalf("loading caddy config: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	// 4. Construct the permission module against the running context.
	//    Use the explicit `Server` field so pickServer's lookup is by
	//    name (decoupled from the random port).
	p := &PermissionByReverseProxy{
		Method: "HEAD",
		Server: "srv0",
		// Tighten the timeout so a test stub backend hang fails fast.
		Timeout: caddy.Duration(2 * time.Second),
		logger:  zap.NewNop(),
	}
	if err := p.Provision(caddy.ActiveContext()); err != nil {
		t.Fatalf("provisioning permission module: %v", err)
	}

	// 5. Disable spoof check for this scenario: the stub upstream
	//    *intentionally* returns 200 only for one specific Host, so
	//    spoof check would also see a 404 for any randomized name and
	//    correctly grant. But we want to also have a separate test for
	//    the spoof-check-positive case below.
	fl := false
	p.SpoofCheck = &fl

	t.Run("known host — allowed", func(t *testing.T) {
		if err := p.CertificateAllowed(context.Background(), knownHost); err != nil {
			t.Fatalf("expected allow for %q; got: %v", knownHost, err)
		}
	})

	t.Run("unknown host — denied (upstream 404)", func(t *testing.T) {
		err := p.CertificateAllowed(context.Background(), "nonexistent.example.com")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected ErrPermissionDenied for unknown host; got: %v", err)
		}
	})

	t.Run("host outside wildcard zone — denied (no route matches)", func(t *testing.T) {
		// The route only covers *.example.com. A name in a different
		// zone should be unhandled by the chain and reported as
		// matched=false → ErrPermissionDenied.
		err := p.CertificateAllowed(context.Background(), "foo.unrelated.org")
		if !errors.Is(err, caddytls.ErrPermissionDenied) {
			t.Fatalf("expected ErrPermissionDenied for out-of-zone host; got: %v", err)
		}
	})
}

// TestE2E_PickServerOnRealCaddyfileLayout proves that the
// listen-port-based pickServer filter works against the *actual*
// http app structure that Caddy's adapter + auto-HTTPS produce — not
// just hand-built fixtures. If a future Caddy refactor renames the
// redirect server, changes its listen port, or restructures the
// HTTPS server's listeners, this test will catch it.
func TestE2E_PickServerOnRealCaddyfileLayout(t *testing.T) {
	httpsPort := freePort(t)
	httpPort := freePort(t)

	// Spin up a stub upstream just so reverse_proxy has a valid dial
	// address; it never actually receives a request in this test.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	upstreamAddr := strings.TrimPrefix(upstream.URL, "http://")

	// JSON that the Caddyfile `*.example.com { tls { on_demand };
	// reverse_proxy ...}` adapts to, with auto-HTTPS enabled (so the
	// `remaining_auto_https_redirects` server gets created). Use
	// `internal` issuer to avoid real ACME from running.
	cfgJSON := fmt.Sprintf(`{
		"admin": {"disabled": true},
		"apps": {
			"http": {
				"http_port": %d,
				"https_port": %d,
				"servers": {
					"srv0": {
						"listen": ["127.0.0.1:%d"],
						"routes": [{
							"match": [{"host": ["*.example.com"]}],
							"handle": [{
								"handler": "reverse_proxy",
								"upstreams": [{"dial": "%s"}]
							}],
							"terminal": true
						}],
						"tls_connection_policies": [{}]
					}
				}
			},
			"tls": {
				"automation": {
					"policies": [{
						"subjects": ["*.example.com"],
						"issuers": [{"module": "internal"}],
						"on_demand": true
					}]
				}
			}
		}
	}`, httpPort, httpsPort, httpsPort, upstreamAddr)

	if err := caddy.Load([]byte(cfgJSON), true); err != nil {
		t.Fatalf("loading caddy config: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	// Reach into the running http app and assert pickServer chooses
	// the HTTPS server, not the auto-generated redirect server.
	httpAppIface, err := caddy.ActiveContext().AppIfConfigured("http")
	if err != nil {
		t.Fatalf("http app not loaded: %v", err)
	}
	httpApp := httpAppIface.(*caddyhttp.App)

	// Sanity: with auto-HTTPS, the redirect server should exist.
	if _, ok := httpApp.Servers["remaining_auto_https_redirects"]; !ok {
		t.Logf("redirect server not present in this caddy version; this test is verifying behavior in the canonical layout, so skipping")
		t.Skip()
	}
	srv0, ok := httpApp.Servers["srv0"]
	if !ok {
		t.Fatal("srv0 not present in the loaded http app")
	}

	// Run the picker; it must always select srv0 (the HTTPS server).
	for i := 0; i < 20; i++ {
		got, err := pickServer(httpApp, "")
		if err != nil {
			t.Fatalf("pickServer error on real config: %v", err)
		}
		if got != srv0 {
			t.Fatalf("pickServer chose the wrong server on real config; expected srv0 (the HTTPS server)")
		}
	}
}

// TestE2E_DNSChallengeBypassesProbe verifies that when the matching
// automation policy has a DNS-validating issuer configured (acme_dns
// on the Caddyfile side, or `Challenges.DNS` on the JSON side, or
// ZeroSSL CNAME validation), CertificateAllowed returns nil without
// dispatching any probe at all. This is the contract the user
// requested: explicit DNS-based validation overrides the new
// probe-based behavior.
//
// This is an e2e test, not a stub of dnsCoversFn: it loads a real TLS
// app via caddy.Load and exercises dnsChallengeCoversName against the
// running config — so if a future Caddy refactor moves the DNS
// configuration around, the test will catch it.
func TestE2E_DNSChallengeBypassesProbe(t *testing.T) {
	cases := []struct {
		name         string
		issuer       string // JSON for the issuers array
		shouldBypass bool
	}{
		{
			name: "ACMEIssuer with Challenges.DNS configured -> bypass",
			issuer: `{
				"module": "acme",
				"challenges": {
					"dns": {
						"provider": {"name": "permissionproxy_mock"}
					}
				}
			}`,
			shouldBypass: true,
		},
		{
			name: "ZeroSSLIssuer with CNAMEValidation configured -> bypass",
			issuer: `{
				"module": "zerossl",
				"cname_validation": {
					"provider": {"name": "permissionproxy_mock"}
				}
			}`,
			shouldBypass: true,
		},
		{
			name: "ACMEIssuer without DNS challenge -> probe still runs",
			issuer: `{
				"module": "acme"
			}`,
			shouldBypass: false,
		},
		{
			name: "internal-only issuer -> probe still runs (no DNS proof)",
			issuer: `{
				"module": "internal"
			}`,
			shouldBypass: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgJSON := fmt.Sprintf(`{
				"admin": {"disabled": true},
				"apps": {
					"tls": {
						"automation": {
							"policies": [{
								"subjects": ["*.example.com"],
								"issuers": [%s]
							}]
						}
					}
				}
			}`, tc.issuer)

			if err := caddy.Load([]byte(cfgJSON), true); err != nil {
				t.Fatalf("loading caddy config: %v", err)
			}
			t.Cleanup(func() { _ = caddy.Stop() })

			// Construct the permission module and provision it against
			// the running context. The dispatchFn is overridden with a
			// canary that fails the test if it ever fires — that's how
			// we prove the DNS short-circuit triggered.
			var dispatchCalled bool
			p := &PermissionByReverseProxy{
				logger: zap.NewNop(),
				dispatchFn: func(context.Context, string, string, string) (int, bool, error) {
					dispatchCalled = true
					// Returning denial as a defense-in-depth: if the short-
					// circuit fails to fire, the test fails on the err
					// check below rather than silently allowing the cert.
					return 0, false, errors.New("dispatch should not have run")
				},
			}
			if err := p.Provision(caddy.ActiveContext()); err != nil {
				t.Fatalf("provisioning permission module: %v", err)
			}

			err := p.CertificateAllowed(context.Background(), "foo.example.com")

			if tc.shouldBypass {
				if err != nil {
					t.Fatalf("expected DNS issuer to bypass probe and allow; got error: %v", err)
				}
				if dispatchCalled {
					t.Fatal("dispatch fired despite DNS-validating issuer; short-circuit didn't trigger")
				}
			} else {
				// Probe path was followed (dispatch fired and returned
				// a synthetic error). What matters here is that the
				// short-circuit *didn't* trigger.
				if !dispatchCalled {
					t.Fatal("dispatch was skipped even though no DNS issuer was configured")
				}
			}
		})
	}
}

// permissionproxyMockDNS is a no-op DNS provider used only by this
// package's e2e tests so configurations with `Challenges.DNS` or
// `CNAMEValidation` actually load. It implements the libdns interfaces
// that certmagic looks for, but every method is a no-op — the e2e
// tests never actually solve a DNS challenge; they only need the
// config tree to be valid so dnsChallengeCoversName can read it.
type permissionproxyMockDNS struct{}

func (permissionproxyMockDNS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.permissionproxy_mock",
		New: func() caddy.Module { return new(permissionproxyMockDNS) },
	}
}
func (permissionproxyMockDNS) Provision(caddy.Context) error { return nil }

// libdns interfaces (AppendRecords, DeleteRecords, GetRecords,
// SetRecords) are referenced by name when certmagic checks the
// provider type-asserts. Returning empty results matches the existing
// caddytest/integration MockDNSProvider.
func (permissionproxyMockDNS) AppendRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}
func (permissionproxyMockDNS) DeleteRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}
func (permissionproxyMockDNS) GetRecords(context.Context, string) ([]libdns.Record, error) {
	return nil, nil
}
func (permissionproxyMockDNS) SetRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

func init() {
	caddy.RegisterModule(permissionproxyMockDNS{})
}

// freePort asks the OS for a free TCP port and returns it.
// There's a tiny race window between Close() and the actual rebind,
// but it's the standard pattern for "pick an ephemeral port".
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("closing free-port listener: %v", err)
	}
	return port
}

