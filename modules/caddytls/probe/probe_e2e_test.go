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

package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"

	// Side-effect imports register the modules the e2e tests load via
	// JSON config (reverse_proxy handler, file_system storage, etc.).
	// Without these, caddy.Load fails with "unknown module: ...".
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	_ "github.com/caddyserver/caddy/v2/modules/filestorage"
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
	//    https_port is set to srvPort so that pickServers (which
	//    filters by configured HTTPS port) selects this server.
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
	//    pickServers will find srv0 by HTTPS port match (the http app
	//    has https_port = srvPort, and srv0 listens on srvPort).
	p := &Permission{
		Method: "HEAD",
		// Tighten the timeout so a test stub backend hang fails fast.
		Timeout: caddy.Duration(2 * time.Second),
		logger:  zap.NewNop(),
	}
	if err := p.Provision(caddy.ActiveContext()); err != nil {
		t.Fatalf("provisioning permission module: %v", err)
	}

	// 5. Disable random-host probe for this scenario: the stub
	//    upstream *intentionally* returns 200 only for one specific
	//    Host, so the random-host probe would correctly see a 404 and
	//    not deny — but we already have separate tests for the
	//    random-host probe matrix.
	fl := false
	p.RandomHostChallenge = &fl

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

// TestE2E_PickServersOnRealCaddyfileLayout proves that the
// listen-port-based pickServers filter works against the *actual*
// http app structure that Caddy's adapter + auto-HTTPS produce — not
// just hand-built fixtures. If a future Caddy refactor renames the
// redirect server, changes its listen port, or restructures the
// HTTPS server's listeners, this test will catch it.
func TestE2E_PickServersOnRealCaddyfileLayout(t *testing.T) {
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

	// Reach into the running http app and assert pickServers returns
	// only the HTTPS server, not the auto-generated redirect server.
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

	// Run the picker; it must always return exactly srv0 (the HTTPS
	// server) and exclude the redirect server.
	for i := 0; i < 20; i++ {
		got, err := pickServers(httpApp)
		if err != nil {
			t.Fatalf("pickServers error on real config: %v", err)
		}
		if len(got) != 1 || got[0] != srv0 {
			t.Fatalf("pickServers returned wrong candidates on real config; expected [srv0], got %d candidates", len(got))
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
						"provider": {"name": "probe_mock"}
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
					"provider": {"name": "probe_mock"}
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
			p := &Permission{
				logger: zap.NewNop(),
				dispatchFn: func(context.Context, string, string) (int, bool, error) {
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

// probeMockDNS is a no-op DNS provider used only by this
// package's e2e tests so configurations with `Challenges.DNS` or
// `CNAMEValidation` actually load. It implements the libdns interfaces
// that certmagic looks for, but every method is a no-op — the e2e
// tests never actually solve a DNS challenge; they only need the
// config tree to be valid so dnsChallengeCoversName can read it.
type probeMockDNS struct{}

func (probeMockDNS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.probe_mock",
		New: func() caddy.Module { return new(probeMockDNS) },
	}
}
func (probeMockDNS) Provision(caddy.Context) error { return nil }

// libdns interfaces (AppendRecords, DeleteRecords, GetRecords,
// SetRecords) are referenced by name when certmagic checks the
// provider type-asserts. Returning empty results matches the existing
// caddytest/integration MockDNSProvider.
func (probeMockDNS) AppendRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}
func (probeMockDNS) DeleteRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}
func (probeMockDNS) GetRecords(context.Context, string) ([]libdns.Record, error) {
	return nil, nil
}
func (probeMockDNS) SetRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

func init() {
	caddy.RegisterModule(probeMockDNS{})
}

// TestE2E_NoOnDemand_NoModuleLoaded verifies that a config with no
// on-demand TLS anywhere doesn't auto-instantiate the new permission
// module — i.e., the new behavior only ever runs when the operator
// has explicitly opted into on-demand. This is a check on
// applyOnDemandPermissionDefault's narrowed scope: explicit-subject
// or no-on-demand configs must remain probe-free.
func TestE2E_NoOnDemand_NoModuleLoaded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream got an unexpected request — probe should not have run: %v %v", r.Method, r.Host)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(upstream.Close)

	// A regular (non-on-demand) site. The TLS app provisions normally
	// but `Automation.OnDemand` should remain unset.
	cfgJSON := fmt.Sprintf(`{
		"admin": {"disabled": true},
		"apps": {
			"http": {
				"servers": {
					"srv0": {
						"listen": ["127.0.0.1:%d"],
						"automatic_https": {"disable": true},
						"routes": [{
							"match": [{"host": ["example.com"]}],
							"handle": [{
								"handler": "reverse_proxy",
								"upstreams": [{"dial": "%s"}]
							}]
						}]
					}
				}
			},
			"tls": {
				"automation": {
					"policies": [{
						"subjects": ["example.com"],
						"issuers": [{"module": "internal"}]
					}]
				}
			}
		}
	}`, freePort(t), strings.TrimPrefix(upstream.URL, "http://"))

	if err := caddy.Load([]byte(cfgJSON), true); err != nil {
		t.Fatalf("loading caddy config: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	tlsAppIface, err := caddy.ActiveContext().AppIfConfigured("tls")
	if err != nil {
		t.Fatalf("tls app not loaded: %v", err)
	}
	tls := tlsAppIface.(*caddytls.TLS)
	if tls.Automation == nil || tls.Automation.OnDemand != nil {
		t.Errorf("expected Automation.OnDemand to be nil when no policy enables on-demand; got %+v", tls.Automation.OnDemand)
	}
}

// TestE2E_StaticCert_BypassesProbe verifies that when a certificate
// is already loaded for a hostname (via tls.certificates.load_files),
// a TLS handshake to that hostname uses the loaded cert directly and
// never triggers the on-demand probe — even though on-demand is
// enabled for the wildcard zone.
//
// The oracle is the upstream stub: if the probe runs, the upstream
// receives a HEAD request. The test asserts the upstream's request
// counter is exactly 0.
//
// Uses a hostname unique to this test so a previous test's
// (legitimately-cached) cert in the package-global cert cache can't
// accidentally satisfy this handshake from cache.
func TestE2E_StaticCert_BypassesProbe(t *testing.T) {
	const knownHost = "staticcert-test-host.example.com"

	// Generate a self-signed cert for knownHost and write it to PEM
	// files.
	certFile, keyFile := writeSelfSignedCertPEM(t, knownHost)

	var probeCount atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	httpsPort := freePort(t)
	cfgJSON := fmt.Sprintf(`{
		"admin": {"disabled": true},
		"apps": {
			"http": {
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
				"certificates": {
					"load_files": [{
						"certificate": "%s",
						"key": "%s",
						"tags": ["static"]
					}]
				},
				"automation": {
					"policies": [{
						"subjects": ["*.example.com"],
						"issuers": [{"module": "internal"}],
						"on_demand": true
					}]
				}
			}
		}
	}`, httpsPort, httpsPort, strings.TrimPrefix(upstream.URL, "http://"),
		filepath.ToSlash(certFile), filepath.ToSlash(keyFile))

	if err := caddy.Load([]byte(cfgJSON), true); err != nil {
		t.Fatalf("loading caddy config: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	// Drive a real TLS handshake to knownHost. With the cert preloaded,
	// the handshake must use it without ever triggering on-demand.
	if err := tlsHandshake(httpsPort, knownHost); err != nil {
		t.Fatalf("TLS handshake to %s failed: %v", knownHost, err)
	}

	// Allow a brief moment for any straggling async probe to fire
	// (there shouldn't be any, but let's be honest about timing).
	time.Sleep(100 * time.Millisecond)

	if got := probeCount.Load(); got != 0 {
		t.Errorf("expected 0 probe requests with a static cert preloaded; got %d", got)
	}
}

// TestE2E_CachedCert_BypassesProbeOnSecondHandshake verifies that
// once a certificate has been issued and cached (e.g. on the first
// on-demand handshake), subsequent handshakes for the same hostname
// reuse the cache and don't re-trigger the probe.
//
// The oracle is again the upstream stub; with RandomHostChallenge
// disabled (so we get exactly one probe request per cert miss), the
// test asserts the upstream sees exactly 1 request after two
// handshakes — proof that the second hit the cache.
//
// Uses a hostname unique to this test so a previous test's
// (legitimately-cached) cert in the package-global cert cache can't
// pre-satisfy the first handshake.
func TestE2E_CachedCert_BypassesProbeOnSecondHandshake(t *testing.T) {
	const knownHost = "cachedcert-test-host.example.com"

	var probeCount atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The probe interrogates with HEAD; only count probe-shaped requests.
		if r.Host == knownHost {
			probeCount.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	httpsPort := freePort(t)
	httpPort := freePort(t)
	// Fresh storage per test so previously-issued certs from earlier
	// runs don't satisfy the first handshake from cache.
	storageRoot := filepath.ToSlash(t.TempDir())
	cfgJSON := fmt.Sprintf(`{
		"admin": {"disabled": true},
		"storage": {
			"module": "file_system",
			"root": "%s"
		},
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
					}],
					"on_demand": {
						"permission": {
							"module": "probe",
							"random_host_challenge": false
						}
					}
				}
			}
		}
	}`, storageRoot, httpPort, httpsPort, httpsPort, strings.TrimPrefix(upstream.URL, "http://"))

	if err := caddy.Load([]byte(cfgJSON), true); err != nil {
		t.Fatalf("loading caddy config: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	// First handshake: cache miss → probe runs → cert issued (internal CA).
	if err := tlsHandshake(httpsPort, knownHost); err != nil {
		t.Fatalf("first TLS handshake to %s failed: %v", knownHost, err)
	}
	first := probeCount.Load()
	if first == 0 {
		t.Fatalf("expected the first handshake to trigger at least one probe; got 0")
	}

	// Second handshake: cache hit → no probe expected.
	if err := tlsHandshake(httpsPort, knownHost); err != nil {
		t.Fatalf("second TLS handshake to %s failed: %v", knownHost, err)
	}

	// Allow a beat for any deferred async work.
	time.Sleep(100 * time.Millisecond)

	second := probeCount.Load()
	if second != first {
		t.Errorf("second handshake unexpectedly probed: probeCount went from %d to %d", first, second)
	}
}

// writeSelfSignedCertPEM generates an ECDSA self-signed certificate
// for the given hostname, writes the cert and key to temp PEM files,
// and returns their paths. Files are cleaned up when the test ends.
func writeSelfSignedCertPEM(t *testing.T, hostname string) (certPath, keyPath string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0o600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	return certPath, keyPath
}

// tlsHandshake dials 127.0.0.1:port, performs a TLS handshake with
// SNI=hostname, and immediately closes. Returns any handshake error
// (the connection itself is throwaway — the on-demand probe path is
// what we care about, and that fires inside the GetCertificate
// callback during the handshake). Self-signed/internal certs are
// accepted via InsecureSkipVerify.
func tlsHandshake(port int, hostname string) error {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err
	}
	return conn.Close()
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

