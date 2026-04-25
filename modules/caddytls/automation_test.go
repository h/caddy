package caddytls

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestAutomationPolicyMakeCertMagicConfigImplicitTailscaleManagersOnly(t *testing.T) {
	ap := AutomationPolicy{
		Managers: []certmagic.Manager{Tailscale{}},
		subjects: []string{"test-node.example.ts.net"},
	}

	cfg, err := ap.makeCertMagicConfig(&TLS{
		logger: zap.NewNop(),
	}, nil, &certmagic.FileStorage{Path: t.TempDir()})
	if err != nil {
		t.Fatalf("making certmagic config: %v", err)
	}
	if cfg.OnDemand == nil {
		t.Fatal("expected on-demand config to be set")
	}
	if len(cfg.Issuers) != 0 {
		t.Fatalf("expected no issuers for tailscale-managed ts.net policy, got %d", len(cfg.Issuers))
	}
}

func TestAutomationPolicyImplicitTailscaleManagersOnlyCatchAll(t *testing.T) {
	ap := AutomationPolicy{
		Managers: []certmagic.Manager{Tailscale{}},
	}
	if ap.implicitTailscaleManagersOnly() {
		t.Fatal("expected catch-all manager policy to remain outside tailscale-only special case")
	}
}

func TestApplyOnDemandPermissionDefault_InjectsReverseProxy(t *testing.T) {
	tlsApp := &TLS{
		Automation: &AutomationConfig{
			Policies: []*AutomationPolicy{{OnDemand: true}},
		},
	}
	tlsApp.applyOnDemandPermissionDefault()

	if tlsApp.Automation.OnDemand == nil {
		t.Fatal("expected OnDemand config to be created")
	}
	got := string(tlsApp.Automation.OnDemand.PermissionRaw)
	if !strings.Contains(got, `"module":"reverse_proxy"`) {
		t.Errorf("expected default permission module to be reverse_proxy; got PermissionRaw=%s", got)
	}
}

func TestApplyOnDemandPermissionDefault_RespectsExplicitPermission(t *testing.T) {
	existing := json.RawMessage(`{"module":"http","endpoint":"https://example.com/check"}`)
	tlsApp := &TLS{
		Automation: &AutomationConfig{
			OnDemand: &OnDemandConfig{PermissionRaw: existing},
			Policies: []*AutomationPolicy{{OnDemand: true}},
		},
	}
	tlsApp.applyOnDemandPermissionDefault()

	if string(tlsApp.Automation.OnDemand.PermissionRaw) != string(existing) {
		t.Errorf("explicit permission module was overwritten: got %s",
			string(tlsApp.Automation.OnDemand.PermissionRaw))
	}
}

func TestApplyOnDemandPermissionDefault_RespectsLegacyAsk(t *testing.T) {
	tlsApp := &TLS{
		Automation: &AutomationConfig{
			OnDemand: &OnDemandConfig{Ask: "https://example.com/check"},
			Policies: []*AutomationPolicy{{OnDemand: true}},
		},
	}
	tlsApp.applyOnDemandPermissionDefault()

	if tlsApp.Automation.OnDemand.PermissionRaw != nil {
		t.Errorf("default should not override legacy 'ask'; got PermissionRaw=%s",
			string(tlsApp.Automation.OnDemand.PermissionRaw))
	}
}

func TestApplyOnDemandPermissionDefault_NoOpWithoutOnDemandPolicy(t *testing.T) {
	tlsApp := &TLS{
		Automation: &AutomationConfig{
			Policies: []*AutomationPolicy{{OnDemand: false}},
		},
	}
	tlsApp.applyOnDemandPermissionDefault()

	if tlsApp.Automation.OnDemand != nil {
		t.Errorf("expected OnDemand config to remain nil when no policy enables it; got %+v",
			tlsApp.Automation.OnDemand)
	}
}
