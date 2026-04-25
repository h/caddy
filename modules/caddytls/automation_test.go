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

func TestApplyOnDemandPermissionDefault_InjectsForCatchAllPolicy(t *testing.T) {
	// No SubjectsRaw: catch-all policy. The existing safety check would
	// have errored without a permission module; we now auto-inject.
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
	if !strings.Contains(got, `"module":"route_probe"`) {
		t.Errorf("expected default permission module to be route_probe; got PermissionRaw=%s", got)
	}
}

func TestApplyOnDemandPermissionDefault_InjectsForWildcardPolicy(t *testing.T) {
	tlsApp := &TLS{
		Automation: &AutomationConfig{
			Policies: []*AutomationPolicy{{
				OnDemand:    true,
				SubjectsRaw: []string{"*.example.com"},
			}},
		},
	}
	tlsApp.applyOnDemandPermissionDefault()

	if tlsApp.Automation.OnDemand == nil ||
		!strings.Contains(string(tlsApp.Automation.OnDemand.PermissionRaw), `"module":"route_probe"`) {
		t.Errorf("expected route_probe default for wildcard policy; got %+v", tlsApp.Automation.OnDemand)
	}
}

func TestApplyOnDemandPermissionDefault_DoesNotInjectForExplicitSubject(t *testing.T) {
	// Explicit-subject on-demand policies were never gated by the
	// missing-permission safety check, so we shouldn't auto-inject for
	// them. The existing behavior (no permission module, no probe) is
	// preserved.
	tlsApp := &TLS{
		Automation: &AutomationConfig{
			Policies: []*AutomationPolicy{{
				OnDemand:    true,
				SubjectsRaw: []string{"example.com", "foo.example.com"},
			}},
		},
	}
	tlsApp.applyOnDemandPermissionDefault()

	if tlsApp.Automation.OnDemand != nil {
		t.Errorf("expected no auto-injection for explicit-subject policy; got %+v",
			tlsApp.Automation.OnDemand)
	}
}

func TestApplyOnDemandPermissionDefault_InjectsWhenAnyPolicyIsWildcard(t *testing.T) {
	// Mix of explicit and wildcard policies — any wildcard triggers injection.
	tlsApp := &TLS{
		Automation: &AutomationConfig{
			Policies: []*AutomationPolicy{
				{OnDemand: true, SubjectsRaw: []string{"explicit.example.com"}},
				{OnDemand: true, SubjectsRaw: []string{"*.wild.example.com"}},
			},
		},
	}
	tlsApp.applyOnDemandPermissionDefault()

	if tlsApp.Automation.OnDemand == nil ||
		!strings.Contains(string(tlsApp.Automation.OnDemand.PermissionRaw), `"module":"route_probe"`) {
		t.Errorf("expected route_probe default when at least one policy is wildcard; got %+v",
			tlsApp.Automation.OnDemand)
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
