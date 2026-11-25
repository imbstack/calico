// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package calc

import (
	"fmt"
	"strings"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
	goldmaneproto "github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	v1v "github.com/projectcalico/calico/libcalico-go/lib/validator/v1"
)

var sameNSPlaceholder = updateprocessors.SameNamespacePlaceholderSelector

func sameNSPolicy() *model.Policy {
	return &model.Policy{
		Selector: "all()",
		InboundRules: []model.Rule{
			{
				Action:                       "allow",
				SrcSelector:                  "(" + sameNSPlaceholder + ") && (has(app))",
				OriginalSrcSelector:          "has(app)",
				OriginalSrcNamespaceSelector: v3.SameNamespaceSelector,
			},
			{
				Action:      "allow",
				SrcSelector: "has(other)",
			},
		},
		OutboundRules: []model.Rule{
			{
				Action:                       "allow",
				DstSelector:                  sameNSPlaceholder,
				OriginalDstNamespaceSelector: v3.SameNamespaceSelector,
			},
		},
	}
}

func TestIsSameNamespacePolicy(t *testing.T) {
	gnpKey := model.PolicyKey{Name: "p", Kind: v3.KindGlobalNetworkPolicy}
	sgnpKey := model.PolicyKey{Name: "p", Kind: v3.KindStagedGlobalNetworkPolicy}
	npKey := model.PolicyKey{Name: "p", Namespace: "ns1", Kind: v3.KindNetworkPolicy}

	if !isSameNamespacePolicy(gnpKey, sameNSPolicy()) {
		t.Error("expected GNP with same() rule to be detected")
	}
	if !isSameNamespacePolicy(sgnpKey, sameNSPolicy()) {
		t.Error("expected staged GNP with same() rule to be detected")
	}
	if isSameNamespacePolicy(npKey, sameNSPolicy()) {
		t.Error("namespaced policy kinds should never be treated as same() policies")
	}
	if isSameNamespacePolicy(gnpKey, &model.Policy{InboundRules: []model.Rule{{Action: "allow"}}}) {
		t.Error("policy without same() rules should not be detected")
	}
	if isSameNamespacePolicy(gnpKey, nil) {
		t.Error("nil policy should not be detected")
	}
}

func TestVirtualPolicyKeyRoundTrip(t *testing.T) {
	parent := model.PolicyKey{Name: "p", Kind: v3.KindGlobalNetworkPolicy}
	vk := virtualPolicyKey(parent, "ns1")

	if vk == parent {
		t.Fatal("virtual key should differ from parent")
	}
	if !IsVirtualPolicyKey(vk) {
		t.Error("expected virtual key to be recognised")
	}
	if IsVirtualPolicyKey(parent) {
		t.Error("parent key should not be recognised as virtual")
	}
	if got := ParentPolicyKey(vk); got != parent {
		t.Errorf("ParentPolicyKey(%v) = %v, want %v", vk, got, parent)
	}

	np := model.PolicyKey{Name: "p", Namespace: "ns1", Kind: v3.KindNetworkPolicy}
	if IsVirtualPolicyKey(np) {
		t.Error("real namespaced policy key should not be recognised as virtual")
	}
	if got := ParentPolicyKey(np); got != np {
		t.Errorf("ParentPolicyKey should leave non-virtual keys unchanged, got %v", got)
	}
}

func TestExpandForNamespace(t *testing.T) {
	policy := sameNSPolicy()
	expanded := expandForNamespace(policy, "ns1")

	if got, want := expanded.InboundRules[0].SrcSelector, "(projectcalico.org/namespace == 'ns1') && (has(app))"; got != want {
		t.Errorf("inbound SrcSelector = %q, want %q", got, want)
	}
	if got, want := expanded.InboundRules[1].SrcSelector, "has(other)"; got != want {
		t.Errorf("non-same() rule changed: got %q, want %q", got, want)
	}
	if got, want := expanded.OutboundRules[0].DstSelector, "projectcalico.org/namespace == 'ns1'"; got != want {
		t.Errorf("outbound DstSelector = %q, want %q", got, want)
	}
	if expanded.Selector != policy.Selector {
		t.Errorf("policy selector changed: got %q, want %q", expanded.Selector, policy.Selector)
	}

	// The parent must not be modified; ARC expands it again for each namespace.
	if got := policy.InboundRules[0].SrcSelector; got != "("+sameNSPlaceholder+") && (has(app))" {
		t.Errorf("parent policy was modified: %q", got)
	}
}

// TestExpandForNamespace_OnlyRewritesSameTerm verifies that expansion only touches the namespace
// term introduced for same().  A user-written selector that happens to match the placeholder
// namespace must keep its meaning, whether it is in a non-same() rule, in the non-same() side of
// a same() rule, in a NotSelector, or inside the same() rule's own endpoint selector.
func TestExpandForNamespace_OnlyRewritesSameTerm(t *testing.T) {
	gnp := v3.NewGlobalNetworkPolicy()
	gnp.Name = "p"
	gnp.Spec.Selector = "all()"
	gnp.Spec.Ingress = []v3.Rule{
		{
			// same() rule whose own selector mentions the placeholder namespace.
			Action: v3.Allow,
			Source: v3.EntityRule{NamespaceSelector: v3.SameNamespaceSelector, Selector: sameNSPlaceholder},
			// Destination side doesn't use same().
			Destination: v3.EntityRule{Selector: sameNSPlaceholder, NotSelector: sameNSPlaceholder},
		},
		{
			// A separate rule that doesn't use same() at all.
			Action: v3.Deny,
			Source: v3.EntityRule{Selector: sameNSPlaceholder, NotSelector: sameNSPlaceholder},
		},
	}
	v1Value, err := updateprocessors.ConvertGlobalNetworkPolicyV3ToV1Value(gnp)
	if err != nil {
		t.Fatalf("update processor failed: %v", err)
	}
	policy := v1Value.(*model.Policy)
	expanded := expandForNamespace(policy, "ns1")

	r0, r1 := expanded.InboundRules[0], expanded.InboundRules[1]
	if got, want := r0.SrcSelector, "(projectcalico.org/namespace == 'ns1') && ("+sameNSPlaceholder+")"; got != want {
		t.Errorf("same() SrcSelector = %q, want %q", got, want)
	}
	for name, pair := range map[string][2]string{
		"same() rule DstSelector":    {r0.DstSelector, policy.InboundRules[0].DstSelector},
		"same() rule NotDstSelector": {r0.NotDstSelector, policy.InboundRules[0].NotDstSelector},
		"other rule SrcSelector":     {r1.SrcSelector, policy.InboundRules[1].SrcSelector},
		"other rule NotSrcSelector":  {r1.NotSrcSelector, policy.InboundRules[1].NotSrcSelector},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s changed: got %q, want %q", name, pair[0], pair[1])
		}
		if !strings.Contains(pair[0], updateprocessors.SameNamespacePlaceholder) {
			t.Errorf("%s lost the user's placeholder-namespace match: %q", name, pair[0])
		}
	}

	// The ns1 copy of the same() rule must still require the user's selector, so it matches
	// nothing in ns1.
	sel, err := selector.Parse(r0.SrcSelector)
	if err != nil {
		t.Fatalf("failed to parse %q: %v", r0.SrcSelector, err)
	}
	if sel.Evaluate(map[string]string{v3.LabelNamespace: "ns1"}) {
		t.Errorf("expanded selector %q should not match endpoints in ns1", r0.SrcSelector)
	}
}

// TestSameNamespace_UpdateProcessorToARC covers the whole path that same() relies on.  The ARC
// re-composes same() selectors from the rule's Original* fields, so those must survive
// serialisation (as through Typha) and Felix's validation, and re-composition must agree with the
// update processor's own composition.  If it doesn't, allow rules match the wrong endpoints and,
// worse, deny rules may not match.
func TestSameNamespace_UpdateProcessorToARC(t *testing.T) {
	gnp := v3.NewGlobalNetworkPolicy()
	gnp.Name = sameNSTestPolicyKey.Name
	gnp.Spec.Selector = "has(app)"
	gnp.Spec.Ingress = []v3.Rule{
		{
			Action: v3.Allow,
			Source: v3.EntityRule{NamespaceSelector: v3.SameNamespaceSelector, Selector: "app == 'x'"},
		},
		{
			// Service account names go through a parse/re-serialise step in the update processor.
			Action: v3.Allow,
			Source: v3.EntityRule{
				NamespaceSelector: v3.SameNamespaceSelector,
				ServiceAccounts:   &v3.ServiceAccountMatch{Names: []string{"sa1"}},
			},
		},
	}
	gnp.Spec.Egress = []v3.Rule{
		{Action: v3.Deny, Destination: v3.EntityRule{NamespaceSelector: v3.SameNamespaceSelector}},
	}

	v1Value, err := updateprocessors.ConvertGlobalNetworkPolicyV3ToV1Value(gnp)
	if err != nil {
		t.Fatalf("update processor failed: %v", err)
	}
	raw, err := model.SerializeValue(&model.KVPair{Key: sameNSTestPolicyKey, Value: v1Value})
	if err != nil {
		t.Fatalf("failed to serialise policy: %v", err)
	}
	parsed, err := model.ParseValue(sameNSTestPolicyKey, raw)
	if err != nil {
		t.Fatalf("failed to parse policy: %v", err)
	}
	policy := parsed.(*model.Policy)
	// Felix's validation filter treats a policy that fails v1 validation as deleted.
	if err := v1v.Validate(*policy); err != nil {
		t.Fatalf("policy failed Felix validation: %v", err)
	}

	arc, scanner, _ := createSameNSARC()
	updatePolicy(arc, sameNSTestPolicyKey, policy)
	expectActiveKeys(t, scanner, sameNSTestPolicyKey,
		virtualPolicyKey(sameNSTestPolicyKey, "ns1"), virtualPolicyKey(sameNSTestPolicyKey, "ns2"))

	nsLabels := func(ns string, extra ...string) map[string]string {
		l := map[string]string{v3.LabelNamespace: ns}
		for i := 0; i < len(extra); i += 2 {
			l[extra[i]] = extra[i+1]
		}
		return l
	}
	hostEndpointLabels := map[string]string{"app": "x"}

	ns1Copy := scanner.activePolicies[virtualPolicyKey(sameNSTestPolicyKey, "ns1")]
	parentCopy := scanner.activePolicies[sameNSTestPolicyKey]
	for _, tc := range []struct {
		name        string
		ns1Sel      string
		parentSel   string
		shouldMatch map[string]string
		shouldNot   []map[string]string
	}{
		{
			name:        "ingress selector",
			ns1Sel:      ns1Copy.InboundRules[0].SrcSelector,
			parentSel:   parentCopy.InboundRules[0].SrcSelector,
			shouldMatch: nsLabels("ns1", "app", "x"),
			shouldNot:   []map[string]string{nsLabels("ns2", "app", "x"), nsLabels("ns1", "app", "y")},
		},
		{
			name:        "ingress service account",
			ns1Sel:      ns1Copy.InboundRules[1].SrcSelector,
			parentSel:   parentCopy.InboundRules[1].SrcSelector,
			shouldMatch: nsLabels("ns1", v3.LabelServiceAccount, "sa1"),
			shouldNot:   []map[string]string{nsLabels("ns2", v3.LabelServiceAccount, "sa1"), nsLabels("ns1")},
		},
		{
			name:        "egress deny",
			ns1Sel:      ns1Copy.OutboundRules[0].DstSelector,
			parentSel:   parentCopy.OutboundRules[0].DstSelector,
			shouldMatch: nsLabels("ns1"),
			shouldNot:   []map[string]string{nsLabels("ns2"), hostEndpointLabels},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Re-composing with the placeholder namespace must reproduce the update processor's
			// selector exactly, i.e. the two compositions agree.
			if got := strings.ReplaceAll(tc.ns1Sel, "'ns1'", "'"+updateprocessors.SameNamespacePlaceholder+"'"); got != tc.parentSel {
				t.Errorf("re-composed selector %q doesn't match update processor's %q", tc.ns1Sel, tc.parentSel)
			}
			if strings.Contains(tc.ns1Sel, updateprocessors.SameNamespacePlaceholder) {
				t.Fatalf("placeholder not replaced in ns1 copy: %q", tc.ns1Sel)
			}
			sel, err := selector.Parse(tc.ns1Sel)
			if err != nil {
				t.Fatalf("failed to parse ns1 copy selector %q: %v", tc.ns1Sel, err)
			}
			if !sel.Evaluate(tc.shouldMatch) {
				t.Errorf("ns1 copy selector %q should match %v", tc.ns1Sel, tc.shouldMatch)
			}
			for _, l := range tc.shouldNot {
				if sel.Evaluate(l) {
					t.Errorf("ns1 copy selector %q should not match %v", tc.ns1Sel, l)
				}
			}

			// The unexpanded policy used for host endpoints must match nothing.
			parentSel, err := selector.Parse(tc.parentSel)
			if err != nil {
				t.Fatalf("failed to parse unexpanded selector %q: %v", tc.parentSel, err)
			}
			if parentSel.Evaluate(tc.shouldMatch) {
				t.Errorf("unexpanded selector %q should not match %v", tc.parentSel, tc.shouldMatch)
			}
		})
	}
}

func TestPolicyLookupsCache_SameNamespaceCopyReportedAsParent(t *testing.T) {
	pc := NewPolicyLookupsCache()
	parent := model.PolicyKey{Name: "same-ns", Kind: v3.KindGlobalNetworkPolicy}
	copyKey := virtualPolicyKey(parent, "ns1")
	pc.OnPolicyActive(copyKey, &model.Policy{
		Tier:         "default",
		InboundRules: []model.Rule{{Action: "allow"}},
	})

	// The dataplane computes the prefix from the copy's own ID.
	prefixStr := rules.CalculateNFLOGPrefixStr(rules.RuleActionAllow, rules.RuleOwnerTypePolicy, rules.RuleDirIngress, 0,
		&types.PolicyID{Name: copyKey.Name, Namespace: copyKey.Namespace, Kind: copyKey.Kind})
	var prefix [64]byte
	copy(prefix[:], prefixStr)

	rid := pc.GetRuleIDFromNFLOGPrefix(prefix)
	if rid == nil {
		t.Fatalf("no RuleID for prefix %q", prefixStr)
	}
	want := PolicyID{Kind: v3.KindGlobalNetworkPolicy, Name: "same-ns"}
	if rid.PolicyID != want {
		t.Errorf("RuleID policy = %+v, want parent %+v", rid.PolicyID, want)
	}
	if got, want := rid.GetFlowLogPolicyName(), "default|gnp:same-ns|allow"; got != want {
		t.Errorf("flow log policy name = %q, want %q", got, want)
	}

	// goldmane must accept the hit; it rejects global policies that have a namespace.
	hit, err := goldmaneproto.HitFromString(fmt.Sprintf("0|%s|%s", rid.GetFlowLogPolicyName(), rid.IndexStr))
	if err != nil {
		t.Fatalf("goldmane failed to parse policy hit: %v", err)
	}
	if _, err := hit.ToString(); err != nil {
		t.Errorf("goldmane rejected policy hit: %v", err)
	}

	pc.OnPolicyInactive(copyKey)
	if rid := pc.GetRuleIDFromNFLOGPrefix(prefix); rid != nil {
		t.Errorf("prefix still registered after copy became inactive: %v", rid)
	}
}

func TestEndpointLookupsCache_SameNamespaceCopyReportedAsParent(t *testing.T) {
	ec := NewEndpointLookupsCache()
	parent := model.PolicyKey{Name: "same-ns", Kind: v3.KindGlobalNetworkPolicy}
	copyKey := virtualPolicyKey(parent, "ns1")
	meta := ExtractPolicyMetadata(&model.Policy{Tier: "default", Types: []string{"ingress", "egress"}})

	epKey := model.WorkloadEndpointKey{Hostname: "host1", OrchestratorID: "k8s", WorkloadID: "ns1/a", EndpointID: "eth0"}
	ed := ec.CreateLocalEndpointData(epKey, &model.WorkloadEndpoint{}, []TierInfo{{
		Name:            "default",
		Valid:           true,
		OrderedPolicies: []PolKV{{Key: copyKey, Value: &meta}},
	}})

	want := PolicyID{Kind: v3.KindGlobalNetworkPolicy, Name: "same-ns"}
	for dir, md := range map[string]*MatchData{"ingress": ed.Ingress, "egress": ed.Egress} {
		if _, ok := md.PolicyMatches[want]; !ok || len(md.PolicyMatches) != 1 {
			t.Errorf("%s policy matches = %v, want only parent %+v", dir, md.PolicyMatches, want)
		}
		if got := md.TierData["default"].TierDefaultActionRuleID.PolicyID; got != want {
			t.Errorf("%s tier default action RuleID policy = %+v, want parent %+v", dir, got, want)
		}
	}
}
