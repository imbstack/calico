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
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
)

var sameNSPlaceholder = updateprocessors.SameNamespacePlaceholderSelector

func sameNSPolicy() *model.Policy {
	return &model.Policy{
		Selector: "all()",
		InboundRules: []model.Rule{
			{
				Action:                       "allow",
				SrcSelector:                  "(" + sameNSPlaceholder + ") && (has(app))",
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
