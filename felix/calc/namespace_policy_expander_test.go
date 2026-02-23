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

package calc_test

import (
	"strings"
	"testing"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// --- helpers ---

func snslMakePolicy(sel string, inbound, outbound []model.Rule) *model.Policy {
	return &model.Policy{
		Selector:      sel,
		Tier:          "default",
		InboundRules:  inbound,
		OutboundRules: outbound,
	}
}

func snslPolicyKey(name string) model.PolicyKey {
	return model.PolicyKey{Name: name}
}

func snslNSUpdate(name string, labels map[string]string) *proto.NamespaceUpdate {
	return &proto.NamespaceUpdate{
		Id:     &proto.NamespaceID{Name: name},
		Labels: labels,
	}
}

// snslCollector records policy updates received by the expander's consumer callbacks.
type snslCollector struct {
	active  map[model.PolicyKey]*model.Policy
	updates []model.PolicyKey
	deletes []model.PolicyKey
}

func newSNSLCollector() *snslCollector {
	return &snslCollector{active: make(map[model.PolicyKey]*model.Policy)}
}

func (c *snslCollector) onUpdate(u api.Update) bool {
	key := u.Key.(model.PolicyKey)
	if u.Value == nil {
		delete(c.active, key)
		c.deletes = append(c.deletes, key)
	} else {
		c.active[key] = u.Value.(*model.Policy)
		c.updates = append(c.updates, key)
	}
	return false
}

// selContains returns true if all substrings appear in s.
func selContains(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// --- Tests ---

// TestSNSLNonSNSLPolicyPassedThrough verifies that a policy with no SharedNamespaceLabels
// is forwarded unchanged to the ARC receiver.
func TestSNSLNonSNSLPolicyPassedThrough(t *testing.T) {
	arcC := newSNSLCollector()
	metaC := newSNSLCollector()
	exp := calc.NewNamespacePolicyExpander(arcC.onUpdate, metaC.onUpdate)

	policy := snslMakePolicy("all()", nil, nil)
	key := snslPolicyKey("plain-policy")

	exp.OnPolicyUpdateForTest(key, policy)

	if len(arcC.active) != 1 {
		t.Fatalf("expected 1 active policy in ARC, got %d", len(arcC.active))
	}
	if _, ok := arcC.active[key]; !ok {
		t.Errorf("expected key %v in ARC active", key)
	}
	if len(metaC.active) != 0 {
		t.Errorf("expected 0 policies in meta receiver, got %d", len(metaC.active))
	}
}

// TestSNSLPolicyOneNamespace verifies that an SNSL policy for one namespace emits a virtual
// policy with the correct namespace-restricted selector and expanded rule selector.
func TestSNSLPolicyOneNamespace(t *testing.T) {
	arcC := newSNSLCollector()
	metaC := newSNSLCollector()
	exp := calc.NewNamespacePolicyExpander(arcC.onUpdate, metaC.onUpdate)

	// First register namespace "foo".
	exp.OnNamespaceUpdate(snslNSUpdate("foo", map[string]string{
		"kubernetes.io/metadata.name": "foo",
	}))

	// Then add an SNSL policy.
	rule := model.Rule{
		Action:                           "allow",
		OriginalSrcSharedNamespaceLabels: []string{"kubernetes.io/metadata.name"},
	}
	policy := snslMakePolicy("has(projectcalico.org/namespace)", []model.Rule{rule}, nil)
	realKey := snslPolicyKey("allow-within-ns")

	exp.OnPolicyUpdateForTest(realKey, policy)

	// Real policy should NOT be in ARC.
	if _, ok := arcC.active[realKey]; ok {
		t.Errorf("real SNSL policy key should not be in ARC")
	}

	// One virtual policy should be active.
	if len(arcC.active) != 1 {
		t.Fatalf("expected 1 virtual policy in ARC, got %d", len(arcC.active))
	}

	// Find the virtual policy.
	var vp *model.Policy
	var vk model.PolicyKey
	for k, v := range arcC.active {
		vk = k
		vp = v
	}

	// Virtual policy name must differ from real key name (has __snsl__: prefix).
	if vk.Name == realKey.Name {
		t.Errorf("virtual key name %q should differ from real key name", vk.Name)
	}

	// Top-level selector must restrict to namespace "foo".
	if vp.Selector == "" {
		t.Errorf("virtual policy selector should be non-empty")
	}
	if !selContains(vp.Selector, "projectcalico.org/namespace == 'foo'") {
		t.Errorf("virtual policy selector %q should contain namespace restriction", vp.Selector)
	}

	// Inbound rule's SrcSelector must include the namespace label restriction.
	if len(vp.InboundRules) != 1 {
		t.Fatalf("expected 1 inbound rule, got %d", len(vp.InboundRules))
	}
	if !selContains(vp.InboundRules[0].SrcSelector, "pcns.kubernetes.io/metadata.name == 'foo'") {
		t.Errorf("virtual rule SrcSelector %q should contain namespace label restriction",
			vp.InboundRules[0].SrcSelector)
	}

	// Meta receiver should also see the virtual policy (for sorting).
	if _, ok := metaC.active[vk]; !ok {
		t.Errorf("meta receiver should have virtual policy %v", vk)
	}
}

// TestSNSLNamespaceAddAfterPolicy verifies that a virtual policy is emitted when a
// namespace is added after the SNSL policy.
func TestSNSLNamespaceAddAfterPolicy(t *testing.T) {
	arcC := newSNSLCollector()
	metaC := newSNSLCollector()
	exp := calc.NewNamespacePolicyExpander(arcC.onUpdate, metaC.onUpdate)

	// Add SNSL policy first (no namespaces yet).
	rule := model.Rule{
		Action:                           "allow",
		OriginalSrcSharedNamespaceLabels: []string{"kubernetes.io/metadata.name"},
	}
	policy := snslMakePolicy("", []model.Rule{rule}, nil)
	realKey := snslPolicyKey("allow-within-ns")
	exp.OnPolicyUpdateForTest(realKey, policy)

	// No virtual policies yet.
	if len(arcC.active) != 0 {
		t.Fatalf("expected 0 policies before namespace add, got %d", len(arcC.active))
	}

	// Now add namespace.
	exp.OnNamespaceUpdate(snslNSUpdate("bar", map[string]string{
		"kubernetes.io/metadata.name": "bar",
	}))

	// One virtual policy should now be active.
	if len(arcC.active) != 1 {
		t.Fatalf("expected 1 virtual policy after namespace add, got %d", len(arcC.active))
	}
}

// TestSNSLNamespaceLabelUpdate verifies that updating namespace labels re-expands the policy.
func TestSNSLNamespaceLabelUpdate(t *testing.T) {
	arcC := newSNSLCollector()
	metaC := newSNSLCollector()
	exp := calc.NewNamespacePolicyExpander(arcC.onUpdate, metaC.onUpdate)

	exp.OnNamespaceUpdate(snslNSUpdate("ns1", map[string]string{"env": "prod"}))

	rule := model.Rule{
		Action:                           "allow",
		OriginalSrcSharedNamespaceLabels: []string{"env"},
	}
	policy := snslMakePolicy("", []model.Rule{rule}, nil)
	realKey := snslPolicyKey("p1")
	exp.OnPolicyUpdateForTest(realKey, policy)

	// Virtual policy with env==prod.
	if len(arcC.active) != 1 {
		t.Fatalf("expected 1 virtual policy, got %d", len(arcC.active))
	}
	var vp *model.Policy
	for _, v := range arcC.active {
		vp = v
	}
	if !selContains(vp.InboundRules[0].SrcSelector, "pcns.env == 'prod'") {
		t.Errorf("SrcSelector %q should contain pcns.env == 'prod'", vp.InboundRules[0].SrcSelector)
	}

	// Update namespace labels.
	arcC.updates = nil
	exp.OnNamespaceUpdate(snslNSUpdate("ns1", map[string]string{"env": "staging"}))

	// Virtual policy should be updated with new label value.
	if len(arcC.updates) == 0 {
		t.Fatal("expected an update after namespace label change")
	}
	for _, v := range arcC.active {
		vp = v
	}
	if !selContains(vp.InboundRules[0].SrcSelector, "pcns.env == 'staging'") {
		t.Errorf("SrcSelector %q should contain pcns.env == 'staging' after update",
			vp.InboundRules[0].SrcSelector)
	}
}

// TestSNSLNamespaceDelete verifies that the virtual policy is retracted when the namespace
// is deleted.
func TestSNSLNamespaceDelete(t *testing.T) {
	arcC := newSNSLCollector()
	metaC := newSNSLCollector()
	exp := calc.NewNamespacePolicyExpander(arcC.onUpdate, metaC.onUpdate)

	exp.OnNamespaceUpdate(snslNSUpdate("ns1", map[string]string{"kubernetes.io/metadata.name": "ns1"}))

	rule := model.Rule{
		Action:                           "allow",
		OriginalSrcSharedNamespaceLabels: []string{"kubernetes.io/metadata.name"},
	}
	policy := snslMakePolicy("", []model.Rule{rule}, nil)
	realKey := snslPolicyKey("p1")
	exp.OnPolicyUpdateForTest(realKey, policy)

	if len(arcC.active) != 1 {
		t.Fatalf("expected 1 virtual policy, got %d", len(arcC.active))
	}

	// Delete namespace.
	exp.OnNamespaceRemove(types.NamespaceID{Name: "ns1"})

	if len(arcC.active) != 0 {
		t.Errorf("expected 0 virtual policies after namespace delete, got %d", len(arcC.active))
	}
}

// TestSNSLPolicyDelete verifies that all virtual policies are retracted when the real
// SNSL policy is deleted.
func TestSNSLPolicyDelete(t *testing.T) {
	arcC := newSNSLCollector()
	metaC := newSNSLCollector()
	exp := calc.NewNamespacePolicyExpander(arcC.onUpdate, metaC.onUpdate)

	for _, ns := range []string{"a", "b", "c"} {
		exp.OnNamespaceUpdate(snslNSUpdate(ns, map[string]string{"kubernetes.io/metadata.name": ns}))
	}

	rule := model.Rule{
		Action:                           "allow",
		OriginalSrcSharedNamespaceLabels: []string{"kubernetes.io/metadata.name"},
	}
	policy := snslMakePolicy("", []model.Rule{rule}, nil)
	realKey := snslPolicyKey("p1")
	exp.OnPolicyUpdateForTest(realKey, policy)

	if len(arcC.active) != 3 {
		t.Fatalf("expected 3 virtual policies, got %d", len(arcC.active))
	}

	// Delete real policy.
	exp.OnPolicyUpdateForTest(realKey, nil)

	if len(arcC.active) != 0 {
		t.Errorf("expected 0 virtual policies after real policy delete, got %d", len(arcC.active))
	}
}

// TestSNSLMultipleKeys verifies that multiple SharedNamespaceLabels keys are all ANDed.
func TestSNSLMultipleKeys(t *testing.T) {
	arcC := newSNSLCollector()
	metaC := newSNSLCollector()
	exp := calc.NewNamespacePolicyExpander(arcC.onUpdate, metaC.onUpdate)

	exp.OnNamespaceUpdate(snslNSUpdate("ns1", map[string]string{
		"kubernetes.io/metadata.name": "ns1",
		"env":                         "prod",
	}))

	rule := model.Rule{
		Action:                           "allow",
		OriginalSrcSharedNamespaceLabels: []string{"kubernetes.io/metadata.name", "env"},
	}
	policy := snslMakePolicy("", []model.Rule{rule}, nil)
	exp.OnPolicyUpdateForTest(snslPolicyKey("p1"), policy)

	if len(arcC.active) != 1 {
		t.Fatalf("expected 1 virtual policy, got %d", len(arcC.active))
	}
	var vp *model.Policy
	for _, v := range arcC.active {
		vp = v
	}
	sel := vp.InboundRules[0].SrcSelector
	if !selContains(sel, "pcns.kubernetes.io/metadata.name == 'ns1'") ||
		!selContains(sel, "pcns.env == 'prod'") {
		t.Errorf("SrcSelector %q should contain both label restrictions", sel)
	}
}

// TestSNSLMissingLabelImpossibleSelector verifies that a missing label key produces an
// impossible selector (match nothing).
func TestSNSLMissingLabelImpossibleSelector(t *testing.T) {
	arcC := newSNSLCollector()
	metaC := newSNSLCollector()
	exp := calc.NewNamespacePolicyExpander(arcC.onUpdate, metaC.onUpdate)

	// Namespace does NOT have "env" label.
	exp.OnNamespaceUpdate(snslNSUpdate("ns1", map[string]string{
		"kubernetes.io/metadata.name": "ns1",
	}))

	rule := model.Rule{
		Action:                           "allow",
		OriginalSrcSharedNamespaceLabels: []string{"env"}, // missing
	}
	policy := snslMakePolicy("", []model.Rule{rule}, nil)
	exp.OnPolicyUpdateForTest(snslPolicyKey("p1"), policy)

	if len(arcC.active) != 1 {
		t.Fatalf("expected 1 virtual policy, got %d", len(arcC.active))
	}
	var vp *model.Policy
	for _, v := range arcC.active {
		vp = v
	}
	// SrcSelector should be set to the impossible selector.
	if vp.InboundRules[0].SrcSelector != "has(__snsl_never_match__)" {
		t.Errorf("SrcSelector should be impossible selector, got %q",
			vp.InboundRules[0].SrcSelector)
	}
}

// TestSNSLNotSharedNamespaceLabels verifies that NotSharedNamespaceLabels generates a
// NotSrcSelector.
func TestSNSLNotSharedNamespaceLabels(t *testing.T) {
	arcC := newSNSLCollector()
	metaC := newSNSLCollector()
	exp := calc.NewNamespacePolicyExpander(arcC.onUpdate, metaC.onUpdate)

	exp.OnNamespaceUpdate(snslNSUpdate("ns1", map[string]string{
		"kubernetes.io/metadata.name": "ns1",
	}))

	rule := model.Rule{
		Action:                              "allow",
		OriginalSrcNotSharedNamespaceLabels: []string{"kubernetes.io/metadata.name"},
	}
	policy := snslMakePolicy("", []model.Rule{rule}, nil)
	exp.OnPolicyUpdateForTest(snslPolicyKey("p1"), policy)

	if len(arcC.active) != 1 {
		t.Fatalf("expected 1 virtual policy, got %d", len(arcC.active))
	}
	var vp *model.Policy
	for _, v := range arcC.active {
		vp = v
	}
	// NotSrcSelector should be set.
	if !selContains(vp.InboundRules[0].NotSrcSelector, "pcns.kubernetes.io/metadata.name == 'ns1'") {
		t.Errorf("NotSrcSelector %q should contain namespace label restriction",
			vp.InboundRules[0].NotSrcSelector)
	}
	// SrcSelector should be empty (no SharedNamespaceLabels on this rule).
	if vp.InboundRules[0].SrcSelector != "" {
		t.Errorf("SrcSelector should be empty, got %q", vp.InboundRules[0].SrcSelector)
	}
}

// TestSNSLNonSNSLPolicyDelete verifies that deletion of a non-SNSL policy is forwarded to ARC.
func TestSNSLNonSNSLPolicyDelete(t *testing.T) {
	arcC := newSNSLCollector()
	metaC := newSNSLCollector()
	exp := calc.NewNamespacePolicyExpander(arcC.onUpdate, metaC.onUpdate)

	key := snslPolicyKey("plain")
	exp.OnPolicyUpdateForTest(key, snslMakePolicy("all()", nil, nil))

	if len(arcC.active) != 1 {
		t.Fatalf("expected 1 policy before delete")
	}

	exp.OnPolicyUpdateForTest(key, nil)

	if len(arcC.active) != 0 {
		t.Errorf("expected 0 policies after delete, got %d", len(arcC.active))
	}
	if len(arcC.deletes) != 1 || arcC.deletes[0] != key {
		t.Errorf("expected delete event for %v", key)
	}
}
