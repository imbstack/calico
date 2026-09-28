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
	"slices"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// testPolicyMatchListener records calls to the PolicyMatchListener interface.
type testPolicyMatchListener struct {
	policyMatches              []policyMatchEvent
	policyMatchStops           []policyMatchEvent
	computedSelectorMatches    []computedSelectorMatchEvent
	computedSelectorMatchStops []computedSelectorMatchEvent
}

type policyMatchEvent struct {
	PolicyKey   model.PolicyKey
	EndpointKey model.EndpointKey
}

type computedSelectorMatchEvent struct {
	Selector    string
	EndpointKey model.EndpointKey
}

func (t *testPolicyMatchListener) OnPolicyMatch(policyKey model.PolicyKey, endpointKey model.EndpointKey) {
	t.policyMatches = append(t.policyMatches, policyMatchEvent{policyKey, endpointKey})
}

func (t *testPolicyMatchListener) OnPolicyMatchStopped(policyKey model.PolicyKey, endpointKey model.EndpointKey) {
	t.policyMatchStops = append(t.policyMatchStops, policyMatchEvent{policyKey, endpointKey})
}

func (t *testPolicyMatchListener) OnComputedSelectorMatch(cs string, endpointKey model.EndpointKey) {
	t.computedSelectorMatches = append(t.computedSelectorMatches, computedSelectorMatchEvent{cs, endpointKey})
}

func (t *testPolicyMatchListener) OnComputedSelectorMatchStopped(cs string, endpointKey model.EndpointKey) {
	t.computedSelectorMatchStops = append(t.computedSelectorMatchStops, computedSelectorMatchEvent{cs, endpointKey})
}

// noopRuleScanner satisfies the ruleScanner interface required by ActiveRulesCalculator.
type noopRuleScanner struct{}

func (n *noopRuleScanner) OnPolicyActive(model.PolicyKey, *model.Policy)              {}
func (n *noopRuleScanner) OnPolicyInactive(model.PolicyKey)                           {}
func (n *noopRuleScanner) OnProfileActive(model.ProfileRulesKey, *model.ProfileRules) {}
func (n *noopRuleScanner) OnProfileInactive(model.ProfileRulesKey)                    {}

func createARC() (*ActiveRulesCalculator, *testPolicyMatchListener) {
	arc := NewActiveRulesCalculator()
	arc.RuleScanner = &noopRuleScanner{}
	listener := &testPolicyMatchListener{}
	arc.RegisterPolicyMatchListener(listener)
	return arc, listener
}

func addEndpoint(arc *ActiveRulesCalculator, key model.WorkloadEndpointKey, labels map[string]string) {
	arc.OnUpdate(api.Update{
		KVPair: model.KVPair{
			Key: key,
			Value: &model.WorkloadEndpoint{
				Labels: uniquelabels.Make(labels),
			},
		},
	})
}

func deleteEndpoint(arc *ActiveRulesCalculator, key model.WorkloadEndpointKey) {
	arc.OnUpdate(api.Update{
		KVPair: model.KVPair{
			Key:   key,
			Value: nil,
		},
	})
}

func TestARC_ComputedSelector_MatchOnEndpointAdd(t *testing.T) {
	arc, listener := createARC()

	arc.AddExtraComputedSelector("has(foo)")

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	addEndpoint(arc, epKey, map[string]string{"foo": "bar"})

	if len(listener.computedSelectorMatches) != 1 {
		t.Fatalf("expected 1 computed selector match, got %d", len(listener.computedSelectorMatches))
	}
	ev := listener.computedSelectorMatches[0]
	if ev.Selector != "has(foo)" {
		t.Errorf("expected selector %q, got %q", "has(foo)", ev.Selector)
	}
	if ev.EndpointKey != epKey {
		t.Errorf("expected endpoint key %v, got %v", epKey, ev.EndpointKey)
	}
}

func TestARC_ComputedSelector_MatchStoppedOnEndpointRemove(t *testing.T) {
	arc, listener := createARC()

	arc.AddExtraComputedSelector("has(foo)")

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	addEndpoint(arc, epKey, map[string]string{"foo": "bar"})

	deleteEndpoint(arc, epKey)

	if len(listener.computedSelectorMatchStops) != 1 {
		t.Fatalf("expected 1 computed selector match stop, got %d", len(listener.computedSelectorMatchStops))
	}
	ev := listener.computedSelectorMatchStops[0]
	if ev.Selector != "has(foo)" {
		t.Errorf("expected selector %q, got %q", "has(foo)", ev.Selector)
	}
	if ev.EndpointKey != epKey {
		t.Errorf("expected endpoint key %v, got %v", epKey, ev.EndpointKey)
	}
}

func TestARC_ComputedSelector_NoMatchForNonMatchingEndpoint(t *testing.T) {
	arc, listener := createARC()

	arc.AddExtraComputedSelector("has(foo)")

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	// Endpoint does NOT have the "foo" label.
	addEndpoint(arc, epKey, map[string]string{"bar": "baz"})

	if len(listener.computedSelectorMatches) != 0 {
		t.Errorf("expected no computed selector matches, got %d", len(listener.computedSelectorMatches))
	}
	if len(listener.computedSelectorMatchStops) != 0 {
		t.Errorf("expected no computed selector match stops, got %d", len(listener.computedSelectorMatchStops))
	}
}

func TestARC_RemoveComputedSelector(t *testing.T) {
	arc, listener := createARC()

	arc.AddExtraComputedSelector("has(foo)")

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	addEndpoint(arc, epKey, map[string]string{"foo": "bar"})

	if len(listener.computedSelectorMatches) != 1 {
		t.Fatalf("expected 1 match after adding endpoint, got %d", len(listener.computedSelectorMatches))
	}

	// Remove the computed selector — should fire match-stopped.
	arc.RemoveExtraComputedSelector("has(foo)")

	if len(listener.computedSelectorMatchStops) != 1 {
		t.Fatalf("expected 1 match stop after removing selector, got %d", len(listener.computedSelectorMatchStops))
	}

	// Reset events.
	listener.computedSelectorMatches = nil
	listener.computedSelectorMatchStops = nil

	// Add another matching endpoint — no further events since selector is removed.
	epKey2 := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl2",
		EndpointID:     "ep2",
	}
	addEndpoint(arc, epKey2, map[string]string{"foo": "baz"})

	if len(listener.computedSelectorMatches) != 0 {
		t.Errorf("expected no matches after selector removed, got %d", len(listener.computedSelectorMatches))
	}
	if len(listener.computedSelectorMatchStops) != 0 {
		t.Errorf("expected no match stops after selector removed, got %d", len(listener.computedSelectorMatchStops))
	}
}

func TestARC_ComputedSelector_DoesNotTriggerPolicyCallbacks(t *testing.T) {
	arc, listener := createARC()

	arc.AddExtraComputedSelector("has(foo)")

	epKey := model.WorkloadEndpointKey{
		Hostname:       "host1",
		OrchestratorID: "orch",
		WorkloadID:     "wl1",
		EndpointID:     "ep1",
	}
	addEndpoint(arc, epKey, map[string]string{"foo": "bar"})

	// Computed selector match should NOT produce policy callbacks.
	if len(listener.policyMatches) != 0 {
		t.Errorf("expected no policy matches, got %d", len(listener.policyMatches))
	}
	if len(listener.policyMatchStops) != 0 {
		t.Errorf("expected no policy match stops, got %d", len(listener.policyMatchStops))
	}

	// policyIDToEndpointKeys should be empty — computed selectors don't create policy entries.
	if arc.policyIDToEndpointKeys.Len() != 0 {
		t.Errorf("expected policyIDToEndpointKeys to be empty, got len=%d", arc.policyIDToEndpointKeys.Len())
	}
}

// recordingRuleScanner records the policies that the ARC has marked active.
type recordingRuleScanner struct {
	activePolicies map[model.PolicyKey]*model.Policy
}

func (r *recordingRuleScanner) OnPolicyActive(key model.PolicyKey, policy *model.Policy) {
	r.activePolicies[key] = policy
}
func (r *recordingRuleScanner) OnPolicyInactive(key model.PolicyKey) {
	delete(r.activePolicies, key)
}
func (r *recordingRuleScanner) OnProfileActive(model.ProfileRulesKey, *model.ProfileRules) {}
func (r *recordingRuleScanner) OnProfileInactive(model.ProfileRulesKey)                    {}

func (r *recordingRuleScanner) activeKeys() []model.PolicyKey {
	var keys []model.PolicyKey
	for k := range r.activePolicies {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b model.PolicyKey) int {
		if a.Namespace < b.Namespace {
			return -1
		} else if a.Namespace > b.Namespace {
			return 1
		}
		return 0
	})
	return keys
}

var sameNSTestPolicyKey = model.PolicyKey{Name: "same-ns", Kind: v3.KindGlobalNetworkPolicy}

func sameNSTestWepKey(ns, pod string) model.WorkloadEndpointKey {
	return model.WorkloadEndpointKey{Hostname: "host1", OrchestratorID: "k8s", WorkloadID: ns + "/" + pod, EndpointID: "eth0"}
}

var sameNSTestHepKey = model.HostEndpointKey{Hostname: "host1", EndpointID: "eth0"}

// createSameNSARC returns an ARC with local endpoints in ns1 (two), ns2 (one) and a host endpoint.
func createSameNSARC() (*ActiveRulesCalculator, *recordingRuleScanner, *testPolicyMatchListener) {
	arc, listener := createARC()
	scanner := &recordingRuleScanner{activePolicies: map[model.PolicyKey]*model.Policy{}}
	arc.RuleScanner = scanner
	labels := map[string]string{"app": "x"}
	addEndpoint(arc, sameNSTestWepKey("ns1", "a"), labels)
	addEndpoint(arc, sameNSTestWepKey("ns1", "b"), labels)
	addEndpoint(arc, sameNSTestWepKey("ns2", "c"), labels)
	arc.OnUpdate(api.Update{KVPair: model.KVPair{
		Key:   sameNSTestHepKey,
		Value: &model.HostEndpoint{Labels: uniquelabels.Make(labels)},
	}})
	return arc, scanner, listener
}

func updatePolicy(arc *ActiveRulesCalculator, key model.PolicyKey, policy *model.Policy) {
	u := api.Update{KVPair: model.KVPair{Key: key}}
	if policy != nil {
		u.Value = policy
	}
	arc.OnUpdate(u)
}

func expectActiveKeys(t *testing.T, scanner *recordingRuleScanner, want ...model.PolicyKey) {
	t.Helper()
	if got := scanner.activeKeys(); !slices.Equal(got, want) {
		t.Fatalf("active policies = %v, want %v", got, want)
	}
}

func TestARC_SameNamespace_CopyPerNamespace(t *testing.T) {
	arc, scanner, listener := createSameNSARC()
	updatePolicy(arc, sameNSTestPolicyKey, sameNSPolicy())

	ns1Key := virtualPolicyKey(sameNSTestPolicyKey, "ns1")
	ns2Key := virtualPolicyKey(sameNSTestPolicyKey, "ns2")
	// The host endpoint uses the real key.
	expectActiveKeys(t, scanner, sameNSTestPolicyKey, ns1Key, ns2Key)

	if got, want := scanner.activePolicies[ns1Key].InboundRules[0].SrcSelector,
		"(projectcalico.org/namespace == 'ns1') && (has(app))"; got != want {
		t.Errorf("ns1 copy SrcSelector = %q, want %q", got, want)
	}
	if got, want := scanner.activePolicies[sameNSTestPolicyKey].InboundRules[0].SrcSelector,
		"("+sameNSPlaceholder+") && (has(app))"; got != want {
		t.Errorf("host endpoint copy should be unexpanded: got %q, want %q", got, want)
	}

	// Each endpoint is reported against the key for its namespace.
	wantMatches := map[model.EndpointKey]model.PolicyKey{
		sameNSTestWepKey("ns1", "a"): ns1Key,
		sameNSTestWepKey("ns1", "b"): ns1Key,
		sameNSTestWepKey("ns2", "c"): ns2Key,
		sameNSTestHepKey:             sameNSTestPolicyKey,
	}
	if len(listener.policyMatches) != len(wantMatches) {
		t.Fatalf("got %d policy matches, want %d: %v", len(listener.policyMatches), len(wantMatches), listener.policyMatches)
	}
	for _, m := range listener.policyMatches {
		if wantMatches[m.EndpointKey] != m.PolicyKey {
			t.Errorf("endpoint %v matched %v, want %v", m.EndpointKey, m.PolicyKey, wantMatches[m.EndpointKey])
		}
	}
}

func TestARC_SameNamespace_LastEndpointInNamespaceRemoved(t *testing.T) {
	arc, scanner, _ := createSameNSARC()
	updatePolicy(arc, sameNSTestPolicyKey, sameNSPolicy())

	deleteEndpoint(arc, sameNSTestWepKey("ns1", "a"))
	expectActiveKeys(t, scanner, sameNSTestPolicyKey,
		virtualPolicyKey(sameNSTestPolicyKey, "ns1"), virtualPolicyKey(sameNSTestPolicyKey, "ns2"))

	deleteEndpoint(arc, sameNSTestWepKey("ns2", "c"))
	expectActiveKeys(t, scanner, sameNSTestPolicyKey, virtualPolicyKey(sameNSTestPolicyKey, "ns1"))
	if arc.parentToVirtualKeys.Contains(sameNSTestPolicyKey, virtualPolicyKey(sameNSTestPolicyKey, "ns2")) {
		t.Error("ns2 copy still tracked after its last endpoint was removed")
	}
}

func TestARC_SameNamespace_ParentUpdateResendsCopies(t *testing.T) {
	arc, scanner, _ := createSameNSARC()
	updatePolicy(arc, sameNSTestPolicyKey, sameNSPolicy())

	updated := sameNSPolicy()
	updated.InboundRules[1].SrcSelector = "has(changed)"
	updatePolicy(arc, sameNSTestPolicyKey, updated)

	for _, ns := range []string{"ns1", "ns2"} {
		copyPol := scanner.activePolicies[virtualPolicyKey(sameNSTestPolicyKey, ns)]
		if got := copyPol.InboundRules[1].SrcSelector; got != "has(changed)" {
			t.Errorf("%s copy not updated: SrcSelector = %q", ns, got)
		}
	}
}

func TestARC_SameNamespace_SwitchToPlainAndBack(t *testing.T) {
	arc, scanner, listener := createSameNSARC()
	updatePolicy(arc, sameNSTestPolicyKey, sameNSPolicy())

	plain := &model.Policy{Selector: "all()", InboundRules: []model.Rule{{Action: "allow"}}}
	updatePolicy(arc, sameNSTestPolicyKey, plain)
	expectActiveKeys(t, scanner, sameNSTestPolicyKey)
	if n := countMatches(arc, sameNSTestPolicyKey); n != 4 {
		t.Errorf("after switch to plain, real key has %d matches, want 4", n)
	}
	if arc.parentToVirtualKeys.Len() != 0 {
		t.Errorf("virtual keys still tracked after switch to plain")
	}

	updatePolicy(arc, sameNSTestPolicyKey, sameNSPolicy())
	expectActiveKeys(t, scanner, sameNSTestPolicyKey,
		virtualPolicyKey(sameNSTestPolicyKey, "ns1"), virtualPolicyKey(sameNSTestPolicyKey, "ns2"))
	if n := countMatches(arc, sameNSTestPolicyKey); n != 1 {
		t.Errorf("after switch back, real key has %d matches, want 1 (the host endpoint)", n)
	}

	// Every match that started was stopped under the same key.
	started := map[policyMatchEvent]int{}
	for _, m := range listener.policyMatches {
		started[m]++
	}
	for _, m := range listener.policyMatchStops {
		started[m]--
		if started[m] < 0 {
			t.Errorf("match %v stopped without being started", m)
		}
	}
}

func TestARC_SameNamespace_DeleteCleansUp(t *testing.T) {
	arc, scanner, _ := createSameNSARC()
	updatePolicy(arc, sameNSTestPolicyKey, sameNSPolicy())
	updatePolicy(arc, sameNSTestPolicyKey, nil)

	expectActiveKeys(t, scanner)
	if arc.policyIDToEndpointKeys.Len() != 0 {
		t.Errorf("matches leaked after delete: %d", arc.policyIDToEndpointKeys.Len())
	}
	if arc.parentToVirtualKeys.Len() != 0 {
		t.Errorf("virtual keys leaked after delete")
	}
	if arc.sameNamespacePolicies.Len() != 0 {
		t.Errorf("policy still marked as same() after delete")
	}
}

func TestARC_SameNamespace_ForceProgrammed(t *testing.T) {
	arc, scanner, _ := createSameNSARC()
	pol := sameNSPolicy()
	pol.PerformanceHints = []v3.PolicyPerformanceHint{v3.PerfHintAssumeNeededOnEveryNode}
	updatePolicy(arc, sameNSTestPolicyKey, pol)

	// The dummy match keeps the real key active, alongside the per-namespace copies.
	expectActiveKeys(t, scanner, sameNSTestPolicyKey,
		virtualPolicyKey(sameNSTestPolicyKey, "ns1"), virtualPolicyKey(sameNSTestPolicyKey, "ns2"))

	deleteEndpoint(arc, sameNSTestWepKey("ns2", "c"))
	arc.OnUpdate(api.Update{KVPair: model.KVPair{Key: sameNSTestHepKey}})
	expectActiveKeys(t, scanner, sameNSTestPolicyKey, virtualPolicyKey(sameNSTestPolicyKey, "ns1"))

	updatePolicy(arc, sameNSTestPolicyKey, nil)
	expectActiveKeys(t, scanner)
}

func countMatches(arc *ActiveRulesCalculator, key model.PolicyKey) int {
	n := 0
	arc.policyIDToEndpointKeys.Iter(key, func(any) { n++ })
	return n
}
