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

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// virtualPolicyPrefix is prepended to the real policy name to form virtual policy names.
// The double-underscore prefix is not a valid Kubernetes name character, preventing collisions
// with real policy names.
const virtualPolicyPrefix = "__snsl__:"

// impossibleSelector is a selector expression that never matches any endpoint.
// It is used when a namespace is missing a label key listed in SharedNamespaceLabels.
const impossibleSelector = "has(__snsl_never_match__)"

// NamespacePolicyExpander sits between AllUpdDispatcher and ActiveRulesCalculator.
// For GlobalNetworkPolicies that contain rules with SharedNamespaceLabels or
// NotSharedNamespaceLabels, it expands them into per-namespace "virtual" policies
// with concrete namespace-scoped selectors.  All other policies are forwarded
// unchanged.
//
// Namespace label changes trigger re-expansion so virtual policies stay current.
type NamespacePolicyExpander struct {
	// namespaces maps namespace name -> decoded labels (without pcns. prefix),
	// as received via OnNamespaceUpdate.
	namespaces map[string]map[string]string

	// snslPolicies stores policies that have SharedNamespaceLabels / NotSharedNamespaceLabels
	// in at least one rule.  These are NOT forwarded directly to ARC; instead their virtual
	// expansions are forwarded.
	snslPolicies map[model.PolicyKey]*model.Policy

	// realToVirtualNs maps a real (SNSL) policy key to the set of namespace names for
	// which a virtual policy is currently active downstream.
	realToVirtualNs map[model.PolicyKey]set.Set[string]

	// arcReceiver receives all policy updates: pass-through non-SNSL policies and virtual
	// expansions of SNSL policies.  Wired to ActiveRulesCalculator.OnUpdate.
	arcReceiver func(api.Update) bool

	// metaReceiver receives only virtual policy updates (creates, updates, deletes).
	// Wired to PolicyResolver.OnUpdate so it can sort virtual policies correctly.
	metaReceiver func(api.Update) bool
}

// NewNamespacePolicyExpander creates a new expander.
//
//   - arcReceiver  receives all policy updates (pass-through + virtual expansions).
//   - metaReceiver receives virtual policy metadata updates only.
func NewNamespacePolicyExpander(
	arcReceiver func(api.Update) bool,
	metaReceiver func(api.Update) bool,
) *NamespacePolicyExpander {
	return &NamespacePolicyExpander{
		namespaces:      make(map[string]map[string]string),
		snslPolicies:    make(map[model.PolicyKey]*model.Policy),
		realToVirtualNs: make(map[model.PolicyKey]set.Set[string]),
		arcReceiver:     arcReceiver,
		metaReceiver:    metaReceiver,
	}
}

// RegisterWith registers the expander with allUpdDispatcher so it intercepts all
// model.PolicyKey updates before they reach ActiveRulesCalculator.
func (e *NamespacePolicyExpander) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.PolicyKey{}, e.onPolicyUpdate)
}

// virtualPolicyKey returns the internal policy key used for the virtual expansion of
// realKey for namespace ns.
func virtualPolicyKey(realKey model.PolicyKey, ns string) model.PolicyKey {
	return model.PolicyKey{
		Name:      fmt.Sprintf("%s%s/%s", virtualPolicyPrefix, realKey.Name, ns),
		Namespace: "",
		Kind:      realKey.Kind,
	}
}

// policyHasSharedNamespaceLabels reports whether any rule in policy uses the
// SharedNamespaceLabels / NotSharedNamespaceLabels fields.
func policyHasSharedNamespaceLabels(policy *model.Policy) bool {
	for _, r := range policy.InboundRules {
		if len(r.OriginalSrcSharedNamespaceLabels) > 0 ||
			len(r.OriginalSrcNotSharedNamespaceLabels) > 0 ||
			len(r.OriginalDstSharedNamespaceLabels) > 0 ||
			len(r.OriginalDstNotSharedNamespaceLabels) > 0 {
			return true
		}
	}
	for _, r := range policy.OutboundRules {
		if len(r.OriginalSrcSharedNamespaceLabels) > 0 ||
			len(r.OriginalSrcNotSharedNamespaceLabels) > 0 ||
			len(r.OriginalDstSharedNamespaceLabels) > 0 ||
			len(r.OriginalDstNotSharedNamespaceLabels) > 0 {
			return true
		}
	}
	return false
}

// onPolicyUpdate is called by AllUpdDispatcher for every model.PolicyKey update.
func (e *NamespacePolicyExpander) onPolicyUpdate(update api.Update) (filterOut bool) {
	key := update.Key.(model.PolicyKey)

	if update.Value == nil {
		// Policy deleted.
		if _, isSNSL := e.snslPolicies[key]; isSNSL {
			// Retract all virtual expansions.
			e.retractAllVirtualPolicies(key)
			delete(e.snslPolicies, key)
		} else {
			// Pass-through deletion to ARC.
			e.arcReceiver(update)
		}
	} else {
		policy := update.Value.(*model.Policy)
		_, wasSNSL := e.snslPolicies[key]

		if policyHasSharedNamespaceLabels(policy) {
			// New or updated SNSL policy.
			e.snslPolicies[key] = policy
			e.reconcilePolicyForAllNamespaces(key, policy)
		} else {
			if wasSNSL {
				// Was SNSL, now it's not – retract virtual policies first.
				e.retractAllVirtualPolicies(key)
				delete(e.snslPolicies, key)
			}
			// Pass-through to ARC.
			e.arcReceiver(update)
		}
	}
	return false
}

// OnNamespaceUpdate is called (via the nsAwareCallbacks wrapper) when a namespace's
// labels change.
func (e *NamespacePolicyExpander) OnNamespaceUpdate(msg *proto.NamespaceUpdate) {
	nsName := msg.Id.Name
	e.namespaces[nsName] = msg.Labels
	e.reconcileNamespaceForAllPolicies(nsName, msg.Labels)
}

// OnNamespaceRemove is called when a namespace is deleted.
func (e *NamespacePolicyExpander) OnNamespaceRemove(id types.NamespaceID) {
	nsName := id.Name
	delete(e.namespaces, nsName)
	// Retract virtual policies for this namespace across all SNSL policies.
	for realKey := range e.snslPolicies {
		e.retractVirtualPolicy(realKey, nsName)
	}
}

// reconcilePolicyForAllNamespaces ensures virtual policies for realKey are up to date
// across all known namespaces when the policy is created or updated.
func (e *NamespacePolicyExpander) reconcilePolicyForAllNamespaces(realKey model.PolicyKey, policy *model.Policy) {
	currentNSes := set.New[string]()
	for nsName, nsLabels := range e.namespaces {
		currentNSes.Add(nsName)
		e.emitVirtualPolicy(realKey, nsName, nsLabels, policy)
	}

	// Retract virtual policies for namespaces that are no longer known.
	active, ok := e.realToVirtualNs[realKey]
	if !ok {
		return
	}
	var toRetract []string
	active.Iter(func(nsName string) error {
		if !currentNSes.Contains(nsName) {
			toRetract = append(toRetract, nsName)
		}
		return nil
	})
	for _, nsName := range toRetract {
		e.retractVirtualPolicy(realKey, nsName)
	}
}

// reconcileNamespaceForAllPolicies updates virtual policies for nsName across all SNSL
// policies when a namespace is added or its labels change.
func (e *NamespacePolicyExpander) reconcileNamespaceForAllPolicies(nsName string, nsLabels map[string]string) {
	for realKey, policy := range e.snslPolicies {
		e.emitVirtualPolicy(realKey, nsName, nsLabels, policy)
	}
}

// emitVirtualPolicy creates or updates the virtual policy for (realKey, nsName).
func (e *NamespacePolicyExpander) emitVirtualPolicy(
	realKey model.PolicyKey,
	nsName string,
	nsLabels map[string]string,
	policy *model.Policy,
) {
	virtualKey := virtualPolicyKey(realKey, nsName)
	virtualPolicy := expandForNamespace(policy, nsName, nsLabels)

	log.WithFields(log.Fields{
		"realKey":    realKey,
		"nsName":     nsName,
		"virtualKey": virtualKey,
	}).Debug("Emitting virtual policy for SharedNamespaceLabels expansion")

	update := api.Update{
		UpdateType: api.UpdateTypeKVNew,
		KVPair: model.KVPair{
			Key:   virtualKey,
			Value: virtualPolicy,
		},
	}
	e.arcReceiver(update)
	e.metaReceiver(update)

	// Track that this virtual policy is now active.
	if _, ok := e.realToVirtualNs[realKey]; !ok {
		e.realToVirtualNs[realKey] = set.New[string]()
	}
	e.realToVirtualNs[realKey].Add(nsName)
}

// retractAllVirtualPolicies removes all virtual policies for realKey.
func (e *NamespacePolicyExpander) retractAllVirtualPolicies(realKey model.PolicyKey) {
	active, ok := e.realToVirtualNs[realKey]
	if !ok {
		return
	}
	// Collect namespace names first to avoid modifying the set during iteration.
	var nsNames []string
	active.Iter(func(nsName string) error {
		nsNames = append(nsNames, nsName)
		return nil
	})
	for _, nsName := range nsNames {
		e.retractVirtualPolicy(realKey, nsName)
	}
	delete(e.realToVirtualNs, realKey)
}

// retractVirtualPolicy retracts the virtual policy for (realKey, nsName) if it is active.
func (e *NamespacePolicyExpander) retractVirtualPolicy(realKey model.PolicyKey, nsName string) {
	active, ok := e.realToVirtualNs[realKey]
	if !ok || !active.Contains(nsName) {
		return
	}
	virtualKey := virtualPolicyKey(realKey, nsName)
	log.WithFields(log.Fields{
		"realKey":    realKey,
		"nsName":     nsName,
		"virtualKey": virtualKey,
	}).Debug("Retracting virtual policy for SharedNamespaceLabels expansion")

	update := api.Update{
		UpdateType: api.UpdateTypeKVDeleted,
		KVPair:     model.KVPair{Key: virtualKey, Value: nil},
	}
	e.arcReceiver(update)
	e.metaReceiver(update)
	active.Discard(nsName)
}

// expandForNamespace creates a virtual policy copy for the given namespace.
func expandForNamespace(policy *model.Policy, nsName string, nsLabels map[string]string) *model.Policy {
	expanded := *policy // shallow copy; rules will be replaced below

	// Restrict the virtual policy's top-level selector to exactly this namespace.
	// We AND the original selector with the namespace restriction so that any
	// endpoint-level selector in the original policy is preserved.
	nsRestriction := fmt.Sprintf("projectcalico.org/namespace == '%s'", nsName)
	if policy.Selector != "" {
		expanded.Selector = fmt.Sprintf("(%s) && %s", policy.Selector, nsRestriction)
	} else {
		expanded.Selector = nsRestriction
	}

	expanded.InboundRules = expandRules(policy.InboundRules, nsLabels)
	expanded.OutboundRules = expandRules(policy.OutboundRules, nsLabels)
	return &expanded
}

// expandRules expands SharedNamespaceLabels fields in each rule.
func expandRules(rules []model.Rule, nsLabels map[string]string) []model.Rule {
	out := make([]model.Rule, len(rules))
	for i, r := range rules {
		out[i] = expandRule(r, nsLabels)
	}
	return out
}

// expandRule expands a single rule's SharedNamespaceLabels fields into concrete selectors.
func expandRule(r model.Rule, nsLabels map[string]string) model.Rule {
	if len(r.OriginalSrcSharedNamespaceLabels) > 0 {
		sharedSel, ok := buildSharedSelector(r.OriginalSrcSharedNamespaceLabels, nsLabels)
		if !ok {
			r.SrcSelector = impossibleSelector
		} else {
			r.SrcSelector = combineSelectors(sharedSel, r.SrcSelector)
		}
	}
	if len(r.OriginalSrcNotSharedNamespaceLabels) > 0 {
		notSharedSel, ok := buildSharedSelector(r.OriginalSrcNotSharedNamespaceLabels, nsLabels)
		if !ok {
			// Missing label: the "not" match is vacuously satisfied (nothing to negate).
			// Leave NotSrcSelector unchanged.
		} else {
			r.NotSrcSelector = combineSelectors(notSharedSel, r.NotSrcSelector)
		}
	}
	if len(r.OriginalDstSharedNamespaceLabels) > 0 {
		sharedSel, ok := buildSharedSelector(r.OriginalDstSharedNamespaceLabels, nsLabels)
		if !ok {
			r.DstSelector = impossibleSelector
		} else {
			r.DstSelector = combineSelectors(sharedSel, r.DstSelector)
		}
	}
	if len(r.OriginalDstNotSharedNamespaceLabels) > 0 {
		notSharedSel, ok := buildSharedSelector(r.OriginalDstNotSharedNamespaceLabels, nsLabels)
		if !ok {
			// Leave NotDstSelector unchanged.
		} else {
			r.NotDstSelector = combineSelectors(notSharedSel, r.NotDstSelector)
		}
	}
	return r
}

// buildSharedSelector constructs a selector of the form
// "pcns.L1 == 'v1' && pcns.L2 == 'v2'" from the given label keys and namespace labels.
// Returns ("", false) if any key is absent from nsLabels.
func buildSharedSelector(keys []string, nsLabels map[string]string) (string, bool) {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v, ok := nsLabels[k]
		if !ok {
			return "", false // label missing
		}
		parts = append(parts, fmt.Sprintf("pcns.%s == '%s'", k, v))
	}
	return strings.Join(parts, " && "), true
}

// combineSelectors ANDs two selector strings, handling the empty-string case.
func combineSelectors(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return fmt.Sprintf("(%s) && (%s)", a, b)
}
