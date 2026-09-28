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

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
)

// Support for the same() namespaceSelector in GlobalNetworkPolicy rules.
//
// The update processor converts same() into a placeholder selector that matches nothing (see
// updateprocessors.SameNamespacePlaceholderSelector).  When a same() policy matches a local workload
// endpoint in namespace N, the ActiveRulesCalculator tracks the match under a "virtual" policy key
// for (policy, N) and activates a copy of the policy with the placeholder replaced by a match on N.
//
// A virtual key is the parent's key with Namespace set to N.  Global policy kinds never have a
// namespace, so virtual keys can't collide with real policies, and the parent is recovered by
// clearing the namespace.

// isSameNamespacePolicy returns true if the policy is a global policy with at least one rule that
// uses the same() namespaceSelector.
func isSameNamespacePolicy(key model.PolicyKey, policy *model.Policy) bool {
	if policy == nil || !kindSupportsSameNamespace(key.Kind) {
		return false
	}
	return rulesUseSameNamespace(policy.InboundRules) || rulesUseSameNamespace(policy.OutboundRules)
}

func kindSupportsSameNamespace(kind string) bool {
	return kind == v3.KindGlobalNetworkPolicy || kind == v3.KindStagedGlobalNetworkPolicy
}

func rulesUseSameNamespace(rules []model.Rule) bool {
	for i := range rules {
		if rules[i].OriginalSrcNamespaceSelector == v3.SameNamespaceSelector ||
			rules[i].OriginalDstNamespaceSelector == v3.SameNamespaceSelector {
			return true
		}
	}
	return false
}

// virtualPolicyKey returns the key used for the copy of the parent policy that applies to
// endpoints in namespace ns.
func virtualPolicyKey(parent model.PolicyKey, ns string) model.PolicyKey {
	return model.PolicyKey{
		Name:      parent.Name,
		Namespace: ns,
		Kind:      parent.Kind,
	}
}

// IsVirtualPolicyKey returns true if the key identifies a per-namespace copy of a same() policy.
func IsVirtualPolicyKey(key model.PolicyKey) bool {
	return key.Namespace != "" && kindSupportsSameNamespace(key.Kind)
}

// ParentPolicyKey returns the key of the real policy that a virtual key was derived from.  For
// any other key, it returns the key unchanged.
func ParentPolicyKey(key model.PolicyKey) model.PolicyKey {
	if !IsVirtualPolicyKey(key) {
		return key
	}
	key.Namespace = ""
	return key
}

// expandForNamespace returns a copy of the policy with same() rules resolved to namespace ns.
// The input policy is not modified.  The policy's own selector is left as-is; the
// ActiveRulesCalculator only uses virtual keys for endpoints in ns.
func expandForNamespace(policy *model.Policy, ns string) *model.Policy {
	expanded := *policy
	expanded.InboundRules = expandRulesForNamespace(policy.InboundRules, ns)
	expanded.OutboundRules = expandRulesForNamespace(policy.OutboundRules, ns)
	return &expanded
}

func expandRulesForNamespace(rules []model.Rule, ns string) []model.Rule {
	if rules == nil {
		return nil
	}
	nsSelector := fmt.Sprintf("%s == '%s'", v3.LabelNamespace, ns)
	out := make([]model.Rule, len(rules))
	for i, r := range rules {
		r.SrcSelector = strings.ReplaceAll(r.SrcSelector, updateprocessors.SameNamespacePlaceholderSelector, nsSelector)
		r.DstSelector = strings.ReplaceAll(r.DstSelector, updateprocessors.SameNamespacePlaceholderSelector, nsSelector)
		r.NotSrcSelector = strings.ReplaceAll(r.NotSrcSelector, updateprocessors.SameNamespacePlaceholderSelector, nsSelector)
		r.NotDstSelector = strings.ReplaceAll(r.NotDstSelector, updateprocessors.SameNamespacePlaceholderSelector, nsSelector)
		out[i] = r
	}
	return out
}
