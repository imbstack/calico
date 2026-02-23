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
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// OnLocalEndpointUpdateForTest exposes the internal onLocalEndpointUpdate method for
// white-box testing.  ep may be nil to simulate a deletion.
func (e *NamespacePolicyExpander) OnLocalEndpointUpdateForTest(key model.WorkloadEndpointKey, ep *model.WorkloadEndpoint) {
	var val interface{}
	if ep != nil {
		val = ep
	}
	e.onLocalEndpointUpdate(api.Update{
		KVPair: model.KVPair{
			Key:   key,
			Value: val,
		},
	})
}

// OnPolicyUpdateForTest exposes the internal onPolicyUpdate method for white-box testing.
// policy may be nil to simulate a deletion.
func (e *NamespacePolicyExpander) OnPolicyUpdateForTest(key model.PolicyKey, policy *model.Policy) {
	var val interface{}
	if policy != nil {
		val = policy
	}
	e.onPolicyUpdate(api.Update{
		KVPair: model.KVPair{
			Key:   key,
			Value: val,
		},
	})
}
