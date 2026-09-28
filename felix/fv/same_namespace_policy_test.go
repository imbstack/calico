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

package fv_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ same namespace policy tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const (
		wepPortStr = "8055"
		appLabel   = "same-ns-test"
	)

	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client client.Interface
		cc     *connectivity.Checker

		// Workloads in ns-a and ns-b on each of the two hosts.
		a0, b0, a1, b1 *workload.Workload
	)

	runWorkload := func(felixIdx int, name, ns, ip string) *workload.Workload {
		infrastructure.AssignIP(name, ip, tc.Felixes[felixIdx].Hostname, client)
		// On Kubernetes, the interface name is derived from the namespace, which workload.Run
		// takes as its profile argument.
		w := workload.Run(tc.Felixes[felixIdx], name, ns, ip, wepPortStr, "tcp")
		w.WorkloadEndpoint.Namespace = ns
		w.WorkloadEndpoint.Labels["app"] = appLabel
		w.ConfigureInInfra(infra)
		return w
	}

	BeforeEach(func() {
		infra = getInfra()

		opts := infrastructure.DefaultTopologyOptions()
		opts.IPIPMode = api.IPIPModeNever
		tc, client = infrastructure.StartNNodeTopology(2, opts, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		a0 = runWorkload(0, "a0", "ns-a", "10.65.0.2")
		b0 = runWorkload(0, "b0", "ns-b", "10.65.0.3")
		a1 = runWorkload(1, "a1", "ns-a", "10.65.1.2")
		b1 = runWorkload(1, "b1", "ns-b", "10.65.1.3")

		ensureRoutesProgrammed(tc.Felixes)
		if BPFMode() {
			ensureAllNodesBPFProgramsAttached(tc.Felixes)
		}

		cc = &connectivity.Checker{}
	})

	expectOnlySameNamespace := func() {
		cc.ResetExpectations()
		// Same namespace, same host and across hosts.
		cc.ExpectSome(a0, a1)
		cc.ExpectSome(a1, a0)
		cc.ExpectSome(b0, b1)
		cc.ExpectSome(b1, b0)
		// Different namespace, same host and across hosts.
		cc.ExpectNone(a0, b0)
		cc.ExpectNone(b0, a0)
		cc.ExpectNone(a0, b1)
		cc.ExpectNone(b1, a0)
		cc.ExpectNone(a1, b1)
		cc.ExpectNone(b0, a1)
		cc.CheckConnectivity()
	}

	expectFullConnectivity := func() {
		cc.ResetExpectations()
		for _, from := range []*workload.Workload{a0, b0, a1, b1} {
			for _, to := range []*workload.Workload{a0, b0, a1, b1} {
				if from != to {
					cc.ExpectSome(from, to)
				}
			}
		}
		cc.CheckConnectivity()
	}

	// A single spec: the infra deletes namespaces asynchronously between specs, so a second spec
	// that recreated ns-a straight away would race with the deletion.
	It("should only allow ingress from the same namespace", func() {
		By("allowing everything before the policy is created")
		expectFullConnectivity()

		By("rejecting same() in a NetworkPolicy")
		np := api.NewNetworkPolicy()
		np.Name = "same-ns"
		np.Namespace = "ns-a"
		np.Spec.Selector = "all()"
		np.Spec.Ingress = []api.Rule{{
			Action: api.Allow,
			Source: api.EntityRule{NamespaceSelector: api.SameNamespaceSelector},
		}}
		_, err := client.NetworkPolicies().Create(utils.Ctx, np, utils.NoOptions)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("same()"))

		By("creating a GlobalNetworkPolicy that allows ingress from same()")
		gnp := api.NewGlobalNetworkPolicy()
		gnp.Name = "same-ns"
		gnp.Spec.Selector = "app == '" + appLabel + "'"
		gnp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
		gnp.Spec.Ingress = []api.Rule{{
			Action: api.Allow,
			Source: api.EntityRule{NamespaceSelector: api.SameNamespaceSelector},
		}}
		gnp, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
		expectOnlySameNamespace()

		By("removing the policy")
		_, err = client.GlobalNetworkPolicies().Delete(utils.Ctx, gnp.Name, options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
		expectFullConnectivity()
	})
})
