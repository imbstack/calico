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

package conversion

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
)

var _ = Describe("ServiceAccount profile disabling", func() {
	Describe("parsing "+EnvDisableServiceAccountProfiles, func() {
		var origVal string
		var origSet bool

		BeforeEach(func() {
			origVal, origSet = os.LookupEnv(EnvDisableServiceAccountProfiles)
		})

		AfterEach(func() {
			if origSet {
				Expect(os.Setenv(EnvDisableServiceAccountProfiles, origVal)).To(Succeed())
			} else {
				Expect(os.Unsetenv(EnvDisableServiceAccountProfiles)).To(Succeed())
			}
		})

		It("should default to false when unset", func() {
			Expect(os.Unsetenv(EnvDisableServiceAccountProfiles)).To(Succeed())
			Expect(readDisableServiceAccountProfilesEnv()).To(BeFalse())
		})

		DescribeTable("should parse values",
			func(val string, expected bool) {
				Expect(os.Setenv(EnvDisableServiceAccountProfiles, val)).To(Succeed())
				Expect(readDisableServiceAccountProfilesEnv()).To(Equal(expected))
			},
			Entry("empty", "", false),
			Entry("true", "true", true),
			Entry("TRUE", "TRUE", true),
			Entry("1", "1", true),
			Entry("false", "false", false),
			Entry("0", "0", false),
			Entry("garbage is treated as false", "yes-please", false),
		)
	})

	Describe("pod to WorkloadEndpoint conversion", func() {
		pod := func() *kapiv1.Pod {
			return &kapiv1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "default",
					Labels:    map[string]string{"app": "foo"},
				},
				Spec: kapiv1.PodSpec{
					NodeName:           "nodeA",
					ServiceAccountName: "sa-test",
				},
				Status: kapiv1.PodStatus{PodIP: "192.168.0.1"},
			}
		}

		convert := func(wc WorkloadEndpointConverter) *internalapi.WorkloadEndpoint {
			kvps, err := wc.PodToWorkloadEndpoints(pod())
			Expect(err).NotTo(HaveOccurred())
			Expect(kvps).To(HaveLen(1))
			return kvps[0].Value.(*internalapi.WorkloadEndpoint)
		}

		It("should be enabled by default in the test environment", func() {
			wc := NewWorkloadEndpointConverter().(*defaultWorkloadEndpointConverter)
			Expect(wc.disableServiceAccountProfiles).To(BeFalse())
		})

		It("should include the ksa.* profile when enabled", func() {
			wep := convert(&defaultWorkloadEndpointConverter{})
			Expect(wep.Spec.Profiles).To(Equal([]string{"kns.default", "ksa.default.sa-test"}))
			Expect(wep.Spec.ServiceAccountName).To(Equal("sa-test"))
			Expect(wep.Labels).To(HaveKeyWithValue(apiv3.LabelServiceAccount, "sa-test"))
		})

		It("should omit the ksa.* profile when disabled", func() {
			wep := convert(&defaultWorkloadEndpointConverter{disableServiceAccountProfiles: true})
			Expect(wep.Spec.Profiles).To(Equal([]string{"kns.default"}))
			// The service account name and label are still populated, so policy that matches
			// on service account name continues to work.
			Expect(wep.Spec.ServiceAccountName).To(Equal("sa-test"))
			Expect(wep.Labels).To(HaveKeyWithValue(apiv3.LabelServiceAccount, "sa-test"))
		})
	})
})
