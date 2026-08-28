// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package model_test

import (
	"reflect"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

func mustParseCIDR(s string) net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *ipNet
}

var _ = Describe("AllocationBlock tests", func() {
	It("should calculate non-affine allocations correctly", func() {
		affinity := "host:myhost"
		block := model.AllocationBlock{
			CIDR: mustParseCIDR("10.0.1.0/29"),
			Allocations: []*int{
				intPtr(1), /* other host */
				intPtr(0), /* same host should be skipped */
				intPtr(2), /* another host */
				intPtr(3), /* missing attrs should be skipped */
				nil,
				nil,
				nil,
				intPtr(2), /* alias of another host */
			},
			Affinity: &affinity,
			Attributes: []model.AllocationAttribute{
				{ActiveOwnerAttrs: map[string]string{"node": "myhost"}},
				{ActiveOwnerAttrs: map[string]string{"node": "otherhost"}},
				{ActiveOwnerAttrs: map[string]string{"node": "anotherhost"}},
			},
		}

		Expect(block.NonAffineAllocations()).To(ConsistOf(
			model.Allocation{Host: "otherhost", Addr: *net.ParseIP("10.0.1.0")},
			model.Allocation{Host: "anotherhost", Addr: *net.ParseIP("10.0.1.2")},
			model.Allocation{Host: "anotherhost", Addr: *net.ParseIP("10.0.1.7")},
		))
	})

	Describe("Clone", func() {
		// fullyPopulatedBlock sets every field of AllocationBlock to a non-zero
		// value, so that the round-trip check below fails if Clone() forgets one.
		fullyPopulatedBlock := func() model.AllocationBlock {
			claimTime := metav1.NewTime(time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC))
			releasedAt := metav1.NewTime(time.Date(2026, 8, 28, 12, 5, 0, 0, time.UTC))
			affinity := "host:myhost"
			hostAffinity := "myhost"
			handle := "k8s-pod-network.abc123"
			return model.AllocationBlock{
				CIDR:              mustParseCIDR("10.0.1.0/30"),
				Affinity:          &affinity,
				AffinityClaimTime: &claimTime,
				Allocations:       []*int{intPtr(0), intPtr(1), nil, nil},
				Unallocated:       []int{2, 3},
				Attributes: []model.AllocationAttribute{
					{
						HandleID:            &handle,
						ActiveOwnerAttrs:    map[string]string{"pod": "nginx"},
						AlternateOwnerAttrs: map[string]string{"pod": "nginx-old"},
					},
					{
						// An IP in cooldown: pointed at by an allocation, but
						// carrying only a release timestamp.
						ReleasedAt: &releasedAt,
					},
				},
				SequenceNumber:              5,
				SequenceNumberForAllocation: map[string]uint64{"0": 4, "1": 5},
				Deleted:                     true,
				HostAffinity:                &hostAffinity,
			}
		}

		It("should populate every field in the test fixture", func() {
			// Guard for the round-trip test below: if a field is added to
			// AllocationBlock, this fails until the fixture covers it.
			b := fullyPopulatedBlock()
			v := reflect.ValueOf(b)
			for i := range v.NumField() {
				name := v.Type().Field(i).Name
				Expect(v.Field(i).IsZero()).To(BeFalse(), "field %s is not set in fullyPopulatedBlock", name)
			}
		})

		It("should copy every field", func() {
			b := fullyPopulatedBlock()
			Expect(*b.Clone()).To(Equal(b))
		})

		It("should not share mutable state with the original", func() {
			b := fullyPopulatedBlock()
			c := b.Clone()

			c.Allocations[0] = nil
			c.Unallocated[0] = 99
			c.Attributes[0].ActiveOwnerAttrs["pod"] = "changed"
			c.Attributes[0].AlternateOwnerAttrs["pod"] = "changed"
			c.SequenceNumberForAllocation["0"] = 99

			Expect(b).To(Equal(fullyPopulatedBlock()))
		})
	})

	DescribeTable("CIDR table tests",
		func(cidr string, expectedNumIPs int) {
			block := model.AllocationBlock{
				CIDR: mustParseCIDR(cidr),
			}
			Expect(block.NumAddresses()).To(Equal(expectedNumIPs))
		},
		Entry("10.0.0.0/16", "10.0.0.0/16", 65536),
		Entry("10.0.0.0/32", "10.0.0.0/32", 1),
	)

	DescribeTable("ordinal arithmetic tests",
		func(cidr string, ordinal int, expectedAddr string) {
			block := model.AllocationBlock{
				CIDR: mustParseCIDR(cidr),
			}
			ip := block.OrdinalToIP(ordinal)
			Expect(ip.String()).To(Equal(expectedAddr))
			Expect(block.IPToOrdinal(ip)).To(Equal(ordinal))
		},
		Entry("10.0.0.0/30 0", "10.0.0.0/30", 0, "10.0.0.0"),
		Entry("10.0.0.0/30 1", "10.0.0.0/30", 1, "10.0.0.1"),
		Entry("10.0.0.0/30 2", "10.0.0.0/30", 2, "10.0.0.2"),
		Entry("10.0.0.0/30 3", "10.0.0.0/30", 3, "10.0.0.3"),

		Entry("10.0.0.64/30 0", "10.0.0.64/30", 0, "10.0.0.64"),
		Entry("10.0.0.64/30 1", "10.0.0.64/30", 1, "10.0.0.65"),
		Entry("10.0.0.64/30 2", "10.0.0.64/30", 2, "10.0.0.66"),
		Entry("10.0.0.64/30 3", "10.0.0.64/30", 3, "10.0.0.67"),

		Entry("10.0.0.64/32 3", "10.0.0.64/32", 0, "10.0.0.64"),

		Entry("10.0.128.0/17 0", "10.0.128.0/17", 0, "10.0.128.0"),
		Entry("10.0.128.0/17 256", "10.0.128.0/17", 256, "10.0.129.0"),
		Entry("10.0.128.0/17 257", "10.0.128.0/17", 257, "10.0.129.1"),
	)
})

func intPtr(i int) *int {
	return &i
}
