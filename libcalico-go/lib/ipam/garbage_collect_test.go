// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package ipam

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("GarbageCollectColdIPs", func() {
	const (
		coldOrd   = 31
		liveOrd   = 52
		cachedRev = "cached-revision"
		freshRev  = "fresh-revision"
	)

	var (
		ctx      context.Context
		fc       *fakeClient
		ic       *ipamClient
		blockKVP *model.KVPair
		updates  []*model.KVPair
		gets     int
		blockUID = types.UID("block-uid")
	)

	// makeColdBlock builds a /26 block with one cold allocation (released an
	// hour ago) at coldOrd and one live allocation at liveOrd.
	makeColdBlock := func() *model.AllocationBlock {
		cidr := cnet.MustParseCIDR("10.0.0.0/26")
		coldHandle := "cold-handle"
		liveHandle := "live-handle"
		releasedAt := metav1.NewTime(time.Now().Add(-time.Hour))
		coldAttr := 0
		liveAttr := 1
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: make([]*int, 64),
			Attributes: []model.AllocationAttribute{
				{AttrPrimary: &coldHandle, ReleasedAt: &releasedAt},
				{AttrPrimary: &liveHandle},
			},
		}
		b.Allocations[coldOrd] = &coldAttr
		b.Allocations[liveOrd] = &liveAttr
		for i := 0; i < 64; i++ {
			if i != coldOrd && i != liveOrd {
				b.Unallocated = append(b.Unallocated, i)
			}
		}
		return b
	}

	BeforeEach(func() {
		ctx = context.Background()

		blockKVP = &model.KVPair{
			Key:      model.BlockKey{CIDR: cnet.MustParseCIDR("10.0.0.0/26")},
			Value:    makeColdBlock(),
			Revision: cachedRev,
			UID:      &blockUID,
		}

		updates = nil
		gets = 0
		fc = newFakeClient()

		// GarbageCollectColdIPs only exercises the blockReaderWriter's client.
		ic = &ipamClient{blockReaderWriter: blockReaderWriter{client: fc}}
	})

	It("writes back the GC'd block in a single CAS when the caller's copy is current", func() {
		fc.updateFuncs["default"] = func(_ context.Context, object *model.KVPair) (*model.KVPair, error) {
			updates = append(updates, object)
			return object, nil
		}
		fc.getFuncs["default"] = func(_ context.Context, _ model.Key, _ string) (*model.KVPair, error) {
			gets++
			return nil, cerrors.ErrorResourceDoesNotExist{}
		}

		err := ic.GarbageCollectColdIPs(ctx, &IPAMConfig{IPCooldownSeconds: 30}, blockKVP)
		Expect(err).NotTo(HaveOccurred())

		// The happy path must not read at all, and must CAS against the caller's
		// revision, carrying the caller's UID.
		Expect(gets).To(BeZero(), "no read expected when the cached copy is current")
		Expect(updates).To(HaveLen(1), "expected the GC'd block to be written back")
		written := updates[0]
		Expect(written.Key).To(Equal(blockKVP.Key))
		Expect(written.Revision).To(Equal(cachedRev))
		Expect(written.UID).To(Equal(&blockUID))

		// The written value must be the GC'd block: the cold ordinal deallocated
		// and its attribute removed, the live allocation retained.
		wb := written.Value.(*model.AllocationBlock)
		Expect(wb.Allocations[coldOrd]).To(BeNil(), "cold IP should be deallocated")
		Expect(wb.Allocations[liveOrd]).NotTo(BeNil(), "live IP should be retained")
		Expect(wb.Unallocated).To(ContainElement(coldOrd))
		Expect(wb.Attributes).To(HaveLen(1), "the cold allocation's attribute should be removed")

		// The caller's copy must not be mutated.
		ob := blockKVP.Value.(*model.AllocationBlock)
		Expect(ob.Allocations[coldOrd]).NotTo(BeNil(), "caller's block must not be mutated")
		Expect(ob.Attributes).To(HaveLen(2))
	})

	It("does nothing when there is nothing to collect", func() {
		fc.updateFuncs["default"] = func(_ context.Context, object *model.KVPair) (*model.KVPair, error) {
			updates = append(updates, object)
			return object, nil
		}
		fc.getFuncs["default"] = func(_ context.Context, _ model.Key, _ string) (*model.KVPair, error) {
			gets++
			return nil, cerrors.ErrorResourceDoesNotExist{}
		}

		// With a long cooldown the released IP is still cooling down.
		err := ic.GarbageCollectColdIPs(ctx, &IPAMConfig{IPCooldownSeconds: 100000}, blockKVP)
		Expect(err).NotTo(HaveOccurred())
		Expect(updates).To(BeEmpty(), "no write expected when nothing is collected")
		Expect(gets).To(BeZero(), "no read expected when nothing is collected")
	})

	It("re-reads and retries when the caller's copy is stale", func() {
		fc.updateFuncs["default"] = func(_ context.Context, object *model.KVPair) (*model.KVPair, error) {
			updates = append(updates, object)
			if object.Revision == cachedRev {
				return nil, cerrors.ErrorResourceUpdateConflict{Identifier: object.Key.String()}
			}
			return object, nil
		}
		fc.getFuncs["default"] = func(_ context.Context, _ model.Key, _ string) (*model.KVPair, error) {
			gets++
			return &model.KVPair{
				Key:      blockKVP.Key,
				Value:    makeColdBlock(),
				Revision: freshRev,
			}, nil
		}

		err := ic.GarbageCollectColdIPs(ctx, &IPAMConfig{IPCooldownSeconds: 30}, blockKVP)
		Expect(err).NotTo(HaveOccurred())

		// One failed optimistic CAS, one re-read, one successful CAS on the
		// fresh revision.
		Expect(updates).To(HaveLen(2))
		Expect(updates[0].Revision).To(Equal(cachedRev))
		Expect(updates[1].Revision).To(Equal(freshRev))
		Expect(gets).To(Equal(1))

		// The final write must be the GC of the *fresh* copy.
		wb := updates[1].Value.(*model.AllocationBlock)
		Expect(wb.Allocations[coldOrd]).To(BeNil(), "cold IP should be deallocated")
		Expect(wb.Allocations[liveOrd]).NotTo(BeNil(), "live IP should be retained")
	})

	It("stops without writing when the fresh copy has already been collected", func() {
		fc.updateFuncs["default"] = func(_ context.Context, object *model.KVPair) (*model.KVPair, error) {
			updates = append(updates, object)
			return nil, cerrors.ErrorResourceUpdateConflict{Identifier: object.Key.String()}
		}
		fc.getFuncs["default"] = func(_ context.Context, _ model.Key, _ string) (*model.KVPair, error) {
			gets++
			// Simulate another actor (e.g. GC-on-load) having collected the cold
			// IP already: the fresh copy has nothing left to collect.
			collected := makeColdBlock()
			collected.Allocations[coldOrd] = nil
			collected.Unallocated = append(collected.Unallocated, coldOrd)
			collected.Attributes = collected.Attributes[1:]
			liveAttr := 0
			collected.Allocations[liveOrd] = &liveAttr
			return &model.KVPair{Key: blockKVP.Key, Value: collected, Revision: freshRev}, nil
		}

		err := ic.GarbageCollectColdIPs(ctx, &IPAMConfig{IPCooldownSeconds: 30}, blockKVP)
		Expect(err).NotTo(HaveOccurred())
		Expect(updates).To(HaveLen(1), "only the failed optimistic CAS should be attempted")
		Expect(gets).To(Equal(1))
	})

	It("treats a deleted block as fully collected", func() {
		fc.updateFuncs["default"] = func(_ context.Context, object *model.KVPair) (*model.KVPair, error) {
			updates = append(updates, object)
			return nil, cerrors.ErrorResourceUpdateConflict{Identifier: object.Key.String()}
		}
		fc.getFuncs["default"] = func(_ context.Context, _ model.Key, _ string) (*model.KVPair, error) {
			gets++
			return nil, cerrors.ErrorResourceDoesNotExist{}
		}

		err := ic.GarbageCollectColdIPs(ctx, &IPAMConfig{IPCooldownSeconds: 30}, blockKVP)
		Expect(err).NotTo(HaveOccurred())
		Expect(updates).To(HaveLen(1))
		Expect(gets).To(Equal(1))
	})
})
