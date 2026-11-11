// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resources

import (
	"context"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	k8stesting "k8s.io/client-go/testing"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var _ = Describe("Profile tests with fake clientSet", func() {
	var clientSet *FakeClientSetWithListRevAndFiltering
	var client *profileClient

	BeforeEach(func() {
		clientSet = NewFakeClientSetWithListRevAndFiltering()

		// Use unique revision for each of the base types so we can verify that
		// they flow through correctly.
		clientSet.CurrentListRevisionByType["Namespace"] = "100"
		clientSet.CurrentListRevisionByType["ServiceAccount"] = "200"

		defaultNS := &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "default",
				ResourceVersion: "10",
				UID:             uuid.NewUUID(),
			},
		}
		defaultNS, err := clientSet.CoreV1().Namespaces().Create(context.TODO(), defaultNS, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		defaultSA := &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "default",
				Namespace:       "default",
				ResourceVersion: "20",
				UID:             uuid.NewUUID(),
			},
		}
		defaultSA, err = clientSet.CoreV1().ServiceAccounts("default").Create(context.TODO(), defaultSA, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		client = NewProfileClient(clientSet).(*profileClient)
	})

	It("should list all and return the collection revision", func() {
		list, err := client.List(context.TODO(), model.ResourceListOptions{}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(list.KVPairs).To(HaveLen(3))
		Expect(list.Revision).To(Equal("100/200"),
			"revision should match the combined collection versions")
	})

	It("should only return the default allow profile by name", func() {
		list, err := client.List(context.TODO(), model.ResourceListOptions{
			Name: "projectcalico-default-allow",
		}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(list.KVPairs).To(HaveLen(1))
		Expect(list.Revision).To(Equal("1"),
			"revision should only relate to the namespace collection")
	})

	It("should only query namespaces when filtering to a namespace profile name", func() {
		list, err := client.List(context.TODO(), model.ResourceListOptions{
			Name: "kns.default",
		}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(list.KVPairs).To(HaveLen(1))
		Expect(list.Revision).To(Equal("100/"),
			"revision should only relate to the namespace collection")
	})

	It("should only query service accounts when filtering to a service account profile name", func() {
		list, err := client.List(context.TODO(), model.ResourceListOptions{
			Name: "ksa.default.default",
		}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(list.KVPairs).To(HaveLen(1))
		Expect(list.Revision).To(Equal("/200"),
			"revision should only relate to the sa collection")
	})
})

var _ = Describe("Profile client with ServiceAccount profiles enabled/disabled", func() {
	var clientSet *FakeClientSetWithListRevAndFiltering
	var client *profileClient

	BeforeEach(func() {
		clientSet = NewFakeClientSetWithListRevAndFiltering()
		clientSet.CurrentListRevisionByType["Namespace"] = "100"
		clientSet.CurrentListRevisionByType["ServiceAccount"] = "200"

		_, err := clientSet.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "default", ResourceVersion: "10", UID: uuid.NewUUID()},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, err = clientSet.CoreV1().ServiceAccounts("default").Create(context.TODO(), &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "default", ResourceVersion: "20", UID: uuid.NewUUID()},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		client = NewProfileClient(clientSet).(*profileClient)
	})

	profileNames := func(kvps []*model.KVPair) []string {
		var names []string
		for _, kvp := range kvps {
			names = append(names, kvp.Key.(model.ResourceKey).Name)
		}
		return names
	}

	saActions := func() []k8stesting.Action {
		var actions []k8stesting.Action
		for _, a := range clientSet.Actions() {
			if a.GetResource().Resource == "serviceaccounts" && a.GetVerb() != "create" {
				actions = append(actions, a)
			}
		}
		return actions
	}

	// createAndCollect creates a new namespace and service account after starting the watch,
	// then returns the names of all profiles seen on the watch within a short window.
	createAndCollect := func(w api.WatchInterface) []string {
		_, err := clientSet.CoreV1().ServiceAccounts("default").Create(context.TODO(), &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "new-sa", Namespace: "default", UID: uuid.NewUUID()},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, err = clientSet.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "new-ns", UID: uuid.NewUUID()},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		var names []string
		timeout := time.After(500 * time.Millisecond)
		for {
			select {
			case e := <-w.ResultChan():
				Expect(e.Error).NotTo(HaveOccurred())
				names = append(names, e.New.Key.(model.ResourceKey).Name)
			case <-timeout:
				return names
			}
		}
	}

	Context("with ServiceAccount profiles enabled (default)", func() {
		It("should default to enabled when the env var is unset", func() {
			Expect(client.disableServiceAccountProfiles).To(BeFalse())
		})

		It("should list ksa.* profiles", func() {
			list, err := client.List(context.TODO(), model.ResourceListOptions{}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(profileNames(list.KVPairs)).To(ConsistOf(
				"projectcalico-default-allow", "kns.default", "ksa.default.default"))
			Expect(list.Revision).To(Equal("100/200"))
			Expect(saActions()).NotTo(BeEmpty())
		})

		It("should get a ksa.* profile", func() {
			kvp, err := client.Get(context.TODO(), model.ResourceKey{Name: "ksa.default.default", Kind: "Profile"}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(kvp.Key.(model.ResourceKey).Name).To(Equal("ksa.default.default"))
		})

		It("should watch ksa.* profiles", func() {
			w, err := client.Watch(context.TODO(), model.ResourceListOptions{Kind: "Profile"}, api.WatchOptions{})
			Expect(err).NotTo(HaveOccurred())
			defer w.Stop()
			Expect(createAndCollect(w)).To(ConsistOf("ksa.default.new-sa", "kns.new-ns"))
		})
	})

	Context("with ServiceAccount profiles disabled", func() {
		BeforeEach(func() {
			client.disableServiceAccountProfiles = true
		})

		It("should list no ksa.* profiles and not query service accounts", func() {
			list, err := client.List(context.TODO(), model.ResourceListOptions{}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(profileNames(list.KVPairs)).To(ConsistOf("projectcalico-default-allow", "kns.default"))
			Expect(list.Revision).To(Equal("100/"))
			Expect(saActions()).To(BeEmpty())
		})

		It("should still list a namespace profile by name", func() {
			list, err := client.List(context.TODO(), model.ResourceListOptions{Name: "kns.default"}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(profileNames(list.KVPairs)).To(ConsistOf("kns.default"))
		})

		It("should return an empty list for a ksa.* profile name", func() {
			list, err := client.List(context.TODO(), model.ResourceListOptions{Name: "ksa.default.default"}, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(list.KVPairs).To(BeEmpty())
			Expect(saActions()).To(BeEmpty())
		})

		It("should return not-found when getting a ksa.* profile", func() {
			_, err := client.Get(context.TODO(), model.ResourceKey{Name: "ksa.default.default", Kind: "Profile"}, "")
			Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorResourceDoesNotExist{}))
			Expect(saActions()).To(BeEmpty())
		})

		It("should still get namespace and default-allow profiles", func() {
			_, err := client.Get(context.TODO(), model.ResourceKey{Name: "kns.default", Kind: "Profile"}, "")
			Expect(err).NotTo(HaveOccurred())
			_, err = client.Get(context.TODO(), model.ResourceKey{Name: "projectcalico-default-allow", Kind: "Profile"}, "")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should watch only namespace profiles", func() {
			// Resume from the revision returned by List, as the syncer would.
			list, err := client.List(context.TODO(), model.ResourceListOptions{}, "")
			Expect(err).NotTo(HaveOccurred())
			w, err := client.Watch(context.TODO(), model.ResourceListOptions{Kind: "Profile"}, api.WatchOptions{Revision: list.Revision})
			Expect(err).NotTo(HaveOccurred())
			defer w.Stop()
			names := createAndCollect(w)
			Expect(names).To(ConsistOf("kns.new-ns"))
			for _, n := range names {
				Expect(strings.HasPrefix(n, "ksa.")).To(BeFalse())
			}
			Expect(saActions()).To(BeEmpty())
		})

		It("should return a no-op watch for a ksa.* profile name", func() {
			w, err := client.Watch(context.TODO(), model.ResourceListOptions{Kind: "Profile", Name: "ksa.default.default"}, api.WatchOptions{})
			Expect(err).NotTo(HaveOccurred())
			defer w.Stop()
			Expect(createAndCollect(w)).To(BeEmpty())
			Expect(saActions()).To(BeEmpty())
		})
	})
})
