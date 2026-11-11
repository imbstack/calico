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
	"strconv"

	log "github.com/sirupsen/logrus"
)

// EnvDisableServiceAccountProfiles is the environment variable that, when set to a true value,
// stops the KDD backend from synthesizing "ksa.<namespace>.<name>" Profiles from Kubernetes
// ServiceAccounts, and stops pods' WorkloadEndpoints from referencing them.
//
// With this set, policy rules that use serviceAccountSelector (which matches the "pcsa.*" labels
// carried by the ServiceAccount profiles) will not match any workload. Rules that match only on
// service account names are unaffected, since those match the projectcalico.org/serviceaccount
// label that is applied directly to the WorkloadEndpoint.
//
// In a KDD + Typha deployment this only needs to be set on Typha, which runs the syncer and the
// pod to WorkloadEndpoint conversion. Without Typha, set it on calico-node instead.
const EnvDisableServiceAccountProfiles = "CALICO_DISABLE_SERVICE_ACCOUNT_PROFILES"

// serviceAccountProfilesDisabled is read once at package initialization.
var serviceAccountProfilesDisabled = readDisableServiceAccountProfilesEnv()

// ServiceAccountProfilesDisabled returns true if EnvDisableServiceAccountProfiles was set to a true
// value when the process started.
func ServiceAccountProfilesDisabled() bool {
	return serviceAccountProfilesDisabled
}

func readDisableServiceAccountProfilesEnv() bool {
	val, ok := os.LookupEnv(EnvDisableServiceAccountProfiles)
	if !ok || val == "" {
		return false
	}
	disabled, err := strconv.ParseBool(val)
	if err != nil {
		log.WithError(err).WithField(EnvDisableServiceAccountProfiles, val).Warn(
			"Failed to parse environment variable as a boolean; ServiceAccount profiles remain enabled")
		return false
	}
	if disabled {
		log.Infof("%s is set; Kubernetes ServiceAccounts will not be converted to Calico Profiles",
			EnvDisableServiceAccountProfiles)
	}
	return disabled
}
