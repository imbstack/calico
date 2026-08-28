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
	"regexp"
	"strings"

	"github.com/docopt/docopt-go"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// documentedOptions extracts the long options from the Options: section of a
// docopt usage string, along with whether each one takes an argument.
func documentedOptions(doc string) map[string]bool {
	_, options, _ := strings.Cut(doc, "\nOptions:\n")
	options, _, _ = strings.Cut(options, "\nDescription:\n")

	takesArg := map[string]bool{}
	re := regexp.MustCompile(`(?m)^\s+(?:-\w )?(--[\w-]+)(=)?`)
	for _, m := range re.FindAllStringSubmatch(options, -1) {
		takesArg[m[1]] = m[2] == "="
	}
	return takesArg
}

var _ = Describe("ipam configure", func() {
	// An option that is described under Options: but missing from the Usage:
	// pattern is silently unusable: docopt fails to match it and Configure
	// reports "invalid option". This caught --ip-cooldown-seconds.
	It("should accept every option it documents", func() {
		doc := configureDoc()
		opts := documentedOptions(doc)
		Expect(opts).To(HaveKey("--ip-cooldown-seconds"))

		for opt, takesArg := range opts {
			if opt == "--help" {
				// docopt handles --help itself by printing and exiting.
				continue
			}
			arg := opt
			if takesArg {
				arg = opt + "=1"
			}
			_, err := docopt.ParseArgs(doc, []string{"ipam", "configure", arg}, "")
			Expect(err).NotTo(HaveOccurred(), "option %s is documented but not in the Usage: pattern", opt)
		}
	})

	It("should parse the value of --ip-cooldown-seconds", func() {
		parsed, err := docopt.ParseArgs(configureDoc(), []string{"ipam", "configure", "--ip-cooldown-seconds=300"}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(parsed["--ip-cooldown-seconds"]).To(Equal("300"))
	})
})
