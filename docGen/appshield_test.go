package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAppShieldRegoPolicyFile(t *testing.T) {
	testCases := []struct {
		name             string
		regoFile         string
		expectedRegoPost string
		expectedError    string
	}{
		{
			name:     "happy path",
			regoFile: "../goldens/rego/Baseline #6 - AppArmor policy disabled.rego",
			expectedRegoPost: `---
title: 
id: KSV002
aliases: [
	"/appshield/ksv002"
]
icon: appshield
source: Trivy
draft: false
date: 2021-04-15T20:55:39Z
severity: medium
version: v1.0.0
shortName: 
category: misconfig
keywords: "KSV002"

avd_page_type: defsec_page

remediations:
  - kubernetes


breadcrumbs: 
  - name: Kubernetes
    path: /misconfig/
---

### AppArmor policies disabled
A program inside the container can bypass AppArmor protection policies.

### Recommended Actions
Remove the 'unconfined' value from 'container.apparmor.security.beta.kubernetes.io'.

### Links
- [REGO Policy Document](https://github.com/aquasecurity/appshield/tree/master/../goldens/rego/Baseline #6 - AppArmor policy disabled.rego)
- https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
`,
		},
		{
			name:     "happy path",
			regoFile: "../goldens/rego/SYS_ADMIN_capability.rego",
			expectedRegoPost: `---
title: 
id: KSV005
aliases: [
	"/appshield/ksv005"
]
icon: appshield
source: Trivy
draft: false
date: 2021-04-15T20:55:39Z
severity: high
version: v1.0.0
shortName: 
category: misconfig
keywords: "KSV005"

avd_page_type: defsec_page

remediations:
  - kubernetes


breadcrumbs: 
  - name: Kubernetes
    path: /misconfig/
---

### SYS_ADMIN capability added
SYS_ADMIN gives the processes running inside the container privileges that are equivalent to root.

### Recommended Actions
Remove the SYS_ADMIN capability from 'containers[].securityContext.capabilities.add'.

### Links
- [REGO Policy Document](https://github.com/aquasecurity/appshield/tree/master/../goldens/rego/SYS_ADMIN_capability.rego)
`,
		},
		{
			name:          "sad path",
			regoFile:      "some/unknown/file",
			expectedError: "open some/unknown/file: no such file or directory",
		},
	}

	for _, tc := range testCases {
		regoPost, err := parseAppShieldRegoPolicyFile(tc.regoFile, fakeClock{})
		switch {
		case tc.expectedError != "":
			assert.Equal(t, tc.expectedError, err.Error(), tc.name)
			continue
		default:
			assert.NoError(t, err, tc.name)
		}

		gotBuffer := bytes.NewBuffer([]byte{})
		err = regoPostToMarkdown(*regoPost, gotBuffer)
		require.NoError(t, err)
		assert.Equal(t, tc.expectedRegoPost, gotBuffer.String(), tc.name)
	}
}

func Test_generateAppShieldRegoPolicyPages(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		policiesDir := "../goldens/rego"
		postsDir, _ := ioutil.TempDir("", "TestGenerateRegoPolicyPages-*")
		defer func() {
			_ = os.RemoveAll(postsDir)
		}()

		generateAppShieldRegoPolicyPages(policiesDir, policiesDir, postsDir, fakeClock{})

		gotFiles, err := getAllFiles(postsDir)
		require.NoError(t, err)
		assert.Equal(t, 3, len(gotFiles))
		for _, file := range gotFiles {
			got, _ := ioutil.ReadFile(file)
			assert.NotEmpty(t, got)

			// check a few files for correctness
			if strings.Contains(file, "KSV002.md") {
				want, _ := ioutil.ReadFile("../goldens/markdown/KSV002.md")
				assert.Equal(t, string(want), string(got))
			}

			if strings.Contains(file, "KSV005.md") {
				want, _ := ioutil.ReadFile("../goldens/markdown/KSV005.md")
				assert.Equal(t, string(want), string(got))
			}
		}
	})
}
