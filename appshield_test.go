package main

import (
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
		expectedRegoPost RegoPost
		expectedError    string
	}{
		{
			name:     "happy path",
			regoFile: "goldens/rego/Baseline #6 - AppArmor policy disabled.rego",
			expectedRegoPost: RegoPost{
				Layout: "regoPolicy",
				Title:  "AppArmor policies disabled",
				By:     "Aqua Security",
				Date:   "2021-04-15T20:55:39Z",
				Rego: Rego{
					ID:          "KSV002",
					Version:     "v1.0.0",
					Description: "A program inside the container can bypass AppArmor protection policies.",
					Links:       []string{"https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline"},
					Severity:    "Informative",
					Policy: `package appshield.kubernetes.KSV002

import data.lib.kubernetes

default failAppArmor = false

__rego_metadata__ := {
     "id": "KSV002",
     "title": "AppArmor policies disabled",
     "version": "v1.0.0",
     "severity": "Medium",
     "type": "Kubernetes Security Check",
     "description": "A program inside the container can bypass AppArmor protection policies.",
     "recommended_actions": "Remove the 'unconfined' value from 'container.apparmor.security.beta.kubernetes.io'.",
     "url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

# getApparmorContainers returns all containers which have an AppArmor
# profile set and is profile not set to "unconfined"
getApparmorContainers[container] {
  some i
  keys := [key | key := sprintf("%s/%s", ["container.apparmor.security.beta.kubernetes.io",
    kubernetes.containers[_].name])]
  apparmor := object.filter(kubernetes.annotations[_], keys)
  val := apparmor[i]
  val != "unconfined"
  [a, c] := split(i, "/")
  container = c
}

# getNoApparmorContainers returns all containers which do not have
# an AppArmor profile specified or profile set to "unconfined"
getNoApparmorContainers[container] {
  container := kubernetes.containers[_].name
  not getApparmorContainers[container]
}

# failApparmor is true if there is ANY container without an AppArmor profile
# or has an AppArmor profile set to "unconfined"
failApparmor {
  count(getNoApparmorContainers) > 0
}

deny[res] {
  failApparmor

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should specify an AppArmor profile",
      [getNoApparmorContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
    res := {
    	"msg": msg,
        "id":  __rego_metadata__.id,
        "title": __rego_metadata__.title,
        "severity": __rego_metadata__.severity,
        "type":  __rego_metadata__.type,
    }
}`,
					RecommendedActions: "Remove the 'unconfined' value from 'container.apparmor.security.beta.kubernetes.io'.",
				},
			},
		},
		{
			name:     "happy path",
			regoFile: "goldens/rego/SYS_ADMIN_capability.rego",
			expectedRegoPost: RegoPost{
				Layout: "regoPolicy",
				Title:  "SYS_ADMIN capability added",
				By:     "Aqua Security",
				Date:   "2021-04-15T20:55:39Z",
				Rego: Rego{
					ID:          "KSV005",
					Version:     "v1.0.0",
					Description: "SYS_ADMIN gives the processes running inside the container privileges that are equivalent to root.",
					Links:       nil,
					Severity:    "Informative",
					Policy: `package appshield.kubernetes.KSV005

import data.lib.kubernetes

default failCapsSysAdmin = false

__rego_metadata__ := {
     "id": "KSV005",
     "title": "SYS_ADMIN capability added",
     "version": "v1.0.0",
     "severity": "High",
     "type": "Kubernetes Security Check",
     "description": "SYS_ADMIN gives the processes running inside the container privileges that are equivalent to root.",
     "recommended_actions": "Remove the SYS_ADMIN capability from 'containers[].securityContext.capabilities.add'.",
}

# getCapsSysAdmin returns the names of all containers which include
# 'SYS_ADMIN' in securityContext.capabilities.add.
getCapsSysAdmin[container] {
  allContainers := kubernetes.containers[_]
  allContainers.securityContext.capabilities.add[_] == "SYS_ADMIN"
  container := allContainers.name
}

# failCapsSysAdmin is true if securityContext.capabilities.add
# includes 'SYS_ADMIN'.
failCapsSysAdmin {
  count(getCapsSysAdmin) > 0
}

deny[res] {
  failCapsSysAdmin

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should not include 'SYS_ADMIN' in securityContext.capabilities.add",
      [getCapsSysAdmin[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
    res := {
    	"msg": msg,
        "id":  __rego_metadata__.id,
        "title": __rego_metadata__.title,
        "severity": __rego_metadata__.severity,
        "type":  __rego_metadata__.type,
    }
}`,
					RecommendedActions: "Remove the SYS_ADMIN capability from 'containers[].securityContext.capabilities.add'.",
				},
			},
		},
		{
			name:          "sad path",
			regoFile:      "some/unknown/file",
			expectedError: "open some/unknown/file: no such file or directory",
		},
	}

	for _, tc := range testCases {
		got, err := ParseAppShieldRegoPolicyFile(tc.regoFile, fakeClock{})
		switch {
		case tc.expectedError != "":
			assert.Equal(t, tc.expectedError, err.Error(), tc.name)
		default:
			assert.NoError(t, err, tc.name)
		}
		assert.Equal(t, tc.expectedRegoPost, got, tc.name)
	}
}

func Test_generateAppShieldRegoPolicyPages(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		policiesDir := "goldens/rego"
		postsDir, _ := ioutil.TempDir("", "TestGenerateRegoPolicyPages-*")
		defer func() {
			_ = os.RemoveAll(postsDir)
		}()

		generateAppShieldRegoPolicyPages(policiesDir, postsDir, fakeClock{})

		gotFiles, err := GetAllFiles(postsDir)
		require.NoError(t, err)
		assert.Equal(t, 3, len(gotFiles))
		for _, file := range gotFiles {
			got, _ := ioutil.ReadFile(file)
			assert.NotEmpty(t, got)

			// check a few files for correctness
			if strings.Contains(file, "KSV002.md") {
				want, _ := ioutil.ReadFile("goldens/markdown/KSV002.md")
				assert.Equal(t, string(want), string(got))
			}

			if strings.Contains(file, "KSV005.md") {
				want, _ := ioutil.ReadFile("goldens/markdown/KSV005.md")
				assert.Equal(t, string(want), string(got))
			}
		}
	})
}
