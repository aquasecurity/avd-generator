package main

import (
	"io/ioutil"
	"os"
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
			regoFile: "goldens/rego/appArmor.rego",
			expectedRegoPost: RegoPost{
				Layout: "regoPolicy",
				Title:  "KSV002",
				By:     "Aqua Security",
				Date:   "2020-07-13 19:43:21 +0000 UTC",
				Rego: Rego{
					ID:          "Apparmor policies are disabled for container",
					Description: "A program inside the container can bypass Apparmor protection policies.",
					Links:       nil,
					Severity:    "Medium",
					Policy: `package main

import data.lib.kubernetes

default failAppArmor = false

# getApparmorContainers returns all containers which have an apparmor
# profile set and is profile not set to "unconfined"
getApparmorContainers[container] {
  some i
  keys := [key | key := sprintf("%s/%s", ["container.apparmor.security.beta.kubernetes.io",
    kubernetes.containers[_].name])]
  apparmor := object.filter(kubernetes.annotations, keys)
  val := apparmor[i]
  val != "unconfined"
  [a, c] := split(i, "/")
  container = c
}

# getNoApparmorContainers returns all containers which do not have
# an apparmor profile specified or profile set to "unconfined"
getNoApparmorContainers[container] {
  container := kubernetes.containers[_].name
  not getApparmorContainers[container]
}

# failApparmor is true if there is ANY container without an apparmor profile
# or has an apparmor profile set to "unconfined"
failApparmor {
  count(getNoApparmorContainers) > 0
}

deny[msg] {
  failApparmor

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should specify an apparmor profile",
      [getNoApparmorContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}`,
					RecommendedActions: "Remove the 'unconfined' value from 'container.apparmor.security.beta.kubernetes.io'",
				},
			},
		},
		{
			name:     "happy path",
			regoFile: "goldens/rego/capsSysAdmin.rego",
			expectedRegoPost: RegoPost{
				Layout: "regoPolicy",
				Title:  "KSV005",
				By:     "Aqua Security",
				Date:   "2020-07-13 19:43:21 +0000 UTC",
				Rego: Rego{
					ID:          "Container should not include SYS_ADMIN capability",
					Description: "SYS_ADMIN gives the processes running inside the container privileges that are equivalent to root.",
					Links:       nil,
					Severity:    "High",
					Policy: `package main

import data.lib.kubernetes

default failCapsSysAdmin = false

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

deny[msg] {
  failCapsSysAdmin

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should not include 'SYS_ADMIN' in securityContext.capabilities.add",
      [getCapsSysAdmin[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}`,
					RecommendedActions: "Remove the SYS_ADMIN capability from 'containers[].securityContext.capabilities.add'",
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
		got, err := ParseAppShieldRegoPolicyFile(tc.regoFile)
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

		generateAppShieldRegoPolicyPages(policiesDir, postsDir)

		gotFiles, err := GetAllFiles(postsDir)
		require.NoError(t, err)
		assert.NotEmpty(t, gotFiles)
		for _, file := range gotFiles {
			got, _ := ioutil.ReadFile(file)
			assert.NotEmpty(t, got)

			// check a few files for correctness
			if file == "KSV002.md" {
				want, _ := ioutil.ReadFile("goldens/markdown/KSV002.md")
				assert.Equal(t, string(want), string(got))
			}

			if file == "KSV013.md" {
				want, _ := ioutil.ReadFile("goldens/markdown/KSV013.md")
				assert.Equal(t, string(want), string(got))
			}
		}
	})
}
