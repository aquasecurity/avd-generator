package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVulnerabilityJSONFile(t *testing.T) {
	testCases := []struct {
		fileName         string
		expectedBlogPost VulnerabilityPost
	}{
		{
			fileName: "goldens/json/nvd/CVE-2020-0001.json",
			expectedBlogPost: VulnerabilityPost{
				Layout: "vulnerability",
				Title:  "CVE-2020-0001",
				By:     "NVD",
				Date:   "2020-01-08 12:19:15 +0000",
				Vulnerability: Vulnerability{
					ID:          "CVE-2020-0001",
					CWEID:       "CWE-269",
					Description: "In getProcessRecordLocked of ActivityManagerService.java isolated apps are not handled correctly. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android Versions: Android-8.0, Android-8.1, Android-9, and Android-10 Android ID: A-140055304",
					References: []string{
						"https://source.android.com/security/bulletin/2020-01-01",
					},
					CVSS: CVSS{
						V2Vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C",
						V2Score:  7.2,
						V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
						V3Score:  7.8,
					},
					Dates: Dates{
						Published: "2020-01-08 12:19:15 +0000",
						Modified:  "2020-01-14 12:21:52 +0000",
					},
					NVDSeverityV2: "HIGH",
					NVDSeverityV3: "HIGH",
					AffectedSoftware: []AffectedSoftware{
						{
							Name:         "android",
							Vendor:       "google",
							StartVersion: "8.0",
							EndVersion:   "8.0",
						},
						{
							Name:         "android",
							Vendor:       "google",
							StartVersion: "8.1",
							EndVersion:   "8.1",
						},
						{
							Name:         "android",
							Vendor:       "google",
							StartVersion: "9.0",
							EndVersion:   "9.0",
						},
						{
							Name:         "android",
							Vendor:       "google",
							StartVersion: "10.0",
							EndVersion:   "10.0",
						},
					},
				},
			},
		},
		{
			fileName: "goldens/json/nvd/CVE-2020-11932.json",
			expectedBlogPost: VulnerabilityPost{
				Layout: "vulnerability",
				Title:  "CVE-2020-11932",
				By:     "NVD",
				Date:   "2020-05-13 12:01:15 +0000",
				Vulnerability: Vulnerability{
					ID:          "CVE-2020-11932",
					CWEID:       "CWE-532",
					Description: "It was discovered that the Subiquity installer for Ubuntu Server logged the LUKS full disk encryption password if one was entered.",
					References: []string{
						"https://github.com/CanonicalLtd/subiquity/commit/7db70650feaf513d7fb6f1ca07f2d670a0890613",
					},
					CVSS: CVSS{
						V2Vector: "AV:L/AC:L/Au:N/C:P/I:N/A:N",
						V2Score:  2.1,
						V3Vector: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
						V3Score:  2.3,
					},
					Dates: Dates{
						Published: "2020-05-13 12:01:15 +0000",
						Modified:  "2020-05-18 12:17:59 +0000",
					},
					NVDSeverityV2: "LOW",
					NVDSeverityV3: "LOW",
					AffectedSoftware: []AffectedSoftware{
						{
							Name:         "subiquity",
							Vendor:       "canonical",
							StartVersion: "*",
							EndVersion:   "*",
						},
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		actual, err := ParseVulnerabilityJSONFile(tc.fileName)
		require.NoError(t, err, tc.fileName)
		assert.Equal(t, tc.expectedBlogPost, actual, tc.fileName)
	}
}

func TestVulnerabilityPostToMarkdown(t *testing.T) {
	testCases := []struct {
		name           string
		inputBlogPost  VulnerabilityPost
		customContent  string
		expectedOutput string
	}{
		{
			name: "happy path with no custom content",
			inputBlogPost: VulnerabilityPost{
				Layout: "vulnerability",
				Title:  "CVE-2020-11932",
				By:     "NVD",
				Date:   "2020-05-13 12:01:15 +0000",
				Vulnerability: Vulnerability{
					ID:          "CVE-2020-11932",
					CWEID:       "CWE-532",
					Description: "It was discovered that the Subiquity installer for Ubuntu Server logged the LUKS full disk encryption password if one was entered.",
					References: []string{
						"https://github.com/CanonicalLtd/subiquity/commit/7db70650feaf513d7fb6f1ca07f2d670a0890613",
					},
					CVSS: CVSS{
						V2Vector: "AV:L/AC:L/Au:N/C:P/I:N/A:N",
						V2Score:  2.1,
						V3Vector: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
						V3Score:  2.3,
					},
					Dates: Dates{
						Published: "2020-05-13T00:01Z",
						Modified:  "2020-05-18T00:17Z",
					},
					NVDSeverityV2: "HIGH",
					NVDSeverityV3: "LOW",
					AffectedSoftware: []AffectedSoftware{
						{
							Name:         "foo-software",
							Vendor:       "foo-vendor",
							StartVersion: "1.2.3",
							EndVersion:   "4.5.6",
						},
					},
				},
			},
			expectedOutput: `---
title: "CVE-2020-11932"
date: 2020-05-13 12:01:15 +0000
draft: false

avd_page_type: nvd_page

date_published: 2020-05-13T00:01Z
date_modified: 2020-05-18T00:17Z

header_subtitle: ""

sidebar_additional_info_nvd: "https://nvd.nist.gov/vuln/detail/CVE-2020-11932"
sidebar_additional_info_cwe: "https://cwe.mitre.org/data/definitions/532.html"

cvss_nvd_v3_vector: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N"
cvss_nvd_v3_score: "2.3"
cvss_nvd_v3_severity: "LOW"

cvss_nvd_v2_vector: "AV:L/AC:L/Au:N/C:P/I:N/A:N"
cvss_nvd_v2_score: "2.1"
cvss_nvd_v2_severity: "HIGH"

redhat_v2_vector: "-"
redhat_v2_score: "0"
redhat_v2_severity: "-"

redhat_v3_vector: "-"
redhat_v3_score: "0"
redhat_v3_severity: "-"

ubuntu_vector: "-"
ubuntu_score: "-"
ubuntu_severity: "-"

---

It was discovered that the Subiquity installer for Ubuntu Server logged the LUKS full disk encryption password if one was entered.
### Affected Software {.with_icon .affected_software}
| Name | Vendor           | Start Version | End Version |
| ------------- |-------------|-----|----|
| Foo-software | Foo-vendor | 1.2.3 | 4.5.6|


### References  {.with_icon .references}
- https://github.com/CanonicalLtd/subiquity/commit/7db70650feaf513d7fb6f1ca07f2d670a0890613

<!--- Add Aqua content below --->`,
		},
		{
			name: "happy path with custom content",
			inputBlogPost: VulnerabilityPost{
				Layout: "vulnerability",
				Title:  "CVE-2020-1234",
				By:     "baz source",
				Date:   "2020-01-08 12:19:15 +0000",
				Vulnerability: Vulnerability{
					ID:          "CVE-2020-1234",
					CWEID:       "CWE-269",
					Description: "foo Description",
					References: []string{
						"https://foo.bar.baz.com",
						"https://baz.bar.foo.org",
					},
					CVSS: CVSS{
						V2Vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C",
						V2Score:  3.4,
						V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
						V3Score:  4.5,
					},
					Dates: Dates{
						Published: "2020-01-08T19:15Z",
						Modified:  "2020-01-14T21:52Z",
					},
					NVDSeverityV2: "HIGH",
					NVDSeverityV3: "LOW",
					AffectedSoftware: []AffectedSoftware{
						{
							Name:         "foo-software",
							Vendor:       "foo-vendor",
							StartVersion: "1.2.3",
							EndVersion:   "4.5.6",
						},
					},
				},
			},
			customContent: `---
### foo heading
bar content`,
			expectedOutput: `---
title: "CVE-2020-1234"
date: 2020-01-08 12:19:15 +0000
draft: false

avd_page_type: nvd_page

date_published: 2020-01-08T19:15Z
date_modified: 2020-01-14T21:52Z

header_subtitle: ""

sidebar_additional_info_nvd: "https://nvd.nist.gov/vuln/detail/CVE-2020-1234"
sidebar_additional_info_cwe: "https://cwe.mitre.org/data/definitions/269.html"

cvss_nvd_v3_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
cvss_nvd_v3_score: "4.5"
cvss_nvd_v3_severity: "LOW"

cvss_nvd_v2_vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C"
cvss_nvd_v2_score: "3.4"
cvss_nvd_v2_severity: "HIGH"

redhat_v2_vector: "-"
redhat_v2_score: "0"
redhat_v2_severity: "-"

redhat_v3_vector: "-"
redhat_v3_score: "0"
redhat_v3_severity: "-"

ubuntu_vector: "-"
ubuntu_score: "-"
ubuntu_severity: "-"

---

foo Description
### Affected Software {.with_icon .affected_software}
| Name | Vendor           | Start Version | End Version |
| ------------- |-------------|-----|----|
| Foo-software | Foo-vendor | 1.2.3 | 4.5.6|


### References  {.with_icon .references}
- https://foo.bar.baz.com
- https://baz.bar.foo.org

<!--- Add Aqua content below --->
---
### foo heading
bar content`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.inputBlogPost.Vulnerability.ID, func(t *testing.T) {
			f, _ := ioutil.TempFile("", "TestBlogPostToMarkdownFile-*")
			defer func() {
				_ = os.RemoveAll(f.Name())
			}()

			require.NoError(t, VulnerabilityPostToMarkdown(tc.inputBlogPost, f, tc.customContent), tc.name)
			actual, _ := ioutil.ReadFile(f.Name())
			assert.Equal(t, tc.expectedOutput, string(actual), tc.name)
		})
	}

}

func TestGetCustomContentFromMarkdown(t *testing.T) {
	// TODO: Add more test cases
	gotCustomContent := GetCustomContentFromMarkdown("goldens/markdown/CVE-2020-0002.md")
	assert.Equal(t, `---
### foo heading
bar content`, gotCustomContent)
}

func TestGetAllFiles(t *testing.T) {
	actual, err := GetAllFiles("goldens/json/nvd")
	require.NoError(t, err)
	assert.Equal(t, []string{"CVE-2020-0001.json", "CVE-2020-0002.json", "CVE-2020-11932.json"}, actual)
}

func TestGenerateVulnerabilityPages(t *testing.T) {
	t.Run("happy path no file with custom content", func(t *testing.T) {
		nvdDir := "goldens/json/nvd"
		postsDir, _ := ioutil.TempDir("", "TestGenerateVulnerabilityPages-*")
		defer func() {
			_ = os.RemoveAll(postsDir)
		}()
		cweDir := "goldens/cwe"
		b, _ := ioutil.ReadFile(filepath.Join(cweDir, "CWE-416.json")) // One test file within the golden directory
		var weaknesses WeaknessType
		err := json.Unmarshal(b, &weaknesses)
		require.NoError(t, err)

		generateVulnerabilityPages(nvdDir, cweDir, postsDir)

		gotFiles, err := GetAllFiles(postsDir)
		require.NoError(t, err)
		for _, file := range gotFiles {
			b, _ := ioutil.ReadFile(filepath.Join(postsDir, file))
			assert.NotEmpty(t, b)

			if file == "CVE-2020-0002.md" {
				assert.Equal(t, `---
title: "CVE-2020-0002"
date: 2020-01-08 12:19:15 +0000
draft: false

avd_page_type: nvd_page

date_published: 2020-01-08 12:19:15 +0000
date_modified: 2020-01-29 12:21:15 +0000

header_subtitle: "Generation of Error Message Containing Sensitive Information"

sidebar_additional_info_nvd: "https://nvd.nist.gov/vuln/detail/CVE-2020-0002"
sidebar_additional_info_cwe: "https://cwe.mitre.org/data/definitions/416.html"

cvss_nvd_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
cvss_nvd_v3_score: "8.8"
cvss_nvd_v3_severity: "HIGH"

cvss_nvd_v2_vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C"
cvss_nvd_v2_score: "9.3"
cvss_nvd_v2_severity: "HIGH"

redhat_v2_vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"
redhat_v2_score: "4.3"
redhat_v2_severity: "MODERATE"

redhat_v3_vector: "-"
redhat_v3_score: "0"
redhat_v3_severity: "MODERATE"

ubuntu_vector: "-"
ubuntu_score: "-"
ubuntu_severity: "LOW"

---

In ih264d_init_decoder of ih264d_api.c, there is a possible out of bounds write due to a use after free. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation Product: Android Versions: Android-8.0, Android-8.1, Android-9, and Android-10 Android ID: A-142602711
### Weakness {.with_icon .weakness}
The software generates an error message that includes sensitive information about its environment, users, or associated data.

### Affected Software {.with_icon .affected_software}
| Name | Vendor           | Start Version | End Version |
| ------------- |-------------|-----|----|
| Android | Google | 1.1.1 | 1.1.1c|
| Android | Google | 8.1 | 8.1|
| Android | Google | 9.0 | 9.0|
| Android | Google | 10.0 | 10.0|
| Red Hat Enterprise Linux 6 Supplementary | RedHat | chromium-browser-80.0.3987.87-1.el6_10 | *|
| Tar | Ubuntu | bionic | *|
| Tar | Ubuntu | cosmic | *|
| Tar | Ubuntu | devel | *|
| Tar | Ubuntu | disco | *|
| Tar | Ubuntu | eoan | *|
| Tar | Ubuntu | focal | *|
| Tar | Ubuntu | trusty | *|
| Tar | Ubuntu | upstream | *|
| Tar | Ubuntu | xenial | *|

### Extended Description
The sensitive information may be valuable information on its own (such as a password), or it may be useful for launching other, more serious attacks. The error message may be created in different ways:

                    
                
An attacker may use the contents of error messages to help launch another, more focused attack. For example, an attempt to exploit a path traversal weakness (CWE-22) might yield the full pathname of the installed application. In turn, this could be used to select the proper number of ".." sequences to navigate to the targeted file. An attack using SQL injection (CWE-89) might not initially succeed, but an error message could reveal the malformed query, which would expose query logic and possibly even passwords or other sensitive information used within the query.

### Potential Mitigations {.with_icon .mitigations}
- Ensure that error messages only contain minimal details that are useful to the intended audience, and nobody else. The messages need to strike the balance between being too cryptic and not being cryptic enough. They should not necessarily reveal the methods that were used to determine the error. Such detailed information can be used to refine the original attack to increase the chances of success.
- If errors must be tracked in some detail, capture them in log messages - but consider what could occur if the log messages can be viewed by attackers. Avoid recording highly sensitive information such as passwords in any form. Avoid inconsistent messaging that might accidentally tip off an attacker about internal state, such as whether a username is valid or not.

### Related Attack Patterns {.with_icon .related_patterns}
- https://cwe.mitre.org/data/definitions/214.html
- https://cwe.mitre.org/data/definitions/215.html
- https://cwe.mitre.org/data/definitions/463.html
- https://cwe.mitre.org/data/definitions/54.html
- https://cwe.mitre.org/data/definitions/7.html


### References  {.with_icon .references}
- https://source.android.com/security/bulletin/2020-01-01

<!--- Add Aqua content below --->`, string(b))
			}
		}
	})

	t.Run("happy path, one file with existing custom content", func(t *testing.T) {
		nvdDir := "goldens/json/nvd"
		postsDir, _ := ioutil.TempDir("", "TestGenerate-*")
		defer func() {
			_ = os.RemoveAll(postsDir)
		}()
		cweDir := "goldens/cwe"
		b, _ := ioutil.ReadFile(filepath.Join(cweDir, "CWE-416.json")) // One test file within the golden directory
		var weakness WeaknessType
		err := json.Unmarshal(b, &weakness)
		require.NoError(t, err)

		b1, _ := ioutil.ReadFile("goldens/markdown/CVE-2020-0002.md")
		_ = ioutil.WriteFile(filepath.Join(postsDir, "CVE-2020-0002.md"), b1, 0600)

		generateVulnerabilityPages(nvdDir, cweDir, postsDir)

		gotFiles, err := GetAllFiles(postsDir)
		require.NoError(t, err)
		for _, file := range gotFiles {
			b, _ := ioutil.ReadFile(filepath.Join(postsDir, file))
			assert.NotEmpty(t, b, file)

			if file == "CVE-2020-0002.md" {
				assert.Equal(t, `---
title: "CVE-2020-0002"
date: 2020-01-08 12:19:15 +0000
draft: false

avd_page_type: nvd_page

date_published: 2020-01-08 12:19:15 +0000
date_modified: 2020-01-29 12:21:15 +0000

header_subtitle: "Generation of Error Message Containing Sensitive Information"

sidebar_additional_info_nvd: "https://nvd.nist.gov/vuln/detail/CVE-2020-0002"
sidebar_additional_info_cwe: "https://cwe.mitre.org/data/definitions/416.html"

cvss_nvd_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
cvss_nvd_v3_score: "8.8"
cvss_nvd_v3_severity: "HIGH"

cvss_nvd_v2_vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C"
cvss_nvd_v2_score: "9.3"
cvss_nvd_v2_severity: "HIGH"

redhat_v2_vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"
redhat_v2_score: "4.3"
redhat_v2_severity: "MODERATE"

redhat_v3_vector: "-"
redhat_v3_score: "0"
redhat_v3_severity: "MODERATE"

ubuntu_vector: "-"
ubuntu_score: "-"
ubuntu_severity: "LOW"

---

In ih264d_init_decoder of ih264d_api.c, there is a possible out of bounds write due to a use after free. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation Product: Android Versions: Android-8.0, Android-8.1, Android-9, and Android-10 Android ID: A-142602711
### Weakness {.with_icon .weakness}
The software generates an error message that includes sensitive information about its environment, users, or associated data.

### Affected Software {.with_icon .affected_software}
| Name | Vendor           | Start Version | End Version |
| ------------- |-------------|-----|----|
| Android | Google | 1.1.1 | 1.1.1c|
| Android | Google | 8.1 | 8.1|
| Android | Google | 9.0 | 9.0|
| Android | Google | 10.0 | 10.0|
| Red Hat Enterprise Linux 6 Supplementary | RedHat | chromium-browser-80.0.3987.87-1.el6_10 | *|
| Tar | Ubuntu | bionic | *|
| Tar | Ubuntu | cosmic | *|
| Tar | Ubuntu | devel | *|
| Tar | Ubuntu | disco | *|
| Tar | Ubuntu | eoan | *|
| Tar | Ubuntu | focal | *|
| Tar | Ubuntu | trusty | *|
| Tar | Ubuntu | upstream | *|
| Tar | Ubuntu | xenial | *|

### Extended Description
The sensitive information may be valuable information on its own (such as a password), or it may be useful for launching other, more serious attacks. The error message may be created in different ways:

                    
                
An attacker may use the contents of error messages to help launch another, more focused attack. For example, an attempt to exploit a path traversal weakness (CWE-22) might yield the full pathname of the installed application. In turn, this could be used to select the proper number of ".." sequences to navigate to the targeted file. An attack using SQL injection (CWE-89) might not initially succeed, but an error message could reveal the malformed query, which would expose query logic and possibly even passwords or other sensitive information used within the query.

### Potential Mitigations {.with_icon .mitigations}
- Ensure that error messages only contain minimal details that are useful to the intended audience, and nobody else. The messages need to strike the balance between being too cryptic and not being cryptic enough. They should not necessarily reveal the methods that were used to determine the error. Such detailed information can be used to refine the original attack to increase the chances of success.
- If errors must be tracked in some detail, capture them in log messages - but consider what could occur if the log messages can be viewed by attackers. Avoid recording highly sensitive information such as passwords in any form. Avoid inconsistent messaging that might accidentally tip off an attacker about internal state, such as whether a username is valid or not.

### Related Attack Patterns {.with_icon .related_patterns}
- https://cwe.mitre.org/data/definitions/214.html
- https://cwe.mitre.org/data/definitions/215.html
- https://cwe.mitre.org/data/definitions/463.html
- https://cwe.mitre.org/data/definitions/54.html
- https://cwe.mitre.org/data/definitions/7.html


### References  {.with_icon .references}
- https://source.android.com/security/bulletin/2020-01-01

<!--- Add Aqua content below --->
---
### foo heading
bar content`, string(b))
			}
		}
	})
}

func TestParseRegoPolicyFile(t *testing.T) {
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
		got, err := ParseRegoPolicyFile(tc.regoFile)
		switch {
		case tc.expectedError != "":
			assert.Equal(t, tc.expectedError, err.Error(), tc.name)
		default:
			assert.NoError(t, err, tc.name)
		}
		assert.Equal(t, tc.expectedRegoPost, got, tc.name)
	}
}

func TestGenerateRegoPolicyPages(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		policiesDir := "goldens/rego"
		postsDir, _ := ioutil.TempDir("", "TestGenerateRegoPolicyPages-*")
		defer func() {
			_ = os.RemoveAll(postsDir)
		}()

		generateRegoPolicyPages(policiesDir, postsDir)

		gotFiles, err := GetAllFiles(postsDir)
		require.NoError(t, err)
		assert.NotEmpty(t, gotFiles)
		for _, file := range gotFiles {
			got, _ := ioutil.ReadFile(filepath.Join(postsDir, file))
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
