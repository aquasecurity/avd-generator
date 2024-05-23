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
			fileName: "../goldens/json/nvd/2020/CVE-2020-0001.json",
			expectedBlogPost: VulnerabilityPost{
				Layout: "vulnerability",
				Title:  "CVE-2020-0001",
				By:     "NVD",
				Date:   "2020-01-08 07:15:12 +0000",
				Vulnerability: Vulnerability{
					ID:          "CVE-2020-0001",
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
						Published: "2020-01-08 07:15:12 +0000",
						Modified:  "2021-07-21 11:39:23 +0000",
					},
					NVDSeverityV2: "HIGH",
					NVDSeverityV3: "HIGH",
					AffectedSoftware: []AffectedSoftware{
						{
							Name:         "android",
							Vendor:       "google",
							StartVersion: "8.0 (including)",
							EndVersion:   "8.0 (including)",
						},
						{
							Name:         "android",
							Vendor:       "google",
							StartVersion: "8.1 (including)",
							EndVersion:   "8.1 (including)",
						},
						{
							Name:         "android",
							Vendor:       "google",
							StartVersion: "9.0-beta1 (including)",
							EndVersion:   "9.0-beta1 (including)",
						},
						{
							Name:         "android",
							Vendor:       "google",
							StartVersion: "10.0 (including)",
							EndVersion:   "10.0 (including)",
						},
					},
				},
			},
		},
		{
			fileName: "../goldens/json/nvd/2020/CVE-2020-11932.json",
			expectedBlogPost: VulnerabilityPost{
				Layout: "vulnerability",
				Title:  "CVE-2020-11932",
				By:     "NVD",
				Date:   "2020-05-13 01:15:12 +0000",
				Vulnerability: Vulnerability{
					ID:          "CVE-2020-11932",
					CWEID:       "CWE-532",
					Description: "It was discovered that the Subiquity installer for Ubuntu Server logged the LUKS full disk encryption password if one was entered.",
					References: []string{
						"https://aliceandbob.company/the-human-factor-in-an-economy-of-scale",
						"https://github.com/CanonicalLtd/subiquity/commit/7db70650feaf513d7fb6f1ca07f2d670a0890613",
					},
					CVSS: CVSS{
						V2Vector: "AV:L/AC:L/Au:N/C:P/I:N/A:N",
						V2Score:  2.1,
						V3Vector: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N",
						V3Score:  2.3,
					},
					Dates: Dates{
						Published: "2020-05-13 01:15:12 +0000",
						Modified:  "2020-08-03 06:15:11 +0000",
					},
					NVDSeverityV2: "LOW",
					NVDSeverityV3: "LOW",
					AffectedSoftware: []AffectedSoftware{
						{
							Name:         "subiquity",
							Vendor:       "canonical",
							StartVersion: "*",
							EndVersion:   "20.05.2 (excluding)",
						},
					},
				},
			},
		},
		{
			fileName: "../goldens/json/nvd/2020/CVE-2022-2788.json",
			expectedBlogPost: VulnerabilityPost{
				Layout: "vulnerability",
				Title:  "CVE-2022-2788",
				By:     "NVD",
				Date:   "2022-08-19 09:15:08 +0000",
				Vulnerability: Vulnerability{
					ID:          "CVE-2022-2788",
					CWEID:       "CWE-22",
					Description: "Emerson Electrics Proficy Machine Edition Version 9.80 and prior is vulnerable to CWE-29 Path Traversal: ..Filename, also known as a ZipSlip attack, through an upload procedure which enables attackers to implant a malicious .BLZ file on the PLC. The file can transfer through the engineering station onto Windows in a way that executes the malicious code.",
					References: []string{
						"https://www.cisa.gov/uscert/ics/advisories/icsa-22-228-06",
					},
					CVSS: CVSS{
						V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H",
						V3Score:  7.3,
					},
					Dates: Dates{
						Published: "2022-08-19 09:15:08 +0000",
						Modified:  "2023-06-28 02:25:03 +0000",
					},
					NVDSeverityV3: "HIGH",
					AffectedSoftware: []AffectedSoftware{
						{
							Name:         "electric's_proficy",
							Vendor:       "emerson",
							StartVersion: "*",
							EndVersion:   "9.80 (including)",
						},
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		actual, err := parseVulnerabilityJSONFile(tc.fileName)
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
							StartVersion: "1.2.3 (including)",
							EndVersion:   "4.5.6 (excluding)",
						},
					},
				},
			},
			expectedOutput: `---
title: "CVE-2020-11932"
aliases: [
	"/nvd/cve-2020-11932"
]

shortName: ""
date: 2020-05-13 12:01:15 +0000
category: vulnerabilities
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

redhat_v2_vector: "N/A"
redhat_v2_score: "0"
redhat_v2_severity: "N/A"

redhat_v3_vector: "N/A"
redhat_v3_score: "0"
redhat_v3_severity: "N/A"

ubuntu_vector: "N/A"
ubuntu_score: "N/A"
ubuntu_severity: "N/A"

---

It was discovered that the Subiquity installer for Ubuntu Server logged the LUKS full disk encryption password if one was entered.
### Affected Software {.with_icon .affected_software}
| Name | Vendor           | Start Version | End Version |
| ------------- |-------------|-----|----|
| Foo-software | Foo-vendor | 1.2.3 (including) | 4.5.6 (excluding)|


### References  {.with_icon .references}
- https://github.com/CanonicalLtd/subiquity/commit/7db70650feaf513d7fb6f1ca07f2d670a0890613

<!--- Add Aqua content below --->`,
		},
		{
			name: "happy path with custom content",
			inputBlogPost: VulnerabilityPost{
				Layout:    "vulnerability",
				Title:     "CVE-2020-1234",
				ShortName: "foo cwe info name",
				By:        "baz source",
				Date:      "2020-01-08 12:19:15 +0000",
				Vulnerability: Vulnerability{
					ID:    "CVE-2020-1234",
					CWEID: "CWE-269",
					CWEInfo: WeaknessType{
						Name: "foo cwe info name",
					},
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
							StartVersion: "1.2.3 (including)",
							EndVersion:   "4.5.6 (excluding)",
						},
					},
				},
			},
			customContent: `---
		### foo heading
		bar content`,
			expectedOutput: `---
title: "CVE-2020-1234"
aliases: [
	"/nvd/cve-2020-1234"
]

shortName: "foo cwe info name"
date: 2020-01-08 12:19:15 +0000
category: vulnerabilities
draft: false

avd_page_type: nvd_page

date_published: 2020-01-08T19:15Z
date_modified: 2020-01-14T21:52Z

header_subtitle: "foo cwe info name"

sidebar_additional_info_nvd: "https://nvd.nist.gov/vuln/detail/CVE-2020-1234"
sidebar_additional_info_cwe: "https://cwe.mitre.org/data/definitions/269.html"

cvss_nvd_v3_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
cvss_nvd_v3_score: "4.5"
cvss_nvd_v3_severity: "LOW"

cvss_nvd_v2_vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C"
cvss_nvd_v2_score: "3.4"
cvss_nvd_v2_severity: "HIGH"

redhat_v2_vector: "N/A"
redhat_v2_score: "0"
redhat_v2_severity: "N/A"

redhat_v3_vector: "N/A"
redhat_v3_score: "0"
redhat_v3_severity: "N/A"

ubuntu_vector: "N/A"
ubuntu_score: "N/A"
ubuntu_severity: "N/A"

---

foo Description
### Affected Software {.with_icon .affected_software}
| Name | Vendor           | Start Version | End Version |
| ------------- |-------------|-----|----|
| Foo-software | Foo-vendor | 1.2.3 (including) | 4.5.6 (excluding)|


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
	testCases := []struct {
		name            string
		inputContents   string
		expectedContent string
	}{
		{
			name: "happy path",
			inputContents: `---
title: "CVE-2020-0002"
date: 2020-01-08 12:19:15 +0000
draft: false
---
### Description
In ih264d_init_decoder of ih264d_api.c, there is a possible out of bounds write due to a use after free. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation Product: Android Versions: Android-8.0, Android-8.1, Android-9, and Android-10 Android ID: A-142602711
<!--- Add Aqua content below --->
---
### foo heading
bar content`,
			expectedContent: `---
### foo heading
bar content`,
		},
		{
			name: "sad path, no custom content",
			inputContents: `---
title: "CVE-2020-0002"
date: 2020-01-08 12:19:15 +0000
draft: false
---
### Description
In ih264d_init_decoder of ih264d_api.c, there is a possible out of bounds write due to a use after free. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation Product: Android Versions: Android-8.0, Android-8.1, Android-9, and Android-10 Android ID: A-142602711
<!--- Add Aqua content below --->


`,
			expectedContent: ``,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := ioutil.TempFile("", "TestGetCustomContentFromMarkdown-*")
			defer func() {
				_ = os.RemoveAll(f.Name())
			}()

			_, _ = f.WriteString(tc.inputContents)
			gotCustomContent := GetCustomContentFromMarkdown(f.Name())
			assert.Equal(t, tc.expectedContent, gotCustomContent, tc.name)
		})
	}

}

func TestGenerateVulnerabilityPages(t *testing.T) {
	t.Run("happy path no file with custom content", func(t *testing.T) {
		nvdApiDir := "../goldens/json/nvd"
		postsDir, _ := ioutil.TempDir("", "TestGenerateVulnerabilityPages-*")
		defer func() {
			_ = os.RemoveAll(postsDir)
		}()
		testCweDir := "../goldens/cwe"
		b, _ := ioutil.ReadFile(filepath.Join(testCweDir, "CWE-416.json")) // One test file within the golden directory
		var weaknesses WeaknessType
		err := json.Unmarshal(b, &weaknesses)
		require.NoError(t, err)

		vendorDirs := map[string]string{
			"redhat": "../goldens/json/redhat",
			"ubuntu": "../goldens/json/ubuntu",
		}
		nvdGenerator := NewNvdGenerator(WithVulnListNvdApiDir(nvdApiDir), WithCweDir(testCweDir), WithNvdPostsDirFormat(postsDir+"/%s"), WithVendorDirs(vendorDirs))
		nvdGenerator.generateVulnerabilityPages("2020")

		gotFiles, err := getAllFiles(filepath.Join(postsDir, "2020"))
		require.NoError(t, err)
		for _, file := range gotFiles {
			b, _ := ioutil.ReadFile(file)
			assert.NotEmpty(t, b)

			if filepath.Base(file) == "CVE-2020-0002.md" {
				assert.Equal(t, `---
title: "CVE-2020-0002"
aliases: [
	"/nvd/cve-2020-0002"
]

shortName: "Generation of Error Message Containing Sensitive Information"
date: 2020-01-08 07:15:12 +0000
category: vulnerabilities
draft: false

avd_page_type: nvd_page

date_published: 2020-01-08 07:15:12 +0000
date_modified: 2022-01-01 08:01:34 +0000

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

redhat_v3_vector: "N/A"
redhat_v3_score: "0"
redhat_v3_severity: "MODERATE"

ubuntu_vector: "N/A"
ubuntu_score: "N/A"
ubuntu_severity: "LOW"

---

In ih264d_init_decoder of ih264d_api.c, there is a possible out of bounds write due to a use after free. This could lead to remote code execution with no additional execution privileges needed. User interaction is needed for exploitation Product: Android Versions: Android-8.0, Android-8.1, Android-9, and Android-10 Android ID: A-142602711
### Weakness {.with_icon .weakness}
The software generates an error message that includes sensitive information about its environment, users, or associated data.

### Affected Software {.with_icon .affected_software}
| Name | Vendor           | Start Version | End Version |
| ------------- |-------------|-----|----|
| Android | Google | 8.0 (including) | 8.0 (including)|
| Android | Google | 8.1 (including) | 8.1 (including)|
| Android | Google | 9.0-beta1 (including) | 9.0-beta1 (including)|
| Android | Google | 10.0 (including) | 10.0 (including)|
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
		nvdApiDir := "../goldens/json/nvd"
		postsDir, _ := ioutil.TempDir("", "TestGenerate-*")
		defer func() {
			_ = os.RemoveAll(postsDir)
		}()
		testCweDir := "../goldens/cwe"
		b, _ := ioutil.ReadFile(filepath.Join(testCweDir, "CWE-416.json")) // One test file within the golden directory
		var weakness WeaknessType
		err := json.Unmarshal(b, &weakness)
		require.NoError(t, err)

		b1, _ := ioutil.ReadFile("../goldens/markdown/CVE-2020-0002.md")
		_ = ioutil.WriteFile(filepath.Join(postsDir, "CVE-2020-0002.md"), b1, 0600)

		vendorDirs := map[string]string{
			"redhat": "../goldens/json/redhat",
			"ubuntu": "../goldens/json/ubuntu",
		}
		nvdGenerator := NewNvdGenerator(WithVulnListNvdApiDir(nvdApiDir), WithCweDir(testCweDir), WithNvdPostsDirFormat(postsDir+"/%s"), WithVendorDirs(vendorDirs))
		nvdGenerator.generateVulnerabilityPages("2020")

		gotFiles, err := getAllFiles(filepath.Join(postsDir, "2020"))
		require.NoError(t, err)
		for _, file := range gotFiles {
			b, _ := ioutil.ReadFile(file)
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

redhat_v3_vector: "N/A"
redhat_v3_score: "0"
redhat_v3_severity: "MODERATE"

ubuntu_vector: "N/A"
ubuntu_score: "N/A"
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

func TestGenerateReservedPages(t *testing.T) {
	t.Run("no existing info from NVD", func(t *testing.T) {
		postsDir, _ := ioutil.TempDir("", "TestGenerateReservedPages-postsDir-*")
		defer func() {
			_ = os.RemoveAll(postsDir)
		}()

		goldenDir := "../goldens/reserved-no-existing-info"
		vendorDirs := map[string]string{
			"redhat": filepath.Join(goldenDir, "redhat"),
			"ubuntu": filepath.Join(goldenDir, "ubuntu"),
		}
		nvdGenerator := NewNvdGenerator(WithVulnListNvdApiDir(filepath.Join(goldenDir, "nvd")), WithNvdPostsDirFormat(postsDir+"/%s"), WithVendorDirs(vendorDirs))
		for _, year := range []string{"2020"} {
			nvdGenerator.GenerateReservedPages(year, fakeClock{})
		}

		// check for one expected file
		got, err := ioutil.ReadFile(filepath.Join(postsDir, "2020", "CVE-2020-0569.md"))
		require.NoError(t, err)
		assert.Equal(t, `---
title: "CVE-2020-0569"
date: 2021-04-15T20:55:39Z
draft: false
category: vulnerabilities

avd_page_type: reserved_page
---

This vulnerability is marked as __RESERVED__ by NVD. This means that the CVE-ID is reserved for future use
by the [CVE Numbering Authority (CNA)](https://cve.mitre.org/cve/cna.html) or a security researcher, but the details of it are not yet publicly available yet. 

This page will reflect the classification results once they are available through NVD. 

Any vendor information available is shown as below.

||||
| ------------- |-------------|-----|


### Redhat
CVE-2020-0569 qt: files placed by attacker can influence the working directory and lead to malicious code execution


#### Mitigation
Use subscription-manager directly from the terminal and do not use the --password flag.


#### Affected Software List
| Name | Vendor           | Version |
| ------------- |-------------|-----|
| Red Hat Enterprise Linux 8 | RedHat | qt5-qtbase-0:5.12.5-6.el8|


### Ubuntu
QPluginLoader in Qt versions 5.0.0 through 5.13.2 would search for certain plugins first on the current working directory of the application, which allows an attacker that can place files in the file system and influence the working directory of Qt-based applications to load and execute malicious code. This issue was verified on macOS and Linux and probably affects all other Unix operating systems. This issue does not affect Windows.



#### Affected Software List
| Name | Vendor           | Version |
| ------------- |-------------|-----|
| Qtbase-opensource-src | Ubuntu/bionic | 5.9.5+dfsg-0ubuntu2.5|

`, string(got))
	})

	t.Run("with existing info from NVD", func(t *testing.T) {
		postsDir, _ := ioutil.TempDir("", "TestGenerateReservedPages-postsDir-*")
		defer func() {
			_ = os.RemoveAll(postsDir)
		}()

		goldenDir := "../goldens/reserved-with-existing-info"
		vendorDirs := map[string]string{
			"redhat": filepath.Join(goldenDir, "redhat"),
			"ubuntu": filepath.Join(goldenDir, "ubuntu"),
		}
		nvdGenerator := NewNvdGenerator(WithVulnListNvdApiDir(filepath.Join(goldenDir, "nvd")), WithNvdPostsDirFormat(postsDir+"/%s"), WithVendorDirs(vendorDirs))
		for _, year := range []string{"2020"} {
			nvdGenerator.GenerateReservedPages(year, fakeClock{})
		}

		// no new reserved page must be created as NVD already has info
		_, err := ioutil.ReadFile(filepath.Join(postsDir, "CVE-2020-0569.md"))
		require.Contains(t, err.Error(), "no such file or directory")
	})
}
