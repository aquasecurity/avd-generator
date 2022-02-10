package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCloudSploitPages(t *testing.T) {
	pagesDir, _ := ioutil.TempDir("", "TestGenerateCloudSploitPages-*")
	defer func() {
		_ = os.RemoveAll(pagesDir)
	}()

	generateCloudSploitPages("goldens/cloudsploit/en", pagesDir)
	got, err := ioutil.ReadFile(filepath.Join(pagesDir, "aws/ACM/acm-certificate-validation.md"))
	require.NoError(t, err)

	want, _ := ioutil.ReadFile("goldens/cloudsploit/acm-certificate-validation.avd.md")
	assert.Equal(t, string(want), string(got))

	// check all providers and services have _index.md pages for redirection back to homepage
	want, err = ioutil.ReadFile(filepath.Join(pagesDir, "aws/_index.md"))
	require.NoError(t, err)
	assert.Empty(t, want)
	want, err = ioutil.ReadFile(filepath.Join(pagesDir, "aws/ACM/_index.md"))
	require.NoError(t, err)
	assert.Empty(t, want)

	// check table of contents content
	got, err = ioutil.ReadFile(filepath.Join(pagesDir, "_index.md"))
	require.NoError(t, err)
	assert.Equal(t, `---
title: Aqua_CSPM_Remediations
draft: false

display_title: "Aqua CSPM Remediations"
avd_page_type: cloudsploit_page
---

### AWS {.listpage_section_title}
#### ACM {.listpage_subsection_title}
- [ACM Certificate Validation](/cspm/aws/acm/acm-certificate-validation)
#### CloudFront {.listpage_subsection_title}
- [CloudFront HTTPS Only](/cspm/aws/cloudfront/cloudfront-https-only)
#### ELB {.listpage_subsection_title}
- [ELB Logging Enabled](/cspm/aws/elb/elb-logging-enabled)
- [Insecure Ciphers](/cspm/aws/elb/insecure-ciphers)
### GOOGLE {.listpage_section_title}
#### DNS {.listpage_subsection_title}
- [DNS Security Enabled](/cspm/google/dns/dns-security-enabled)
`, string(got))

}
