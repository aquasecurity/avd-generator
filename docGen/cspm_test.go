package main

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/avd-generator/docGen/menu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCloudtSploitPages(t *testing.T) {
	pagesDir := t.TempDir()

	misConfigurationMenu = menu.New("misconfig", pagesDir)

	generateCloudSploitPages("../goldens/cloudsploit/plugins", pagesDir, "../goldens/cloudsploit/en")
	got, err := ioutil.ReadFile(filepath.Join(pagesDir, "aws/acm/acm-certificate-validation.md"))
	require.NoError(t, err)

	want, _ := ioutil.ReadFile("../goldens/cloudsploit/acm-certificate-validation.avd.md")
	assert.Equal(t, string(want), string(got))
}
