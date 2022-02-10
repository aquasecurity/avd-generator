package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKubeHunterPages(t *testing.T) {
	pagesDir, _ := ioutil.TempDir("", "TestKubeHunterPages-*")
	defer func() {
		_ = os.RemoveAll(pagesDir)
	}()

	generateKubeHunterPages("goldens/kube-hunter", pagesDir)
	got, err := ioutil.ReadFile(filepath.Join(pagesDir, "KHV002-orig.md"))
	require.NoError(t, err)

	want, _ := ioutil.ReadFile("goldens/kube-hunter/KHV002-avd.md")
	assert.Equal(t, string(want), string(got))
}
