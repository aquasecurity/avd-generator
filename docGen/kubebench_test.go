package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKubeBenchPages(t *testing.T) {
	pagesDir, _ := ioutil.TempDir("", "TestKubeBenchPages-*")
	defer func() {
		_ = os.RemoveAll(pagesDir)
	}()

	generateKubeBenchPages("../goldens/kube-bench/originals", pagesDir)
	gotBytes, err := ioutil.ReadFile(filepath.Join(pagesDir, "benchmarks", "ack-1.0", "controlplane.md"))
	require.NoError(t, err)

	wantBytes, err := ioutil.ReadFile("../goldens/kube-bench/expected/controlplane.md")
	require.NoError(t, err)

	got := string(gotBytes)
	want := string(wantBytes)

	assert.Equal(t, want, got)
}
