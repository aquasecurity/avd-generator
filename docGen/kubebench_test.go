package main

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKubeBenchPages(t *testing.T) {

	pagesDir := t.TempDir()
	generateKubeBenchPages("../goldens/kube-bench/originals", pagesDir)
	gotBytes, err := ioutil.ReadFile(filepath.Join(pagesDir, "kubernetes", "ack-1.0", "ack-1.0-controlplane", "3.1.md"))
	require.NoError(t, err)

	wantBytes, err := ioutil.ReadFile("../goldens/kube-bench/expected/controlplane.md")
	require.NoError(t, err)

	got := string(gotBytes)
	want := string(wantBytes)

	assert.Equal(t, want, got)
}
