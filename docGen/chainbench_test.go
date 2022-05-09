package main

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChainBenchPages(t *testing.T) {

	pagesDir := t.TempDir()
	generateChainBenchPages("../goldens/chain-bench/originals", pagesDir)
	gotBytes, err := ioutil.ReadFile(filepath.Join(pagesDir, "softwaresupplychain", "cis-1.0", "cis-1.0-buildpipelines", "2.3.md"))
	require.NoError(t, err)

	wantBytes, err := ioutil.ReadFile("../goldens/chain-bench/expected/2.3.md")
	require.NoError(t, err)

	got := string(gotBytes)
	want := string(wantBytes)

	assert.Equal(t, want, got)
}
