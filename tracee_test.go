package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func Test_generateTraceePages(t *testing.T) {
	postsDir, _ := ioutil.TempDir("", "Test_generateTraceePages-*")
	defer func() {
		_ = os.RemoveAll(postsDir)
	}()
	require.NoError(t, generateTraceePages("goldens/tracee-sigs", postsDir, fakeClock{}))

	gotFiles, err := GetAllFiles(postsDir)
	require.NoError(t, err)
	assert.Equal(t, 3, len(gotFiles))

	// check for various files and contents
	got, err := ioutil.ReadFile(filepath.Join(postsDir, "TRC2.md"))
	require.NoError(t, err)
	want, _ := ioutil.ReadFile("goldens/tracee-sigs/generated-mds/TRC2.md")
	assert.Equal(t, string(want), string(got))

	got, err = ioutil.ReadFile(filepath.Join(postsDir, "TRC3.md"))
	require.NoError(t, err)
	want, _ = ioutil.ReadFile("goldens/tracee-sigs/generated-mds/TRC3.md")
	assert.Equal(t, string(want), string(got))

	got, err = ioutil.ReadFile(filepath.Join(postsDir, "TRC1.md"))
	require.NoError(t, err)
	want, _ = ioutil.ReadFile("goldens/tracee-sigs/generated-mds/TRC1.md")
	assert.Equal(t, string(want), string(got))
}
