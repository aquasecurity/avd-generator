package main

import (
	"fmt"
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
	generateTraceePages("goldens/tracee-sigs", filepath.Join(postsDir, "tracee"), fakeClock{})

	gotFiles, err := getAllFiles(postsDir)
	require.NoError(t, err)
	require.Equal(t, 3, len(gotFiles))

	// check for various files and contents
	for i := 1; i <= 3; i++ {
		got, err := ioutil.ReadFile(filepath.Join(postsDir, "tracee", fmt.Sprintf("TRC%d.md", i)))
		require.NoError(t, err)
		want, _ := ioutil.ReadFile(fmt.Sprintf("goldens/tracee-sigs/generated-mds/TRC%d.md", i))
		assert.Equal(t, string(want), string(got))
	}
}
