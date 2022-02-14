package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func Test_generateTraceePages(t *testing.T) {
	postsDir, _ := ioutil.TempDir("", "Test_generateTraceePages-*")
	defer func() {
		_ = os.RemoveAll(postsDir)
	}()
	generateTraceePages("../goldens/tracee-sigs", filepath.Join(postsDir, "tracee"), fakeClock{})

	gotFiles, err := getAllFiles(postsDir)
	require.NoError(t, err)
	require.Equal(t, 3, len(gotFiles))

	dirRegex := regexp.MustCompile("(?m).+MITRE ATT&CK\n(.*):")

	// check for various files and contents
	for i := 1; i <= 3; i++ {
		want, err := ioutil.ReadFile(fmt.Sprintf("../goldens/tracee-sigs/generated-mds/TRC%d.md", i))
		require.NoError(t, err)

		dir := strings.ReplaceAll(string(dirRegex.FindSubmatch(want)[1]), " ", "-")

		got, err := ioutil.ReadFile(filepath.Join(postsDir, "tracee", strings.ToLower(dir), fmt.Sprintf("TRC%d.md", i)))
		require.NoError(t, err)

		assert.Equal(t, string(want), string(got))
	}
}

/*

(?m).+MITRE ATT&CK\n(.*):
*/
