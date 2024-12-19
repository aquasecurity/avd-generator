package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func Test_generateTraceePages(t *testing.T) {
	postsDir := t.TempDir()

	err := generateTraceePages("../goldens/tracee-sigs", filepath.Join(postsDir, "tracee"), fakeClock{})
	require.NoError(t, err)

	gotFiles, err := getAllFiles(postsDir)
	require.NoError(t, err)
	require.Equal(t, 1, len(gotFiles))

	dirRegex := regexp.MustCompile("(?m).+MITRE ATT&CK\n(.*):")

	want, err := os.ReadFile("../goldens/tracee-sigs/generated-mds/TRC1.md")
	require.NoError(t, err)

	dir := strings.ReplaceAll(string(dirRegex.FindSubmatch(want)[1]), " ", "-")

	got, err := os.ReadFile(filepath.Join(postsDir, "tracee", strings.ToLower(dir), "TRC1.md"))
	require.NoError(t, err)
	assert.Equal(t, string(want), string(got))
}
