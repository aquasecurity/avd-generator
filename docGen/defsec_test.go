package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadsAsExpected(t *testing.T) {

	tempDir := t.TempDir()

	generateDefsecPages("../goldens/defsec/md", tempDir)

	ids := []string{"avd-aws-0018"}

	for _, id := range ids {
		content, err := os.ReadFile(fmt.Sprintf("%s/aws/code-build/%s.md", tempDir, id))
		require.NoError(t, err)

		expected, err := os.ReadFile(fmt.Sprintf("../goldens/defsec/expected/%s.md", id))
		require.NoError(t, err)

		assert.Equal(t, string(expected), string(content))
	}
}
