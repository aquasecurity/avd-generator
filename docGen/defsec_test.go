package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadsAsExpected(t *testing.T) {

	rules := []rules.RegisteredRule{
		rules.Register(rules.Rule{
			AVDID:       "AVD-AWS-0018",
			Provider:    provider.AWSProvider,
			Service:     "codebuild",
			ShortCode:   "enable-encryption",
			Summary:     "CodeBuild Project artifacts encryption should not be disabled",
			Impact:      "CodeBuild project artifacts are unencrypted",
			Resolution:  "Enable encryption for CodeBuild project artifacts",
			Explanation: `All artifacts produced by your CodeBuild project pipeline should always be encrypted`,
			Links: []string{
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html",
				"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html",
			},
		}, nil)}

	tempDir := t.TempDir()

	generateDefsecPages("../goldens/defsec/md", tempDir, rules)

	ids := []string{"avd-aws-0018"}

	for _, id := range ids {
		content, err := os.ReadFile(fmt.Sprintf("%s/aws/codebuild/%s.md", tempDir, id))
		require.NoError(t, err)

		expected, err := os.ReadFile(fmt.Sprintf("../goldens/defsec/expected/%s.md", id))
		require.NoError(t, err)

		assert.Equal(t, string(expected), string(content))
	}
}
