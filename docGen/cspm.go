package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/aquasecurity/avd-generator/docGen/menu"
	"github.com/aquasecurity/avd-generator/docGen/util"
)

func generateCloudSploitPages(inputPagesDir, outputPagesDir, remediationsDir string) {
	log.Printf("generating cloudsploit pages in: %s...", outputPagesDir)
	var fileList []string
	if err := filepath.Walk(inputPagesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		fileList = append(fileList, path)
		return nil
	}); err != nil {
		fail(err)
	}

	titleRegex := regexp.MustCompile(`(?m)^\s+title:\s?'(.*)'`)
	categoryRegex := regexp.MustCompile(`(?m)^\s+category:\s?'(.*)'`)
	descriptionRegex := regexp.MustCompile(`(?m)^\s+description:\s?'(.*)'`)
	moreInfoRegex := regexp.MustCompile(`(?m)^\s+more_info:\s?'(.*)'`)
	linkRegex := regexp.MustCompile(`(?m)^\s+link:\s?'(.*)'`)
	recommendedActionsRegex := regexp.MustCompile(`(?m)^\s+recommended_action:\s?'(.*)'`)

	for _, file := range fileList {

		if strings.HasSuffix(file, ".spec.js") {
			// not interested in spec files
			continue
		}

		fullPath := strings.Split(file, "plugins/")[1]
		provider := strings.Split(fullPath, "/")[0]

		b, err := ioutil.ReadFile(file)
		if err != nil {
			fmt.Printf("Error reading %s\n", file)
			continue
		}

		content := string(b)

		var title, originalCategory, category, description, moreInfo, link, recommendedActions, remediationString string

		if titleRegex.MatchString(content) {
			title = titleRegex.FindStringSubmatch(content)[1]
			if title == "" {
				fmt.Printf("Error, title not found for file :%s\n", file)
				continue
			}
		}
		if categoryRegex.MatchString(content) {
			originalCategory = categoryRegex.FindStringSubmatch(content)[1]
			category = util.RemapCategory(originalCategory)
		}
		if descriptionRegex.MatchString(content) {
			description = descriptionRegex.FindStringSubmatch(content)[1]
		}
		if moreInfoRegex.MatchString(content) {
			moreInfo = moreInfoRegex.FindStringSubmatch(content)[1]
		}
		if linkRegex.MatchString(content) {
			link = linkRegex.FindStringSubmatch(content)[1]
		}

		remediationString = strings.ToLower(strings.ReplaceAll(title, " ", "-"))
		remediationBody := getRemediationBodyWhereExists(remediationsDir, provider, originalCategory, remediationString)
		if remediationBody != "" {
			recommendedActions = remediationBody
		} else if recommendedActionsRegex.MatchString(content) {
			recommendedActions = fmt.Sprintf(`### Recommended Actions
			
%s
`, recommendedActionsRegex.FindStringSubmatch(content)[1])
		}

		categoryID := strings.ReplaceAll(strings.ToLower(category), " ", "-")
		providerID := strings.ReplaceAll(strings.ToLower(provider), " ", "-")

		outputFilePath := filepath.Join(outputPagesDir, providerID, categoryID, strings.ToLower(fmt.Sprintf("%s.md", remediationString)))
		if err := os.MkdirAll(filepath.Dir(outputFilePath), 0755); err != nil {
			fmt.Printf("Could not create directory for %s\n", outputFilePath)
			continue
		}

		outputFile, err := os.Create(outputFilePath)
		if err != nil {
			fmt.Printf("failed to create file %s\n", outputFilePath)
			continue
		}

		var post = map[string]interface{}{
			"Title":              title,
			"Description":        description,
			"ID":                 remediationString,
			"ShortName":          remediationString,
			"Remediations":       []string{},
			"ProviderID":         providerID,
			"ProviderName":       provider,
			"CategoryID":         categoryID,
			"ServiceName":        category,
			"MoreInfo":           moreInfo,
			"Links":              []string{link},
			"RecommendedActions": recommendedActions,
			"AliasID":            fmt.Sprintf("%s/%s/%s", providerID, categoryID, strings.ToLower(remediationString)),
		}

		t := template.Must(template.New("defsecPost").Parse(cspmTemplate))
		if err := t.Execute(outputFile, post); err != nil {
			fail(err)
		}

		misConfigurationMenu.AddNode(providerID, provider, outputPagesDir, "", []string{},
			[]menu.MenuCategory{
				{
					Name: "Misconfiguration",
					Url:  "/misconfig",
				},
			}, "iac")
		misConfigurationMenu.AddNode(categoryID, category, filepath.Join(outputPagesDir, providerID),
			providerID, []string{},
			[]menu.MenuCategory{
				{Name: "Misconfiguration", Url: "/misconfig"},
				{Name: provider, Url: fmt.Sprintf("/misconfig/%s", providerID)},
			}, "iac")

	}

}

func getRemediationBodyWhereExists(remediationsDir, provider, category, remediationID string) string {
	remediationFile := strings.ReplaceAll(filepath.Join(
		remediationsDir, strings.ToLower(provider), strings.ToLower(category),
		fmt.Sprintf("%s.md", remediationID)), " ", "")

	remediationFile, err := filepath.Abs(remediationFile)
	if err != nil {
		fmt.Printf("Could not get the working directory %s\n", err.Error())
		return ""
	}

	if _, err := os.Stat(remediationFile); err != nil {
		fmt.Printf("Could not get remediation file %s %s\n", remediationFile, err.Error())
		return ""
	}

	content, err := os.ReadFile(remediationFile)
	if err != nil {
		fmt.Printf("Error reading remediation file %s\n", remediationFile)
	}

	components := strings.Split(string(content), "## Detailed Remediation Steps")
	if len(components) < 2 {
		return ""
	}

	strippedContent := strings.TrimSpace(components[1])
	if strippedContent == "" {
		return ""
	}

	imageConverterRegex := regexp.MustCompile(`</br>\s?<img src=\"(.*)"\s?/>`)
	strippedContent = imageConverterRegex.ReplaceAllString(strippedContent, "![Step]($1)\n")
	body := `### Recommended Actions

Follow the appropriate remediation steps below to resolve the issue.
`
	body += "{{< tabs groupId=\"remediation\" >}}\n"
	body += "{{% tab name=\"Management Console\" %}}\n"
	body += strippedContent
	body += "{{% /tab %}}\n"
	body += "{{< /tabs >}}\n"

	return body
}

const cspmTemplate = `---
title: {{ .ServiceName }} - {{.Title}}
aliases: [
	"/cspm/{{ .AliasID}}"
]
heading: Misconfiguration
icon: iac
sidebar_category: misconfig
draft: false
shortName: {{.ShortName}}
severity: "unknown"

avd_page_type: defsec_page

remediations:
  - management console

menu:
  misconfig:
    identifier: {{.ProviderID}}/{{.CategoryID}}/{{.ID}}
    name: {{.Title}}
    parent: {{.ProviderID}}/{{.CategoryID}}
---

Misconfiguration > [{{.ProviderName}}](../../) > [{{.ServiceName}}](../) > {{.Title}}

### {{ .Title }}

{{ .Description }}

{{ .MoreInfo }}

{{ .RecommendedActions }}

{{ if .Links }}
### Links
{{ range .Links}}  - {{ .}}
{{ end}}
{{ end }}
`
