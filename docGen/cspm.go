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
	"github.com/leekchan/gtf"
)

const cloudSploitTableOfContents = `---
title: Aqua_CSPM_Remediations
draft: false

display_title: "Aqua CSPM Remediations"
avd_page_type: cloudsploit_page
---

{{range $provider, $serviceFile := .}}### {{ $provider | upper }} {.listpage_section_title}
{{ range $service, $files := .}}#### {{ $service }} {.listpage_subsection_title}
{{ range $file := .}}- [{{ $file }}](/cspm/{{ $provider }}/{{ $service | lower | findreplace " " "-" }}/{{ $file | lower | findreplace " " "-" }})
{{ end }}{{ end }}{{ end }}`

// {"aws":{"acm":{"foo","bar"},"elb":{"foo2","bar2"}},"google":{"dns"}}
type CloudSploitIndexMap map[string]map[string][]string

func generateCloudSploitPages(inputPagesDir string, outputPagesDir string) {
	log.Printf("generating cloudsploit pages in: %s...", outputPagesDir)
	var fileList []string
	_ = filepath.Walk(inputPagesDir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		fileList = append(fileList, path)
		return nil
	})

	csIndexMap := make(CloudSploitIndexMap)

	titleRegex := regexp.MustCompile(`(?m)^\s+title:\s?'(.*)'`)
	categoryRegex := regexp.MustCompile(`(?m)^\s+category:\s?'(.*)'`)
	descriptionRegex := regexp.MustCompile(`(?m)^\s+description:\s?'(.*)'`)
	moreInfoRegex := regexp.MustCompile(`(?m)^\s+more_info:\s?'(.*)'`)
	linkRegex := regexp.MustCompile(`(?m)^\s+link:\s?'(.*)'`)
	recommendedActionsRegex := regexp.MustCompile(`(?m)^\s+recommended_action:\s?'(.*)'`)

	for _, file := range fileList {

		if strings.HasSuffix(file, ".spec.js") {
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
		if recommendedActionsRegex.MatchString(content) {
			recommendedActions = fmt.Sprintf(`### Recommended Actions
			
%s`, recommendedActionsRegex.FindStringSubmatch(content)[1])
		}

		if title == "" {
			fmt.Printf("Error, title not found for file :%s\n", file)
			continue
		}

		remediationString = strings.ToLower(strings.ReplaceAll(title, " ", "-"))
		remediationBody := getRemediationBody(provider, originalCategory, remediationString)
		if remediationBody != "" {
			recommendedActions = remediationBody
		}

		categoryID := strings.ReplaceAll(strings.ToLower(category), " ", "-")
		providerID := strings.ReplaceAll(strings.ToLower(provider), " ", "-")

		outputFilePath := strings.ToLower(filepath.Join(outputPagesDir, providerID, categoryID, fmt.Sprintf("%s.md", remediationString)))

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
		}

		t := template.Must(template.New("defsecPost").Parse(cspmTemplate))
		t.Execute(outputFile, post)

		misConfigurationMenu.AddNode(providerID, provider, outputPagesDir, "", []string{},
			[]menu.MenuCategory{
				{"Misconfiguration", "/misconfig"},
			}, "iac")
		misConfigurationMenu.AddNode(categoryID, category, filepath.Join(outputPagesDir, providerID),
			providerID, []string{},
			[]menu.MenuCategory{
				{"Misconfiguration", "/misconfig"},
				{provider, "/misconfig/" + providerID},
			}, "iac")

	}

	// generate a table of contents markdown
	f, err := os.Create(filepath.Join(outputPagesDir, "_index.md"))
	if err != nil {
		log.Fatal("unable to create a table of contents _index.md file: ", err)
	}
	t := template.Must(template.New("cloudSploitTableOfContents").Funcs(gtf.GtfTextFuncMap).Parse(cloudSploitTableOfContents))
	err = t.Execute(f, csIndexMap)
	if err != nil {
		log.Fatal(err)
	}
}

func getRemediationBody(provider, category, remediationID string) string {
	remediationFile := strings.ReplaceAll(filepath.Join(
		"remediations-repo", "en", strings.ToLower(provider), strings.ToLower(category),
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

	regexp.Compile(`<br `)
	cleanContent := strings.TrimSpace(components[1])
	if cleanContent == "" {
		return ""
	}

	contentCleaner := regexp.MustCompile(`</br>\s?<img src=\"(.*)"\s?/>`)
	cleanContent = contentCleaner.ReplaceAllString(cleanContent, "![Step]($1)\n")
	body := `### Recommended Actions

Follow the appropriate remediation steps below to resolve the issue.
`
	body += "{{< tabs groupId=\"remediation\" >}}\n"
	body += "{{% tab name=\"Management Console\" %}}\n"
	body += cleanContent
	body += "{{% /tab %}}\n"
	body += "{{< /tabs >}}\n"

	return body
}

const cspmTemplate = `---
title: "{{.Title}}"
parent: {{ .ParentID}}
heading: Cloud Security Posture Management
icon: iac
category: misconfig
sidebar_category: misconfig
draft: false
shortName: {{.ShortName}}
severity: "unknown"

avd_page_type: defsec_page

remediations:
  - management_console

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
