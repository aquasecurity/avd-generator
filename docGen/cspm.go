package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/aquasecurity/avd-generator/menu"
	"github.com/aquasecurity/avd-generator/util"
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
	severityRegex := regexp.MustCompile(`(?m)^\s+severity:\s?'(.*)'`)
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

		id := strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
		if slices.Contains(cloudsploitIgnores, id) {
			fmt.Printf("Skipping '%s' because it is in the cloudsploit ignore list: \n", id)

			continue
		}

		content := string(b)

		var title, originalCategory, category, description, severity, moreInfo, link, recommendedActions, remediationString string

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
		if severityRegex.MatchString(content) {
			severity = severityRegex.FindStringSubmatch(content)[1]
			if len(severity) > 1 {
				severity = strings.ToLower(severity)
			}
		} else {
			severity = "unknown"
		}

		remediationString = strings.ToLower(strings.ReplaceAll(title, " ", "-"))

		remediationPathKey := strings.ReplaceAll(filepath.Join(
			"en", strings.ToLower(provider), strings.ToLower(category),
			fmt.Sprintf("%s.md", remediationString)), " ", "")

		if hasDefsecOverride(remediationPathKey) {
			continue
		}
		remediationFile := strings.ReplaceAll(filepath.Join(
			remediationsDir, strings.ToLower(provider), strings.ToLower(category),
			fmt.Sprintf("%s.md", remediationString)), " ", "")
		remediationBody := getRemediationBodyWhereExists(remediationFile, false)
		if remediationBody != "" {
			recommendedActions = remediationBody
		} else if recommendedActionsRegex.MatchString(content) {
			recommendedActions = fmt.Sprintf(`### Recommended Actions
			
%s
`, recommendedActionsRegex.FindStringSubmatch(content)[1])
		}

		categoryID := strings.ReplaceAll(strings.ToLower(filepath.Base(filepath.Dir(file))), " ", "")
		aliasCategoryID := strings.ReplaceAll(strings.ToLower(category), " ", "-")
		providerID := strings.ReplaceAll(strings.ToLower(provider), " ", "-")

		outputFilePath := filepath.Join(outputPagesDir, providerID, aliasCategoryID, strings.ToLower(fmt.Sprintf("%s.md", remediationString)))
		if err := os.MkdirAll(filepath.Dir(outputFilePath), 0755); err != nil {
			fmt.Printf("Could not create directory for %s\n", outputFilePath)
			continue
		}

		outputFile, err := os.Create(outputFilePath)
		if err != nil {
			fmt.Printf("failed to create file %s\n", outputFilePath)
			continue
		}

		aliases := []string{
			// fmt.Sprintf("misconfig/%s/%s/%s", providerID, categoryID, strings.ToLower(remediationString)),
			fmt.Sprintf("cspm/%s/%s/%s", providerID, categoryID, strings.ToLower(remediationString)),
		}
		if categoryID != aliasCategoryID {
			aliases = append(aliases, fmt.Sprintf("cspm/%s/%s/%s", providerID, aliasCategoryID, strings.ToLower(remediationString)))
		}

		var post = map[string]interface{}{
			"Title":              title,
			"Description":        description,
			"ID":                 remediationString,
			"ShortName":          remediationString,
			"Severity":           severity,
			"Remediations":       []string{},
			"ProviderID":         providerID,
			"ProviderName":       util.Nicify(strings.Title(provider)),
			"CategoryID":         aliasCategoryID,
			"ServiceName":        category,
			"MoreInfo":           moreInfo,
			"Links":              []string{link},
			"RecommendedActions": recommendedActions,
			"AliasIDs":           aliases,
			"Keyword":            fmt.Sprintf("%s/%s/%s", providerID, categoryID, strings.ToLower(remediationString)),
		}

		t := template.Must(template.New("defsecPost").Parse(cspmTemplate))
		if err := t.Execute(outputFile, post); err != nil {
			fail(err)
		}

		misConfigurationMenu.AddNode(providerID, provider, outputPagesDir, "", []string{},
			[]menu.BreadCrumb{}, providerID, true)
		misConfigurationMenu.AddNode(aliasCategoryID, category, filepath.Join(outputPagesDir, providerID),
			providerID, []string{},
			[]menu.BreadCrumb{{Name: util.Nicify(strings.Title(provider)), Url: fmt.Sprintf("/misconfig/%s", providerID)}}, providerID, false)

	}

}

func hasDefsecOverride(remediationFile string) bool {
	if avdID := getAVDIDByCSPMPath(remediationFile); avdID != "" {
		// log.Printf("Override detected: '%s' has been overridden by '%s'\n", remediationFile, avdID)
		return true
	}
	return false

}

func getRemediationBodyWhereExists(remediationFile string, fromDefsec bool) string {

	remediationFile, err := filepath.Abs(remediationFile)
	if err != nil {
		fmt.Printf("Could not get the working directory %s\n", err.Error())
		return ""
	}

	if _, err := os.Stat(remediationFile); err != nil {
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
	body := ""
	if !fromDefsec {
		body += `### Recommended Actions `
		body += "\n Follow the appropriate remediation steps below to resolve the issue."
		body += "{{< tabs groupId=\"remediation\" >}}\n"
		body += "{{% tab name=\"Management Console\" %}}\n"
	}
	body += "\n" + strippedContent
	if !fromDefsec {
		body += "{{% /tab %}}\n"
		body += "{{< /tabs >}}\n"
	}

	return body
}

const cspmTemplate = `---
title: {{.Title}}
id: {{.ShortName}}
aliases: [
	{{range $i, $e := .AliasIDs}}{{if $i}},
	{{end}}"/{{ $e }}"{{end}}
]
source: CloudSploit
icon: {{ .ProviderID }}
draft: false
shortName: {{.ShortName}}
severity: {{.Severity}}
category: misconfig
keywords: "{{ .Keyword }}"

avd_page_type: avd_page

breadcrumbs: 
  - name: {{ .ProviderName }}
    path: /misconfig/{{ .ProviderID }}
  - name: {{ .ServiceName }}
    path: /misconfig/{{ .ProviderID }}/{{ .CategoryID }}

remediations:
  - management console

---

### {{.Title}}

{{ .Description }}

{{ .MoreInfo }}

{{ .RecommendedActions }}

{{ if .Links }}
### Links
{{ range .Links}}  - {{ .}}
{{ end}}
{{ end }}
`
