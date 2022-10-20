package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/aquasecurity/avd-generator/menu"
	"github.com/aquasecurity/avd-generator/util"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/defsec/pkg/framework"
	_ "github.com/aquasecurity/defsec/pkg/rego"
	"github.com/aquasecurity/defsec/pkg/rules"
	"github.com/aquasecurity/defsec/pkg/scan"
)

type DefsecComplianceSpec struct {
	Spec struct {
		ID               string   `yaml:"id"`
		Title            string   `yaml:"title"`
		Description      string   `yaml:"description"`
		RelatedResources []string `yaml:"relatedResources"`
		Version          string   `yaml:"version"`
		Category         string   `yaml:"category"`
		CategoryTitle    string
		Controls         []struct {
			Name        string `yaml:"name"`
			Description string `yaml:"description"`
			ID          string `yaml:"id"`
			Checks      []struct {
				ID string `yaml:"id"`
			} `yaml:"checks"`
			Severity      string `yaml:"severity"`
			DefaultStatus string `yaml:"defaultStatus,omitempty"`
		} `yaml:"controls"`
	} `yaml:"spec"`
}

var funcMap = template.FuncMap{
	"toLower":    strings.ToLower,
	"toUpper":    strings.ToUpper,
	"toTitle":    strings.Title,
	"getSummary": getSummary,
}

var registeredRulesSummaries = make(map[string]string)

func init() {
	for _, rule := range rules.GetRegistered(framework.ALL) {
		registeredRulesSummaries[rule.Rule().AVDID] = rule.Rule().Summary
	}
}

func generateDefsecComplianceSpecPages(specDir, contentDir string) {

	if err := filepath.Walk(specDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !strings.HasSuffix(info.Name(), ".yaml") && !strings.HasSuffix(info.Name(), ".yml") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var spec DefsecComplianceSpec

		if err := yaml.Unmarshal(content, &spec); err != nil {
			return err
		}

		if spec.Spec.Category == "" {
			spec.Spec.Category = "kubernetes"
		}
		outputDir := filepath.Join(contentDir, spec.Spec.Category)
		title := fmt.Sprintf("%s-%s", strings.ToUpper(spec.Spec.Title), spec.Spec.Version)
		complianceMenu.AddNode(title, fmt.Sprintf("%s-%s", spec.Spec.Title, spec.Spec.Version), filepath.Join(outputDir),
			spec.Spec.Category, []string{},
			[]menu.BreadCrumb{{Name: "Compliance", Url: "/compliance"},
				{Name: strings.Title(spec.Spec.Category), Url: fmt.Sprintf("/compliance/%s", spec.Spec.Category)}}, spec.Spec.Category, true)

		return generateDefsecComplianceSpecPage(spec, contentDir)

	}); err != nil {
		fmt.Println(err)
	}

}

func getSummary(id string) string {
	if summary, ok := registeredRulesSummaries[id]; ok {
		return fmt.Sprintf(" - %s", summary)
	}

	return ""

}

func generateDefsecComplianceSpecPage(spec DefsecComplianceSpec, contentDir string) error {

	for _, control := range spec.Spec.Controls {

		outputFilePath := filepath.Join(contentDir, spec.Spec.Category, fmt.Sprintf("%s-%s", spec.Spec.Title, spec.Spec.Version), fmt.Sprintf("%s.md", control.ID))

		if err := os.MkdirAll(filepath.Dir(outputFilePath), 0755); err != nil {
			return err
		}

		outputFile, err := os.Create(outputFilePath)
		if err != nil {
			return err
		}

		t := template.Must(template.New("defsecPost").Funcs(funcMap).Parse(defsecComplianceTemplate))
		if err := t.Execute(outputFile, map[string]interface{}{
			"ID":          spec.Spec.ID,
			"Version":     spec.Spec.Version,
			"Severity":    control.Severity,
			"Title":       spec.Spec.Title,
			"Description": control.Description,
			"Category":    spec.Spec.Category,
			"Name":        control.Name,
			"ControlID":   control.ID,
			"Checks":      control.Checks,
		}); err != nil {
			return err
		}

	}
	return nil
}

func generateDefsecPages(remediationDir, contentDir string) {
	for _, r := range rules.GetRegistered(framework.ALL) {

		avdId := r.Rule().AVDID
		topLevelID := strings.ToLower(r.Rule().Provider.ConstName())
		branchID := r.Rule().Service
		branchID = util.RemapCategory(branchID)

		log.Printf("Getting remediation markdown for %s", avdId)
		remediationDir := filepath.Join(remediationDir, strings.ToLower(r.Rule().Provider.ConstName()), strings.ReplaceAll(r.Rule().Service, "-", ""), avdId)

		remediations := make(map[string]string)
		docsFile := filepath.Join(remediationDir, "docs.md")

		if err := filepath.Walk(remediationDir, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() || filepath.Ext(path) != ".md" || path == docsFile {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			remediationName := strings.ReplaceAll(strings.TrimSuffix(info.Name(), filepath.Ext(info.Name())), "_", " ")
			remediations[remediationName] = string(content)

			return nil
		}); err != nil {
			fmt.Println(err.Error())
			continue
		}

		if _, ok := remediations["Management Console"]; !ok {
			if remediationFile, ok := crossOver[avdId]; ok {
				if remediationContent := getRemediationBodyWhereExists(fmt.Sprintf("remediations-repo/%s", remediationFile)); remediationContent != "" {
					log.Printf("Can use %s for %s\n", remediationFile, avdId)
					remediations["Management Console"] = remediationContent
				}
			}
		}

		if err := generateDefsecCheckPage(r.Rule(), remediations, contentDir, docsFile, branchID); err != nil {
			log.Printf("an error occurred writing the page for %s. %v", r.Rule().AVDID, err)
		}

		providerName := r.Rule().Provider.DisplayName()
		misConfigurationMenu.AddNode(topLevelID, providerName, contentDir, "", []string{},
			[]menu.BreadCrumb{}, topLevelID, true)
		misConfigurationMenu.AddNode(branchID, branchID, filepath.Join(contentDir, topLevelID),
			topLevelID, []string{},
			[]menu.BreadCrumb{
				{
					Name: util.Nicify(strings.Title(providerName)), Url: fmt.Sprintf("/misconfig/%s", topLevelID),
				},
			}, topLevelID, false)
	}
}

func generateDefsecCheckPage(rule scan.Rule, remediations map[string]string, contentDir string, docsFile string, menuParent string) error {

	providerPath := strings.ToLower(rule.Provider.ConstName())
	servicePath := strings.ToLower(menuParent)
	ruleIDPath := strings.ToLower(rule.AVDID)

	outputFilePath := strings.ReplaceAll(filepath.Join(contentDir, providerPath, servicePath, strings.ToLower(fmt.Sprintf("%s.md", ruleIDPath))), " ", "-")
	if err := os.MkdirAll(filepath.Dir(outputFilePath), 0777); err != nil {
		return err
	}
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}

	docsContent, err := os.ReadFile(docsFile)
	if err != nil {
		return err
	}

	var funcMap = template.FuncMap{
		"severity":           func(severity string) string { return severity },
		"remediationActions": func() string { return createRemediation(remediations) },
	}

	var documentBody bytes.Buffer
	t := template.Must(template.New("bodyContent").Funcs(funcMap).Parse(string(docsContent)))
	if err := t.Execute(&documentBody, nil); err != nil {
		return err
	}

	remediationKeys := make([]string, 0, len(remediations))
	for k := range remediations {
		remediationKeys = append(remediationKeys, strings.ReplaceAll(strings.ToLower(k), " ", "_"))
	}

	sort.Strings(remediationKeys)

	var legacy string
	if rule.Aliases != nil && len(rule.Aliases) > 0 {
		legacy = rule.Aliases[0]
	}

	var frameworks []string

	if rule.Frameworks != nil && len(rule.Frameworks) > 0 {
		for framework, _ := range rule.Frameworks {
			if framework == "default" {
				continue
			}
			frameworks = append(frameworks, strings.ToUpper(strings.ReplaceAll(string(framework), "-", " ")))
		}
	}

	post := map[string]interface{}{
		"AVDID":            rule.AVDID,
		"AVDID_Lowered":    strings.ToLower(rule.AVDID),
		"LegacyID":         legacy,
		"LegacyID_Lowered": strings.ToLower(legacy),
		"ShortName":        rule.ShortCodeDisplayName(),
		"Provider":         strings.ToLower(rule.Provider.ConstName()),
		"ProviderName":     rule.Provider.DisplayName(),
		"ServiceName":      rule.ServiceDisplayName(),
		"Service":          strings.ToLower(strings.ReplaceAll(rule.Service, " ", "-")),
		"Summary":          rule.Summary,
		"Body":             documentBody.String(),
		"Severity":         strings.ToLower(string(rule.Severity)),
		"ParentID":         strings.ReplaceAll(strings.ToLower(menuParent), " ", "-"),
		"Remediations":     remediationKeys,
		"Frameworks":       frameworks,
		"Source":           "Trivy",
	}

	if aliases := getCSPMAliasesForAVDID(rule.AVDID); len(aliases) > 0 {
		post["AdditionalAliases"] = aliases
	}

	if remediationPath, ok := crossOver[rule.AVDID]; ok {
		id := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(remediationPath, "en/", ""), ".md", ""))
		post["AliasID"] = id
		post["Source"] = "Trivy/CSPM"
		parts := strings.Split(id, "/")
		post["CSPMID"] = parts[len(parts)-1]

	}

	t = template.Must(template.New("defsecPost").Parse(defsecTemplate))
	return t.Execute(outputFile, post)
}

func createRemediation(remediations map[string]string) string {
	if len(remediations) == 0 {
		return ""
	}
	body := `### Recommended Actions

Follow the appropriate remediation steps below to resolve the issue.

{{< tabs groupId="remediation" >}}`
	keys := make([]string, 0, len(remediations))
	for k := range remediations {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		body += fmt.Sprintf(`{{%% tab name="%s" %%}}`, k)
		body += remediations[k]
		body += "{{% /tab %}}"
	}
	body += "{{< /tabs >}}"
	return body
}

const defsecTemplate string = `---
title: {{.ShortName}}
id: {{ .AVDID }}

aliases: [
{{ if .AliasID}}	"/cspm/{{ .AliasID}}",
{{ end }}{{ if .LegacyID }}  "/misconfig/{{ .Provider }}/{{ .LegacyID_Lowered }}",
{{ end }}{{ if .LegacyID }}  "/misconfig/{{ .LegacyID_Lowered }}",
{{ end }}  "/misconfig/{{ .AVDID_Lowered }}",
  "/misconfig/{{ .Provider }}/{{ .Service }}/{{ .AVDID_Lowered }}",
{{ if .AdditionalAliases }}{{ range $alias := .AdditionalAliases }}  "{{ $alias }}",
{{end}}{{end}}
]
{{ if .Frameworks }}
frameworks: [
{{ range .Frameworks }}  "{{ . }}",
{{ end }}]
{{ end }}

source: {{ .Source }}
{{ if .CSPMID}}
cspmID: {{ .CSPMID}}
{{ end }}
icon: {{ .Provider }}
draft: false
shortName: {{.ShortName}}
severity: "{{.Severity}}"
category: misconfig
keywords: "{{ .AVDID }}"

breadcrumbs: 
  - name: {{ .ProviderName }}
    path: /misconfig/{{ .Provider }}
  - name: {{ .ServiceName }}
    path: /misconfig/{{ .Provider }}/{{ .Service }}

avd_page_type: avd_page

remediations:
{{ range .Remediations }}  - {{ .}}
{{ end }}
---

### {{ .Summary }}

{{.Body}}

`

const defsecComplianceTemplate string = `---
title: {{ .Name }}
id: {{ .ControlID }}
source: Trivy
icon: {{ .Category }}
draft: false
shortName: {{.Title}}
severity: {{ .Severity | toLower}}
version: {{ .Version}}
category: compliance

breadcrumbs: 
  - name: Compliance
    path: /compliance
  - name: {{ .Category | toTitle }}
    path: /compliance/{{ .Category }}
  - name: {{ .Title | toUpper }}-{{ .Version }}
    path: /compliance/{{ .Category }}/{{ .Title }}-{{ .Version}}


avd_page_type: avd_page

---

### {{ .ControlID }} - {{ .Name }}
{{ .Description }}

**Control Checks**
{{ range .Checks }}* [{{ .ID }}](https://avd.aquasec.com/misconfig/{{ .ID | toLower }}){{ .ID | getSummary }}{{ end }}


`
