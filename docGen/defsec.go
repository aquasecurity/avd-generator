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

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/avd-generator/menu"
	"github.com/aquasecurity/avd-generator/util"
	"github.com/aquasecurity/trivy-checks/pkg/rego/metadata"
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

func generateDefsecComplianceSpecPages(specDir, contentDir string, checksFS fs.FS) {
	checksMetadata, err := metadata.LoadChecksMetadata(checksFS)
	if err != nil {
		fmt.Println(err)
		return
	}
	checksByID := make(map[string]metadata.Metadata)
	for _, meta := range checksMetadata {
		checksByID[meta.ID()] = meta
	}

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

		return generateDefsecComplianceSpecPage(spec, contentDir, checksByID)

	}); err != nil {
		fmt.Println(err)
	}

}

func generateDefsecComplianceSpecPage(
	spec DefsecComplianceSpec, contentDir string, checksByID map[string]metadata.Metadata,
) error {
	for _, control := range spec.Spec.Controls {
		outputFilePath := filepath.Join(contentDir, spec.Spec.Category, fmt.Sprintf("%s-%s", spec.Spec.Title, spec.Spec.Version), fmt.Sprintf("%s.md", control.ID))

		if err := os.MkdirAll(filepath.Dir(outputFilePath), 0755); err != nil {
			return err
		}

		outputFile, err := os.Create(outputFilePath)
		if err != nil {
			return err
		}

		funcs := template.FuncMap{
			"toLower": strings.ToLower,
			"toUpper": strings.ToUpper,
			"toTitle": strings.Title,
			"getSummary": func(id string) string {
				if meta, ok := checksByID[id]; ok {
					return fmt.Sprintf(" - %s", meta.Title)
				}
				return ""
			},
			"getAVDID": func(id string) string {
				if meta, ok := checksByID[id]; ok {
					return meta.AVDID()
				}
				return id
			},
		}

		t := template.Must(template.New("defsecPost").Funcs(funcs).Parse(defsecComplianceTemplate))
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

func generateDefsecPages(remediationDir, contentDir string, checksFS fs.FS) {
	checksMetadata, err := metadata.LoadChecksMetadata(checksFS)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	for checkPath, meta := range checksMetadata {
		topLevelID := strings.ToLower(meta.Provider().ConstName())
		branchID := meta.Service()
		branchID = util.RemapCategory(branchID)

		log.Printf("Getting remediation markdown for %s: %s", meta.ID(), checkPath)
		remediationDir := filepath.Join(
			remediationDir,
			strings.ToLower(meta.Provider().ConstName()), strings.ReplaceAll(meta.Service(), "-", ""),
			meta.ID(),
		)

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
			if remediationFile, ok := crossOver[meta.AVDID()]; ok {
				if remediationContent := getRemediationBodyWhereExists(fmt.Sprintf("remediations-repo/%s", remediationFile), true); remediationContent != "" {
					log.Printf("Can use %s for %s\n", remediationFile, meta.AVDID())
					remediations["Management Console"] = remediationContent
				}
			}
		}

		if err := generateDefsecCheckPage(meta, remediations, contentDir, docsFile, branchID); err != nil {
			log.Printf("an error occurred writing the page for %s. %v", meta.AVDID(), err)
		}

		providerName := meta.Provider().DisplayName()
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

func generateDefsecCheckPage(meta metadata.Metadata, remediations map[string]string, contentDir string, docsFile string, menuParent string) error {
	providerPath := strings.ToLower(meta.Provider().ConstName())
	servicePath := strings.ToLower(menuParent)
	ruleIDPath := strings.ToLower(meta.AVDID())

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

	checkAliases := meta.Aliases()

	var legacy string
	// for Rego checks the last alias is the ID field from metadata
	if len(checkAliases) > 2 && checkAliases[1] != meta.ID() {
		legacy = checkAliases[1]
	}

	var frameworks []string
	for name := range meta.Frameworks() {
		if name == "default" {
			continue
		}
		frameworks = append(frameworks, strings.ToUpper(strings.ReplaceAll(name, "-", " ")))
	}
	sort.Strings(frameworks)

	post := map[string]any{
		"AVDID":            meta.AVDID(),
		"Deprecated":       meta.Deprecated(),
		"AVDID_Lowered":    strings.ToLower(meta.AVDID()),
		"LegacyID":         legacy,
		"LegacyID_Lowered": strings.ToLower(legacy),
		"ShortName":        util.Nicify(checkAliases[len(checkAliases)-1]),
		"Provider":         strings.ToLower(meta.Provider().ConstName()),
		"ProviderName":     meta.Provider().DisplayName(),
		"ServiceName":      util.Nicify(meta.Service()),
		"Service":          strings.ToLower(strings.ReplaceAll(meta.Service(), " ", "-")),
		"Summary":          meta.Title,
		"Body":             documentBody.String(),
		"Severity":         strings.ToLower(meta.Severity()),
		"ParentID":         strings.ReplaceAll(strings.ToLower(menuParent), " ", "-"),
		"Remediations":     remediationKeys,
		"Frameworks":       frameworks,
		"Source":           "Trivy",
	}

	if aliases := getCSPMAliasesForAVDID(meta.AVDID()); len(aliases) > 0 {
		post["AdditionalAliases"] = aliases
	}

	if remediationPath, ok := crossOver[meta.AVDID()]; ok {
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
deprecated: {{ .Deprecated }}

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
{{ range .Checks }}* [{{ .ID | getAVDID }}](https://avd.aquasec.com/misconfig/{{ .ID | getAVDID | toLower }}){{ .ID | getSummary }}{{ end }}


`
