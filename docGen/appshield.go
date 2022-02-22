package main

import (
	"encoding/json"
	"fmt"
	"io"
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

type RegoMetadata struct {
	ID                 string   `json:"id"`
	AVDID              string   `json:"avd_id"`
	Title              string   `json:"title"`
	ShortCode          string   `json:"short_code"`
	ShortName          string   `json:"-"`
	Version            string   `json:"version"`
	Type               string   `json:"type"`
	Description        string   `json:"description"`
	Url                string   `json:"url"`
	Severity           string   `json:"severity"`
	RecommendedActions string   `json:"recommended_actions"`
	Links              []string `json:"-"`

	Policy string `json:"-"`
}
type RegoPost struct {
	Title        string
	By           string
	Date         string
	GroupName    string
	Remediations []string
	PolicyUrl    string
	PolicyName   string
	ParentID     string
	Rego         RegoMetadata
}

func parseAppShieldRegoPolicyFile(fileName string, clock Clock) (rp *RegoPost, err error) {
	rego, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	rp = &RegoPost{
		By:   "Aqua Security",
		Date: clock.Now("2006-01-02"),
	}

	metadataReplacer := strings.NewReplacer("\n", "", "\t", "", `\\"`, `"`, ",\n}", "}")
	metadataRegex := regexp.MustCompile(`(?m)(?s)__rego_metadata__ := (\{.+?\})`)
	metadata := metadataReplacer.Replace(metadataRegex.FindStringSubmatch(string(rego))[1])
	var regoMeta RegoMetadata
	if err := json.Unmarshal([]byte(metadata), &regoMeta); err != nil {
		return nil, err
	}

	regoMeta.Title = strings.ReplaceAll(regoMeta.Title, `"`, ``)
	if regoMeta.Url != "" {
		regoMeta.Links = append(regoMeta.Links, regoMeta.Url)
	}
	regoMeta.ShortName = util.Nicify(regoMeta.ShortCode)
	regoMeta.Severity = strings.ToLower(regoMeta.Severity)

	rp.Title = regoMeta.Title
	rp.GroupName = strings.Split(regoMeta.Type, " ")[0]
	rp.Remediations = append(rp.Remediations, strings.ToLower(rp.GroupName))
	rp.PolicyUrl = strings.TrimPrefix(fileName, "appshield-repo/")
	rp.PolicyName = filepath.Base(fileName)
	rp.Rego = regoMeta
	return
}

func regoPostToMarkdown(rp RegoPost, output io.Writer) error {
	t := template.Must(template.New("regoPost").Funcs(template.FuncMap(gtf.GtfTextFuncMap)).Parse(regoPolicyPostTemplate))
	err := t.Execute(output, rp)
	if err != nil {
		return err
	}
	return nil
}

func generateAppShieldPages(policyDir, postsDir string, clock Clock) {
	for _, p := range []string{"kubernetes", "docker"} {
		policiesDir := filepath.Join(policyDir, p, "policies")
		log.Printf("generating policies in: %s...", policiesDir)
		generateAppShieldRegoPolicyPages(policyDir, policiesDir, postsDir, clock)
	}
}

func generateAppShieldRegoPolicyPages(policyDir, policiesDir string, postsDir string, clock Clock) {
	files, err := getAllFilesOfKind(policiesDir, "rego", "_test")
	if err != nil {
		log.Fatal("unable to get policy files: ", err)
	}

	for _, file := range files {
		rp, err := parseAppShieldRegoPolicyFile(file, clock)
		if err != nil {
			log.Printf("unable to parse file: %s, err: %s, skipping...\n", file, err)
			continue
		}
		topLevelID := strings.ToLower(rp.GroupName)
		misConfigurationMenu.AddNode(topLevelID, strings.Title(topLevelID), postsDir, "", rp.Remediations, []menu.MenuCategory{}, "appshield", false)

		parentID := topLevelID
		rp.ParentID = parentID

		postPath := filepath.Join(postsDir, parentID, fmt.Sprintf("%s.md", strings.ToLower(rp.Rego.ID)))
		if err := os.MkdirAll(filepath.Dir(postPath), 0755); err != nil {
			fail(err)
		}
		f, err := os.Create(postPath)
		if err != nil {
			log.Printf("unable to create file: %s for markdown, err: %s, skipping...\n", file, err)
			continue
		}

		if err := regoPostToMarkdown(*rp, f); err != nil {
			log.Printf("unable to write file: %s as markdown, err: %s, skipping...\n", file, err)
			continue
		}
		_ = f.Close()
	}
}

const regoPolicyPostTemplate = `---
title: {{.Rego.ShortName}}
id: {{.Rego.ID}}
aliases: [
	"/appshield/{{ lower .Rego.ID}}"
]
icon: appshield
source: Trivy
draft: false
date: {{.Date}}
severity: {{ .Rego.Severity }}
version: {{ .Rego.Version }}
shortName: {{ .Rego.ShortName }}
category: misconfig

avd_page_type: defsec_page

remediations:
{{ range .Remediations }}  - {{ .}}
{{ end }}

breadcrumbs: 
  - name: {{ .GroupName }}
    path: /misconfig/{{ .ParentID }}
---

### {{.Title}}
{{.Rego.Description}}

### Recommended Actions
{{ .Rego.RecommendedActions }}

### Links
{{ if .PolicyUrl}}- [REGO Policy Document](https://github.com/aquasecurity/appshield/tree/master/{{ .PolicyUrl }}){{ end }}{{range $element := .Rego.Links}}
- {{$element}}{{end}}
`
