package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/aquasecurity/avd-generator/menu"
	"github.com/aquasecurity/avd-generator/util"
	"github.com/aquasecurity/tracee/tracee-rules/signatures/rego/regosig"
)

var (
	SeverityNames = []string{
		"info",
		"low",
		"medium",
		"high",
		"critical",
	}
)

func getSeverityName(sev string) string {
	sevIndex, _ := strconv.Atoi(sev)
	return SeverityNames[sevIndex]
}

func findSubstringsInString(target string, needles []string) bool {
	for _, s := range needles {
		if strings.Contains(target, s) {
			return true
		}
	}
	return false
}

func findSuffixSubstringInString(target string, needles []string) bool {
	for _, s := range needles {
		if strings.HasSuffix(target, s) {
			return true
		}
	}
	return false
}

type Signature struct {
	ID      string
	Version string
	Name    string

	Description string
	Severity    string
	MitreAttack string
	// Tags        []string
	// Properties map[string]interface{}
	RegoPolicy string
	GoCode     string
}

type TraceePost struct {
	Title      string
	Date       string
	TopLevelID string
	ParentID   string
	ParentName string
	AliasID    string
	Signature  Signature
}

func TraceePostToMarkdown(tp TraceePost, outputFile *os.File) error {
	t := template.Must(template.New("traceePost").Parse(signaturePostTemplate))
	err := t.Execute(outputFile, tp)
	if err != nil {
		return err
	}
	return nil
}

func generateTraceePages(rulesDir, postsDir string, clock Clock) {
	err := os.MkdirAll(postsDir, 0755)
	if err != nil {
		log.Fatal("unable to create tracee directory ", err)
	}

	log.Println("generating tracee pages in: ", postsDir)

	if err := generateRegoSigPages(rulesDir, postsDir, clock); err != nil {
		log.Fatal("failed to generate rego sig pages: ", err)
	}

	if err := generateGoSigPages(rulesDir, postsDir, clock); err != nil {
		log.Fatal("failed to generate go sig pages: ", err)
	}
}

func generateGoSigPages(rulesDir string, postsDir string, clock Clock) error {
	var files []string
	var err error
	if files, err = getAllFiles(rulesDir); err != nil {
		return err
	}

	for _, file := range files {
		if findSubstringsInString(file, []string{"helpers.go", "example.go", "export.go", "traceerego.go", "aio", "common", "mapper"}) || findSuffixSubstringInString(file, []string{".md", ".rego", "test.go"}) {
			continue
		}

		b, _ := ioutil.ReadFile(file)
		r := strings.NewReplacer(`"`, ``)
		rTitle := strings.NewReplacer("/", "-", `"`, "")

		// TODO: Check for split string length before indexing to avoid panic
		sig := Signature{
			ID:          r.Replace(strings.TrimSpace(strings.Split(regexp.MustCompile(`(ID)\:\s*\"(.*?)"`).FindString(string(b)), ":")[1])),
			Version:     r.Replace(strings.TrimSpace(strings.Split(regexp.MustCompile(`(Version)\:\s*\"(.*?)\"`).FindString(string(b)), ":")[1])),
			Name:        rTitle.Replace(strings.TrimSpace(strings.Split(regexp.MustCompile(`(Name)\:\s*\"(.*?)\"`).FindString(string(b)), ":")[1])),
			Description: r.Replace(strings.TrimSpace(strings.Split(regexp.MustCompile(`(Description)\:\s*\"(.*?)\"`).FindString(string(b)), ":")[1])),
			Severity:    getSeverityName(r.Replace(strings.TrimSpace(strings.Split(regexp.MustCompile(`\"(Severity)\"\:\s*\d`).FindString(string(b)), ":")[1]))),
			MitreAttack: r.Replace(strings.TrimSpace(strings.Split(regexp.MustCompile(`\"(MITRE ATT&CK)\"\:\s*\"(...)*`).FindString(string(b)), `: "`)[1])),
			GoCode:      string(b),
		}

		topLevelIDName := strings.TrimSpace(strings.Split(sig.MitreAttack, ":")[0])
		topLevelID := strings.ToLower(strings.ReplaceAll(topLevelIDName, " ", "-"))
		runTimeSecurityMenu.AddNode(topLevelID, strings.Title(topLevelIDName), postsDir, "", []string{"runtime"}, []menu.MenuCategory{
			{Name: "Runtime Security", Url: "/tracee"},
		}, "runtime", true)
		parentID := topLevelID

		outputFilepath := filepath.Join(postsDir, parentID, fmt.Sprintf("%s.md", strings.ReplaceAll(sig.ID, "-", "")))
		if err := os.MkdirAll(filepath.Dir(outputFilepath), 0755); err != nil {
			log.Printf("error occurred while creating target directory: %s, %s", filepath.Dir(outputFilepath), err)
		}

		f, err := os.Create(outputFilepath)
		if err != nil {
			log.Printf("unable to create tracee markdown file: %s for sig: %s, skipping...\n", err, sig.ID)
			continue
		}

		if err = TraceePostToMarkdown(TraceePost{
			Title:      util.Nicify(strings.Title(strings.ReplaceAll(sig.Name, "-", " "))),
			TopLevelID: parentID,
			ParentID:   parentID,
			ParentName: strings.Title(topLevelIDName),
			AliasID:    strings.ToLower(strings.ReplaceAll(sig.ID, "-", "")),
			Date:       clock.Now("2006-01-02"),
			Signature:  sig,
		}, f); err != nil {
			log.Printf("unable to write tracee signature markdown: %s.md, err: %s", sig.ID, err)
			continue
		}
	}

	return nil
}

func generateRegoSigPages(rulesDir string, postsDir string, clock Clock) error {
	files, err := getAllFilesOfKind(rulesDir, "rego", "_test")
	if err != nil {
		log.Println("unable to get rego signature files: ", err)
		return err
	}

	helpers, err := ioutil.ReadFile(filepath.Join(rulesDir, "rego", "helpers.rego"))
	if err != nil {
		log.Println("unable to read helpers.rego file: ", err)
		return err
	}

	for _, file := range files {
		if findSubstringsInString(file, []string{"helpers", "example", ".go", "aio"}) { // TODO: This should be handled by a filter in GetAllFilesOfKind
			continue
		}

		b, err := ioutil.ReadFile(file)
		if err != nil {
			log.Printf("unable to read signature file: %s, %s\n", file, err)
			return err
		}

		sig, err := regosig.NewRegoSignature("rego", false, string(b), string(helpers))
		if err != nil {
			log.Printf("unable to create new rego signature in file %s: %s\n", file, err)
			return err
		}
		m, _ := sig.GetMetadata()

		var severity int64
		if m.Properties["Severity"] != nil {
			severity, _ = m.Properties["Severity"].(json.Number).Int64()
		}
		var ma string
		if m.Properties["MITRE ATT&CK"] != nil {
			ma = m.Properties["MITRE ATT&CK"].(string)
		}

		topLevelIDName := strings.TrimSpace(strings.Split(ma, ":")[0])
		topLevelID := strings.ToLower(strings.ReplaceAll(topLevelIDName, " ", "-"))
		runTimeSecurityMenu.AddNode(topLevelID, strings.Title(topLevelIDName), postsDir, "tracee", []string{"runtime"}, []menu.MenuCategory{
			{Name: "Tracee", Url: "/tracee"},
		}, "tracee", false)
		parentID := topLevelID

		outputFilepath := filepath.Join(postsDir, parentID, fmt.Sprintf("%s.md", strings.ReplaceAll(m.ID, "-", "")))
		if err := os.MkdirAll(filepath.Dir(outputFilepath), 0755); err != nil {
			log.Printf("error occurred while creating target directory: %s, %s", filepath.Dir(outputFilepath), err)
		}

		f, err := os.Create(outputFilepath)
		if err != nil {
			log.Printf("unable to create tracee markdown file: %s for sig: %s, skipping...\n", err, m.ID)
			continue
		}

		if err = TraceePostToMarkdown(TraceePost{
			Title:      util.Nicify(strings.Title(m.Name)),
			ParentID:   parentID,
			ParentName: strings.Title(topLevelIDName),
			AliasID:    strings.ToLower(strings.ReplaceAll(m.ID, "-", "")),
			TopLevelID: parentID,
			Date:       clock.Now("2006-01-02"),
			Signature: Signature{
				ID:          m.ID,
				Version:     m.Version,
				Name:        strings.ReplaceAll(m.Name, " ", "-"),
				Description: m.Description,
				Severity:    SeverityNames[severity],
				MitreAttack: ma,
				RegoPolicy:  string(b),
			},
		}, f); err != nil {
			log.Printf("unable to write tracee signature markdown: %s.md, err: %s", m.ID, err)
			continue
		}

		// TODO: Add MITRE classification details
		// TODO: Add ability to append custom aqua blog post from another markdown
	}
	return nil
}

const signaturePostTemplate = `---
title: {{.Title}}
id: {{.Signature.ID}}
aliases: [
    "/tracee/{{ .AliasID}}"
]
source: Tracee
icon: aqua
shortName: {{.Title}}
severity: {{.Signature.Severity}}
draft: false
version: {{.Signature.Version}}
keywords: "{{.Signature.ID}}"

category: runsec
date: {{.Date}}

remediations:

breadcrumbs: 
  - name: Tracee
    path: /tracee
  - name: {{ .ParentName }}
    path: /tracee/{{ .ParentID }}

avd_page_type: avd_page
---

### {{.Title}}
{{.Signature.Description}}

### MITRE ATT&CK
{{.Signature.MitreAttack}}


{{if .Signature.RegoPolicy}}### Rego Policy
` + "```\n{{ .Signature.RegoPolicy }}\n```" + `
{{- end}}
{{- if .Signature.GoCode}}### Go Source
` + "```\n{{ .Signature.GoCode }}\n```" + `
{{- end}}
`
