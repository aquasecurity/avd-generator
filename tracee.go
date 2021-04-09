package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/aquasecurity/tracee/tracee-rules/signatures/rego/regosig"
	traceesigs "github.com/simar7/tracee-signatures/golang" // TODO: Update to Aqua repo
)

var (
	SeverityNames = []string{
		"Informative",
		"Low",
		"Medium",
		"High",
		"Critical",
	}
)

type Signature struct {
	ID          string
	Version     string
	Name        string
	Description string
	Severity    string
	MitreAttack string
	//Tags        []string
	//Properties  map[string]interface{}
	RegoPolicy string
	GoCode     string
}

type TraceePost struct {
	Date string
	Signature
}

const signaturePostTemplate = `---
title: "{{.Name}}"
date: {{.Date}}
draft: false

avd_page_type: tracee_page
---

### {{.ID}}
#### {{.Name}}

### Severity
#### {{.Severity}}

### Description
{{.Description}}

### MITRE ATT&CK
{{.MitreAttack}}

### Version
{{.Version}}

{{if .RegoPolicy}}### Rego Policy
` + "```\n{{ .RegoPolicy }}\n```" + `
{{- end}}
{{- if .GoCode}}### Go Source
` + "```\n{{ .GoCode }}\n```" + `
{{- end}}
`

func TraceePostToMarkdown(tp TraceePost, outputFile *os.File) error {
	t := template.Must(template.New("traceePost").Parse(signaturePostTemplate))
	err := t.Execute(outputFile, tp)
	if err != nil {
		return err
	}
	return nil
}

func generateTraceePages(rulesDir, postsDir string, clock Clock) {
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
	if files, err = GetAllFiles(rulesDir); err != nil {
		return err
	}

	// gather all signatures and their data
	type fileMap struct {
		sigID        string
		fileContents string
		fileName     string
	}
	var fm []fileMap
	for _, file := range files {
		if strings.Contains(file, "helpers.go") || strings.Contains(file, "example.go") || strings.Contains(file, "export.go") {
			continue
		}
		b, _ := ioutil.ReadFile(file)
		fm = append(fm, fileMap{
			fileName:     file,
			sigID:        regexp.MustCompile(`(TRC)\-\d+`).FindString(string(b)),
			fileContents: string(b)})
	}

	// iterate over exported signatures
	for _, sig := range traceesigs.ExportedSignatures {
		m, err := sig.GetMetadata()
		if err != nil {
			log.Println("unable to get signature metadata: ", err, "skipping..")
			continue
		}

		r := strings.NewReplacer("-", "", `"`, ``)
		of, err := os.Create(filepath.Join(postsDir, fmt.Sprintf("%s.md", r.Replace(m.ID))))
		if err != nil {
			log.Printf("unable to create tracee markdown file: %s for sig: %s, skipping...\n", err, m.ID)
			continue
		}

		var goCode string
		for _, f := range fm {
			if f.sigID == m.ID {
				goCode = f.fileContents
			}
		}

		if err = TraceePostToMarkdown(TraceePost{
			Date: clock.Now(),
			Signature: Signature{
				ID:          m.ID,
				Version:     m.Version,
				Name:        strings.ReplaceAll(m.Name, "/", "-"),
				Description: m.Description,
				Severity:    SeverityNames[m.Properties["Severity"].(int)],
				MitreAttack: strings.ReplaceAll(m.Properties["MITRE ATT&CK"].(string), `"`, ``),
				GoCode:      goCode,
			},
		}, of); err != nil {
			log.Printf("unable to write tracee signature markdown: %s.md, err: %s", m.ID, err)
			continue
		}
	}
	return nil
}

func generateRegoSigPages(rulesDir string, postsDir string, clock Clock) error {
	files, err := GetAllFilesOfKind(rulesDir, "rego", "_test")
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
		if strings.Contains(file, "helpers") || strings.Contains(file, "traceerego.go") || strings.Contains(file, "example") { // TODO: This should be handled by a filter in GetAllFilesOfKind
			continue
		}

		b, err := ioutil.ReadFile(file)
		if err != nil {
			log.Printf("unable to read signature file: %s, %s\n", file, err)
			return err
		}

		sig, err := regosig.NewRegoSignature(string(b), string(helpers))
		if err != nil {
			log.Printf("unable to create new rego signature in file %s: %s\n", file, err)
			return err
		}
		m, _ := sig.GetMetadata()

		f, err := os.Create(filepath.Join(postsDir, fmt.Sprintf("%s.md", strings.ReplaceAll(m.ID, "-", ""))))
		if err != nil {
			log.Printf("unable to create tracee markdown file: %s for sig: %s, skipping...\n", err, m.ID)
			continue
		}

		var severity int64
		if m.Properties["Severity"] != nil {
			severity, _ = m.Properties["Severity"].(json.Number).Int64()
		}
		var ma string
		if m.Properties["MITRE ATT&CK"] != nil {
			ma = m.Properties["MITRE ATT&CK"].(string)
		}
		if err = TraceePostToMarkdown(TraceePost{
			Date: clock.Now(),
			Signature: Signature{
				//Tags:        m.Tags,
				//Properties:  m.Properties,
				ID:          m.ID,
				Version:     m.Version,
				Name:        m.Name,
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
