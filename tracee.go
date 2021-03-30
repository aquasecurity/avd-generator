package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/aquasecurity/tracee/tracee-rules/signatures/rego/regosig"
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

### Rego Policy
` + "```\n{{ .RegoPolicy }}\n```" + `
`

func TraceePostToMarkdown(tp TraceePost, outputFile *os.File) error {
	t := template.Must(template.New("traceePost").Parse(signaturePostTemplate))
	err := t.Execute(outputFile, tp)
	if err != nil {
		return err
	}
	return nil
}

func generateTraceePages(rulesDir, postsDir string, clock Clock) error {
	log.Println("generating tracee pages in: ", postsDir)

	files, err := GetAllFilesOfKind(rulesDir, "rego", "_test")
	if err != nil {
		log.Println("unable to get signature files: ", err)
		return err
	}

	helpers, err := ioutil.ReadFile(filepath.Join(rulesDir, "helpers.rego"))
	if err != nil {
		log.Printf("unable to read helpers.rego file: %s\n", err)
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
