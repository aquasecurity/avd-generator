package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

const regoPolicyPostTemplate = `---
title: "{{.Title}}"
date: {{.Date}}
draft: false

avd_page_type: appshield_page
---

### {{.Rego.ID}}

### Description
{{.Rego.Description}}

### Severity
{{ .Rego.Severity }}

### Recommended Actions 
{{ .Rego.RecommendedActions }}

### Rego Policy
` + "```\n{{ .Rego.Policy }}\n```" + `
### Links{{range $element := .Rego.Links}}
- {{$element}}{{end}}
`

type Rego struct {
	ID                 string
	Description        string
	Links              []string
	Severity           string
	Policy             string
	RecommendedActions string
}

type RegoPost struct {
	Layout string
	Title  string
	By     string
	Date   string
	Rego   Rego
}

func ParseRegoPolicyFile(fileName string) (rp RegoPost, err error) {
	rego, err := ioutil.ReadFile(fileName)
	if err != nil {
		return RegoPost{}, err
	}

	idx := strings.Index(string(rego), "package main")
	metadata := string(rego)[:idx]

	rp.Layout = "regoPolicy"
	rp.By = "Aqua Security"
	rp.Rego.Policy = strings.TrimSpace(string(rego)[idx:])
	rp.Date = time.Unix(1594669401, 0).UTC().String()

	for _, line := range strings.Split(metadata, "\n") {
		r := strings.NewReplacer("@", "", "#", "")
		str := r.Replace(line)
		kv := strings.SplitN(str, ":", 2)
		if len(kv) >= 2 {
			val := strings.TrimSpace(kv[1])
			switch strings.ToLower(strings.TrimSpace(kv[0])) {
			case "id":
				rp.Title = val
			case "description":
				rp.Rego.Description = val
			case "recommended_actions":
				rp.Rego.RecommendedActions = val
			case "severity":
				rp.Rego.Severity = val
			case "title":
				rp.Rego.ID = val
				// TODO: Add case for parsing links
			}
		}
	}

	return
}

func RegoPostToMarkdown(rp RegoPost, outputFile *os.File) error {
	t := template.Must(template.New("regoPost").Parse(regoPolicyPostTemplate))
	err := t.Execute(outputFile, rp)
	if err != nil {
		return err
	}
	return nil
}

func generateRegoPages() {
	for _, p := range []string{"kubernetes"} {
		policyDir := filepath.Join("appshield-repo", "policies", p, "policy")
		log.Printf("generating policies in: %s...", policyDir)
		generateRegoPolicyPages(policyDir, "content/appshield")
	}
}

func generateRegoPolicyPages(policyDir string, postsDir string) {
	files, err := GetAllFilesOfKind(policyDir, "rego", "_test")

	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		rp, err := ParseRegoPolicyFile(filepath.Join(policyDir, file))
		if err != nil {
			log.Printf("unable to parse file: %s, err: %s, skipping...\n", file, err)
			continue
		}

		f, err := os.Create(filepath.Join(postsDir, fmt.Sprintf("%s.md", rp.Title)))
		if err != nil {
			log.Printf("unable to create file: %s for markdown, err: %s, skipping...\n", file, err)
			continue
		}
		if err := RegoPostToMarkdown(rp, f); err != nil {
			log.Printf("unable to write file: %s as markdown, err: %s, skipping...\n", file, err)
			continue
		}
		_ = f.Close()
	}
}
