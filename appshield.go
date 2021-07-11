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
)

const regoPolicyPostTemplate = `---
title: "{{.Rego.ID}}"
date: {{.Date}}
draft: false

avd_page_type: appshield_page
---

### {{.Title}}

### Version
{{.Rego.Version}}

### Description
{{.Rego.Description}}

### Severity
{{ .Rego.Severity }}

### Recommended Actions
{{ .Rego.RecommendedActions }}

### Links{{range $element := .Rego.Links}}
- {{$element}}{{end}}

### Rego Policy
` + "```\n{{ .Rego.Policy }}\n```" + `
`

type Rego struct {
	ID                 string
	Version            string
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

func ParseAppShieldRegoPolicyFile(fileName string, clock Clock) (rp RegoPost, err error) {
	rego, err := ioutil.ReadFile(fileName)
	if err != nil {
		return RegoPost{}, err
	}

	rp.Layout = "regoPolicy"
	rp.By = "Aqua Security"
	rp.Rego.Policy = strings.TrimSpace(string(rego))
	rp.Date = clock.Now()

	r := strings.NewReplacer(`"`, ``)
	rTitle := strings.NewReplacer("/", "-", `"`, "")
	rp.Rego.ID = r.Replace(strings.TrimSpace(strings.Split(regexp.MustCompile(`(\"id\")\:\s*\"(.*?)"`).FindString(string(rego)), ":")[1]))
	rp.Rego.Version = r.Replace(strings.TrimSpace(strings.Split(regexp.MustCompile(`(\"version\")\:\s*\"(.*?)\"`).FindString(string(rego)), ":")[1]))
	rp.Title =
		rTitle.Replace(strings.TrimSpace(strings.Split(regexp.MustCompile(`(\"title\")\:\s*\"(.*?)\"`).FindString(string(rego)), ":")[1]))
	rp.Rego.Description =
		r.Replace(strings.TrimSpace(strings.Split(regexp.MustCompile(`(\"description\")\:\s*\"(.*?)\"`).FindString(string(rego)), ":")[1]))
	rp.Rego.Severity =
		getSeverityName(r.Replace(strings.TrimSpace(strings.Split(regexp.MustCompile(`(\"severity\")\:\s*\"(.*?)\"`).FindString(string(rego)), ":")[1])))

	recommendedActions := regexp.MustCompile(`(\"recommended_actions\")\:\s*\"(.*?)\"`).FindString(string(rego))
	if recommendedActions != "" {
		rp.Rego.RecommendedActions = r.Replace(strings.TrimSpace(strings.Split(recommendedActions, ":")[1]))
	}

	reference := regexp.MustCompile(`(\"url\")\:\s*\"(.*?)\"`).FindString(string(rego))
	if reference != "" {
		reference = r.Replace(strings.TrimSpace(strings.SplitN(reference, ":", 2)[1]))
		rp.Rego.Links = []string{reference}
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

func generateAppShieldPages(policyDir, postsDir string, clock Clock) {
	for _, p := range []string{"kubernetes", "docker"} {
		policyDir := filepath.Join(policyDir, p, "policies")
		log.Printf("generating policies in: %s...", policyDir)
		generateAppShieldRegoPolicyPages(policyDir, postsDir, clock)
	}
}

func generateAppShieldRegoPolicyPages(policyDir string, postsDir string, clock Clock) {
	files, err := GetAllFilesOfKind(policyDir, "rego", "_test")
	if err != nil {
		log.Fatal("unable to get policy files: ", err)
	}

	for _, file := range files {
		rp, err := ParseAppShieldRegoPolicyFile(file, clock)
		if err != nil {
			log.Printf("unable to parse file: %s, err: %s, skipping...\n", file, err)
			continue
		}

		f, err := os.Create(filepath.Join(postsDir, fmt.Sprintf("%s.md", rp.Rego.ID)))
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
