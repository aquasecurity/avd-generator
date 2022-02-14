package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/avd-generator/docGen/menu"
)

func generateKubeHunterPages(inputPagesDir string, outputPagesDir string) {
	log.Printf("generating kube-hunter pages in: %s...", outputPagesDir)

	if err := os.MkdirAll(outputPagesDir, 0777); err != nil {
		panic(err)
	}
	pages, err := getAllFiles(inputPagesDir)
	if err != nil {
		log.Fatal(err)
	}

	titleRegex := regexp.MustCompile("(?m)title: (.+)$")

	for _, page := range pages {
		b, err := ioutil.ReadFile(page)
		if err != nil {
			log.Println("unable to read original kube hunter doc: ", err)
			continue
		}

		id := filepath.Base(page)
		title := titleRegex.FindSubmatch(b)[1]

		newContent := strings.Replace(string(b), "---", fmt.Sprintf(`---
avd_page_type: kube-hunter_page
shortName: %s
sidebar_category: misconfig

remediations:
  - kubernetes

menu:
  misconfig:
    identifier: %s
    name: %s
    parent: kubernetes/kubehunter

`, string(title), id, string(title)), 1)
		r := strings.NewReplacer(
			"# {{ page.vid }} - {{ page.title }}", "",
			"title", "description",
			"vid", "title",
			"categories: ", "types: ",
			"## Remediation", "### Recommended Actions",
			"## References", "### Links",
			"## Issue description", fmt.Sprintf(`
Misconfiguration > [Kubernetes](../../) > [Kube Hunter](../) > %s

### %s`, id, string(title)))
		content := r.Replace(newContent)

		err = ioutil.WriteFile(filepath.Join(outputPagesDir, filepath.Base(page)), []byte(content), 0644)
		if err != nil {
			log.Fatalln("unable to write kube hunter page: ", err)
		}
	}

	topLevelPath := filepath.Join(outputPagesDir, "_index.md")
	menu.NewTopLevelMenu("Kube Hunter Misconfiguration", "avd_list", topLevelPath).
		WithHeading("Kube Hunter").
		WithIcon("kubehunter").
		WithCategory("misconfig").
		WithMenu("Kube Hunter").
		WithMenuID("kubehunter").
		WithMenuParent("kubernetes").
		Generate()
}
