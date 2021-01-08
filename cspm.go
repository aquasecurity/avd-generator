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

	"github.com/leekchan/gtf"
)

const cloudSploitTableOfContents = `---
title: Aqua_CSPM_Remediations
draft: false

display_title: "Aqua CSPM Remediations"
avd_page_type: cloudsploit_page
---

{{range $provider, $serviceFile := .}}### {{ $provider | upper }} {.listpage_section_title}
{{ range $service, $files := .}}#### {{ $service }} {.listpage_subsection_title}
{{ range $file := .}}- [{{ $file }}](/cspm/{{ $provider }}/{{ $service | lower | findreplace " " "-" }}/{{ $file | lower | findreplace " " "-" }})
{{ end }}{{ end }}{{ end }}`

// {"aws":{"acm":{"foo","bar"},"elb":{"foo2","bar2"}},"google":{"dns"}}
type CloudSploitIndexMap map[string]map[string][]string

func generateCloudSploitPages(inputPagesDir string, outputPagesDir string) {
	log.Printf("generating cloudsploit pages in: %s...", outputPagesDir)
	var fileList []string
	_ = filepath.Walk(inputPagesDir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		fileList = append(fileList, path)
		return nil
	})

	csIndexMap := make(CloudSploitIndexMap)

	for _, file := range fileList {
		b, _ := ioutil.ReadFile(file)
		category := regexp.MustCompile(`\|\s\*\*(Category)\*\*\s\|\s.*`).Find(b)
		service := strings.TrimSpace(strings.Split(string(category), "|")[2])

		fullPath := strings.Split(file, "en/")[1]
		provider := strings.Split(fullPath, "/")[0]
		pluginTitle := regexp.MustCompile(`\|\s\*\*(Plugin Title)\*\*\s\|\s.*`).Find(b)
		fileName := strings.TrimSpace(strings.Split(string(pluginTitle), "|")[2])

		if v, ok := csIndexMap[provider]; !ok {
			csIndexMap[provider] = map[string][]string{
				service: {fileName},
			}
		} else {
			csIndexMap[provider][service] = append(v[service], fileName)
		}

		b, err := ioutil.ReadFile(file)
		if err != nil {
			log.Println("unable to read cloudsploit file: ", err)
			continue
		}

		fileContent := strings.Split(string(b), "## Quick Info")[1]
		contentReplacer := strings.NewReplacer(`</br> <img src="`, `\
![](`, `</br><img src="`, `\
![](`, `"/>`, `)`)
		fileContent = contentReplacer.Replace(fileContent)

		err = os.MkdirAll(filepath.Join(outputPagesDir, provider, service), 0755)
		if err != nil {
			log.Fatal("unable to create cloudsploit directory ", err)
		}

		// strip any nasty chars for search index primary key
		titleSanitizer := strings.NewReplacer(" ", "-", ".", "")

		err = ioutil.WriteFile(filepath.Join(outputPagesDir, provider, service, strings.ToLower(strings.ReplaceAll(fileName, " ", "-"))+".md"), append([]byte(fmt.Sprintf(`---
title: %s
draft: false

display_title: %s
avd_page_type: cloudsploit_page

breadcrumb_remediation_parent: %s
breadcrumb_remediation_parent_name: %s
breadcrumb_remediation_child: %s
breadcrumb_remediation_child_name: %s
---
### Quick Info`, titleSanitizer.Replace(fileName), fileName, strings.ToLower(provider), strings.ToUpper(provider), strings.ReplaceAll(strings.ToLower(service), " ", "-"), service)), []byte(fileContent)...), 0600)
		if err != nil {
			log.Println("unable to write cloudsploit file: ", err)
			continue
		}
	}

	// generate a table of contents markdown
	f, err := os.Create(filepath.Join(outputPagesDir, "_index.md"))
	if err != nil {
		log.Fatal("unable to create a table of contents _index.md file: ", err)
	}
	t := template.Must(template.New("cloudSploitTableOfContents").Funcs(gtf.GtfTextFuncMap).Parse(cloudSploitTableOfContents))
	err = t.Execute(f, csIndexMap)
	if err != nil {
		log.Fatal(err)
	}
}
