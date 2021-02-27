package main

import (
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
)

func generateKubeHunterPages(inputPagesDir string, outputPagesDir string) {
	log.Printf("generating kube-hunter pages in: %s...", outputPagesDir)
	pages, err := GetAllFiles(inputPagesDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, page := range pages {
		b, err := ioutil.ReadFile(page)
		if err != nil {
			log.Println("unable to read original kube hunter doc: ", err)
			continue
		}

		newContent := strings.Replace(string(b), "---", `---
avd_page_type: kube-hunter_page
`, 1)
		r := strings.NewReplacer(
			"# {{ page.vid }} - {{ page.title }}", "",
			"title", "description",
			"vid", "title",
			"categories: ", "types: ")
		content := r.Replace(newContent)

		err = ioutil.WriteFile(filepath.Join(outputPagesDir, filepath.Base(page)), []byte(content), 0644)
		if err != nil {
			log.Fatalln("unable to write kube hunter page: ", err)
		}
	}
}
