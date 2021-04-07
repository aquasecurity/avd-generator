package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
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

func generateTraceePages(rulesDir, postsDir string, clock Clock) error {
	log.Println("generating tracee pages in: ", postsDir)

	if err := generateRegoSigPages(rulesDir, postsDir, clock); err != nil {
		return err
	}

	if err := generateGoSigPages(rulesDir, postsDir, clock); err != nil {
		return err
	}

	return nil
}

func generateGoSigPages(rulesDir string, postsDir string, clock Clock) error {
	fset := token.NewFileSet()
	files, err := GetAllFilesOfKind(rulesDir, ".go", "_test.go")
	if err != nil {
		log.Println("unable to get golang signature files: ", err)
		return err
	}

	for _, file := range files {
		if !strings.Contains(file, "stdio") { // TODO: Remove this
			continue
		}

		b, err := ioutil.ReadFile(file)
		if err != nil {
			log.Println("unable to read golang signature file: ", file, err, "skipping...")
			continue
		}
		f, err := parser.ParseFile(fset, "", string(b), 0)
		if err != nil {
			log.Println("unable to parse golang signature file: ", file, err, "skipping...")
			continue
		}

		//ast.Print(fset, f) // debug output
		sm := Signature{}

		for _, dec := range f.Decls {
			if fn, ok := dec.(*ast.FuncDecl); ok {
				if fn.Name.String() != "GetMetadata" {
					continue
				}

				for _, b := range fn.Body.List {
					if res, ok := b.(*ast.ReturnStmt); ok {
						for _, r := range res.Results {
							if cl, ok := r.(*ast.CompositeLit); ok {
								for _, elt := range cl.Elts {
									if kv, ok := elt.(*ast.KeyValueExpr); ok {
										if val, ok := kv.Value.(*ast.BasicLit); ok { // id, version, name, description
											val.Value = strings.ReplaceAll(val.Value, `"`, ``)
											key, _ := kv.Key.(*ast.Ident)
											switch key.Name {
											case "ID":
												sm.ID = val.Value
											case "Version":
												sm.Version = val.Value
											case "Name":
												sm.Name = strings.ReplaceAll(val.Value, "/", "-")
											case "Description":
												sm.Description = val.Value
											default:
												log.Println("unknown key in signature metadata: ", key.Name, "file: ", file)
											}
											continue
										}
										if val, ok := kv.Value.(*ast.CompositeLit); ok { // properties
											if keyName, ok := kv.Key.(*ast.Ident); ok {
												if keyName.Name == "Properties" {
													for _, elt := range val.Elts {
														if prop, ok := elt.(*ast.KeyValueExpr); ok {
															if k, ok := prop.Key.(*ast.BasicLit); ok {
																if v, ok := prop.Value.(*ast.BasicLit); ok {
																	switch k.Value {
																	case `"Severity"`:
																		sev, _ := strconv.Atoi(v.Value)
																		sm.Severity = SeverityNames[sev]
																	case `"MITRE ATT&CK"`:
																		sm.MitreAttack = strings.ReplaceAll(v.Value, `"`, ``)
																	default:
																		log.Println("unknown key in signature metadata properties: ", k.Value, "file: ", file)
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}

			}
		}

		// at this point sm should be populated
		r := strings.NewReplacer("-", "", `"`, ``)
		of, err := os.Create(filepath.Join(postsDir, fmt.Sprintf("%s.md", r.Replace(sm.ID))))
		if err != nil {
			log.Printf("unable to create tracee markdown file: %s for sig: %s, skipping...\n", err, sm.ID)
			continue
		}
		if err = TraceePostToMarkdown(TraceePost{
			Date: clock.Now(),
			Signature: Signature{
				ID:          sm.ID,
				Version:     sm.Version,
				Name:        sm.Name,
				Description: sm.Description,
				Severity:    sm.Severity,
				MitreAttack: sm.MitreAttack,
				GoCode:      string(b),
			},
		}, of); err != nil {
			log.Printf("unable to write tracee signature markdown: %s.md, err: %s", sm.ID, err)
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
