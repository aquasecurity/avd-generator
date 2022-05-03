package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"text/template"

	"path/filepath"

	"github.com/Masterminds/semver"
	"github.com/aquasecurity/avd-generator/menu"
	"gopkg.in/yaml.v3"
)

type ChainBenchRulesConfig struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Checks map[string]struct {
		Title       string `json:"title"`
		Type        string `json:"type"`
		Description string `json:"description"`
		Remediation string `json:"remediation"`
	} `json:"checks"`
}

type ChainBenchSectionsConfig struct {
	Version  string `json:"version"`
	ID       string `json:"id"`
	Text     string `json:"text"`
	Type     string `json:"type"`
	Sections map[string]ChainBenchRulesConfig
}

func generateChainBenchPages(configDir, outputDir string) {
	var rulesConfigs []ChainBenchRulesConfig
	var sectionsConfigs []ChainBenchSectionsConfig

	if err := filepath.Walk(configDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !strings.HasSuffix(info.Name(), ".metadata.json") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		switch info.Name() {
		case "rules.metadata.json":
			var ruleConfig ChainBenchRulesConfig
			if err := yaml.Unmarshal(content, &ruleConfig); err != nil {
				return err
			}
			rulesConfigs = append(rulesConfigs, ruleConfig)
		case "sections.metadata.json":
			var sectionConfig ChainBenchSectionsConfig
			if err := yaml.Unmarshal(content, &sectionConfig); err != nil {
				return err
			}
			sectionsConfigs = append(sectionsConfigs, sectionConfig)
		}

		return nil
	}); err != nil {
		fmt.Println(err)
	}
	versionedConf := make(map[string]ChainBenchSectionsConfig, 3)

	for _, sectionConfig := range sectionsConfigs {
		configTypeMap := sectionConfig
		configTypeMap.Sections = make(map[string]ChainBenchRulesConfig)
		versionedConf[strconv.FormatInt(semver.MustParse(sectionConfig.ID).Major(), 10)] = configTypeMap
	}

	for _, ruleConfig := range rulesConfigs {
		version := strconv.FormatInt(semver.MustParse(ruleConfig.ID).Major(), 10)
		versionedConf[version].Sections[ruleConfig.ID] = ruleConfig
	}

	versioned := make(map[string]map[string]ChainBenchSectionsConfig)
	versioned["cis-1.0"] = versionedConf
	if err := writeSupplyChainTemplates(versioned, outputDir); err != nil {
		fmt.Println(err)
	}
}

func writeSupplyChainTemplates(versionedConfigs map[string]map[string]ChainBenchSectionsConfig, outputDir string) error {
	complianceMenu.AddNode("softwaresupplychain", "Software Supply Chain", outputDir, "compliance", []string{},
		[]menu.BreadCrumb{{Name: "Compliance", Url: "/compliance"}}, "softwaresupplychain", true)

	outputDir = filepath.Join(outputDir, "softwaresupplychain")

	t := template.Must(template.New("bodyContent").Parse(chainBenchTemplate))
	for version, grouping := range versionedConfigs {
		complianceMenu.AddNode(version, cisVersion(version), filepath.Join(outputDir),
			"softwaresupplychain", []string{},
			[]menu.BreadCrumb{{Name: "Compliance", Url: "/compliance"},
				{Name: "Software Supply Chain", Url: "/compliance/softwaresupplychain"}}, "softwaresupplychain", true)

		for group, config := range grouping {

			complianceMenu.AddNode(fmt.Sprintf("%s-%s", version, config.Type), config.Text, filepath.Join(outputDir, version),
				version, []string{},
				[]menu.BreadCrumb{
					{Name: "Compliance", Url: "/compliance"},
					{Name: "Software Supply Chain", Url: "/compliance/softwaresupplychain"},
					{Name: cisVersion(version), Url: fmt.Sprintf("/compliance/softwaresupplychain/%s", version)},
				}, "aqua", false)

			for id, checkGroup := range config.Sections {

				targetFilePath := filepath.Join(outputDir, version, fmt.Sprintf("%s-%s", version, config.Type),
					fmt.Sprintf("%s.md", checkGroup.ID))
				if err := os.MkdirAll(filepath.Dir(targetFilePath), os.ModePerm); err != nil {
					return err
				}
				var documentBody bytes.Buffer
				if err := t.Execute(&documentBody, map[string]interface{}{
					"ShortName":   checkGroup.Name,
					"ID":          id,
					"Version":     version,
					"NiceVersion": cisVersion(version),
					"Category":    config.Type,
					"Checks":      checkGroup.Checks,
					"ParentID":    group,
					"ParentTitle": config.Text,
				}); err != nil {
					return err
				}

				if err := os.WriteFile(targetFilePath, documentBody.Bytes(), os.ModePerm); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

const chainBenchTemplate string = `---
title: {{.ShortName}}
id: {{ .ID }}
source: Chain Bench
icon: chain-bench
draft: false
shortName: {{.ShortName}}
severity: "n/a"
version: {{ .Version}}
category: compliance
keywords: "{{ .Category }}"

breadcrumbs: 
  - name: Compliance
    path: /compliance
  - name: Software Supply Chain
    path: /compliance/softwaresupplychain
  - name: {{ .NiceVersion }}
    path: /compliance/softwaresupplychain/{{ .Version}}
  - name: {{ .ParentTitle }}
    path: /compliance/softwaresupplychain/{{ .Version}}/{{ .Version}}-{{ .Category}}


avd_page_type: avd_page

---

### {{ .ID }} {{ .ShortName }}
{{ range $key, $value := .Checks }}
####  {{$key }} {{ $value.Title }}

##### Recommended Action
{{ $value.Remediation }}
<br />

{{ end }}
`
