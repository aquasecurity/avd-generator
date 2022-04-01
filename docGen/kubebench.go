package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"text/template"

	"path/filepath"

	"github.com/aquasecurity/avd-generator/menu"
	"github.com/aquasecurity/avd-generator/util"
	"gopkg.in/yaml.v3"
)

type KubeBenchConfig struct {
	Version string `yaml:"version"`
	ID      string `yaml:"id"`
	Text    string `yaml:"text"`
	Type    string `yaml:"type"`
	Groups  []struct {
		ID     string `yaml:"id"`
		Text   string `yaml:"text"`
		Checks []struct {
			ID          string `yaml:"id"`
			Text        string `yaml:"text"`
			Type        string `yaml:"type"`
			Remediation string `yaml:"remediation"`
			Scored      bool   `yaml:"scored"`
		} `yaml:"checks"`
	} `yaml:"groups"`
}

func generateKubeBenchPages(configDir, outputDir string) {

	misConfigurationMenu.AddNode("kubernetes", "Kubernetes", outputDir, "", []string{}, []menu.MenuCategory{}, "kubernetes", false)

	var configs []KubeBenchConfig

	if err := filepath.Walk(configDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || info.Name() == "config.yaml" {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var config KubeBenchConfig
		if err := yaml.Unmarshal(content, &config); err != nil {
			return err
		}

		configs = append(configs, config)

		return nil
	}); err != nil {
		fmt.Println(err)
	}
	versionedConfigs := make(map[string]map[string]KubeBenchConfig)

	for _, config := range configs {
		if _, ok := versionedConfigs[config.Version]; !ok {
			versionedConfigs[config.Version] = make(map[string]KubeBenchConfig)
		}
		configTypeMap := versionedConfigs[config.Version]
		if _, ok := configTypeMap[config.Type]; !ok {
			configTypeMap[config.Type] = config
		}

		versionedConfigs[config.Version] = configTypeMap
	}

	if err := writeTemplates(versionedConfigs, outputDir); err != nil {
		fmt.Println(err)
	}
}

func writeTemplates(versionedConfigs map[string]map[string]KubeBenchConfig, outputDir string) error {

	t := template.Must(template.New("bodyContent").Parse(kubeBenchTemplate))

	for version, grouping := range versionedConfigs {
		for group, config := range grouping {
			misConfigurationMenu.AddNode(fmt.Sprintf("%s-%s", version, group), config.Text, filepath.Join(outputDir, "kubernetes", version),
				version, []string{},
				[]menu.MenuCategory{{Name: "Kubernetes", Url: "/misconfig/kubernetes"}, {Name: fmt.Sprintf("Benchmarks - %s", util.Nicify(version)), Url: fmt.Sprintf("/misconfig/kubernetes/%s", version)}}, "kubernetes", false)
			for _, checkGroup := range config.Groups {

				targetFilePath := filepath.Join(outputDir, "kubernetes", version, fmt.Sprintf("%s-%s", version, group), checkGroup.ID, fmt.Sprintf("%s.md", group))
				if err := os.MkdirAll(filepath.Dir(targetFilePath), os.ModePerm); err != nil {
					return err
				}
				var documentBody bytes.Buffer

				postDetails := map[string]interface{}{
					"ShortName":   checkGroup.Text,
					"ID":          checkGroup.ID,
					"Version":     config.Version,
					"NiceVersion": util.Nicify(config.Version),
					"Category":    config.Type,
					"Checks":      checkGroup.Checks,
					"ParentID":    group,
					"ParentTitle": config.Text,
				}

				if err := t.Execute(&documentBody, postDetails); err != nil {
					return err
				}

				if err := os.WriteFile(targetFilePath, documentBody.Bytes(), os.ModePerm); err != nil {
					return err
				}
				misConfigurationMenu.AddNode(checkGroup.ID, checkGroup.Text, filepath.Join(outputDir, "kubernetes", version, group),
					fmt.Sprintf("%s-%s", version, group), []string{},
					[]menu.MenuCategory{{Name: "Kubernetes", Url: "/misconfig/kubernetes"},
						{Name: config.Text, Url: fmt.Sprintf("/misconfig/kubernetes/%s-%s", version, group)}}, "kubernetes", false)
			}

		}

		misConfigurationMenu.AddNode(version, fmt.Sprintf("Benchmarks - %s", util.Nicify(version)), filepath.Join(outputDir, "kubernetes"),
			"benchmarks", []string{},
			[]menu.MenuCategory{{Name: "Kubernetes", Url: "/misconfig/kubernetes"}}, "kubernetes", false)

	}

	return nil
}

const kubeBenchTemplate string = `---
title: {{.ShortName}}
id: {{ .ID }}
source: Kube Bench
icon: kubernetes
draft: false
shortName: {{.ShortName}}
severity: "n/a"
version: {{ .Version}}
category: misconfig
keywords: "{{ .Category }}"

breadcrumbs: 
  - name: Kubernetes
    path: /misconfig/kubernetes
  - name: Benchmarks - {{ .NiceVersion }}
    path: /misconfig/kubernetes/{{ .Version}}
  - name: {{ .ParentTitle }}
    path: /misconfig/kubernetes/{{ .Version}}/{{ .Version}}-{{ .ParentID}}


avd_page_type: avd_page

---

### {{ .ID }} {{ .ShortName }}
{{ range .Checks }}
#### {{ .ID }} {{ .Text}}

##### Recommended Action
{{ .Remediation }}
<br />

{{ end }}
`
