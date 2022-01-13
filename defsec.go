package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	_ "github.com/aquasecurity/defsec/loader"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
)

type DefsecPost struct {
	AVDID        string
	ShortName    string
	Severity     string
	Provider     string
	Service      string
	ServiceName  string
	Body         string
	Remediations []string
}

type RuleSummary struct {
	AVID         string
	DisplayName  string
	Summary      string
	Remediations []string
}

type ProviderIndex struct {
	Provider     provider.Provider
	Remediations string
}

type ServiceIndex struct {
	Name          string
	Remediations  string
	RuleSummaries []RuleSummary
}

func (p *ProviderIndex) Equals(p2 ProviderIndex) bool {

	return true
}

func generateDefsecPages(remidiationDir, contentDir string, clock Clock) {

	registeredRules := rules.GetRegistered()
	providers := make(map[ProviderIndex][]*ServiceIndex)

	for _, r := range registeredRules {

		avdId := r.Rule().AVDID
		log.Printf("Getting remediation markdown for %s", avdId)
		remediationDir := filepath.Join(remidiationDir, strings.ToLower(r.Rule().Provider.ConstName()), strings.ReplaceAll(r.Rule().Service, "-", ""), avdId)

		remediations := make(map[string]string)
		docsFile := filepath.Join(remediationDir, "docs.md")

		if err := filepath.Walk(remediationDir, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() || filepath.Ext(path) != ".md" || path == docsFile {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			remediationName := strings.ReplaceAll(strings.TrimSuffix(info.Name(), filepath.Ext(info.Name())), "_", " ")
			remediations[remediationName] = string(content)

			return nil
		}); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		if err := generatePage(r, remediations, contentDir, docsFile); err != nil {
			log.Printf("an error occurred writing the page for %s. %v", r.Rule().AVDID, err)
		}

		p := ProviderIndex{
			Provider: r.Rule().Provider,
		}

		if _, exists := providers[p]; !exists {
			providers[p] = []*ServiceIndex{}
		}
		services := providers[p]

		var serviceIndex *ServiceIndex
		for _, s := range services {
			if s.Name == r.Rule().Service {
				serviceIndex = s
				break
			}
		}

		if serviceIndex == nil {
			serviceIndex = &ServiceIndex{
				Name: r.Rule().Service,
			}
			services = append(services, serviceIndex)
		}

		remediationNames := make([]string, 0, len(remediations))
		for k := range remediations {
			remediationNames = append(remediationNames, k)
		}

		serviceIndex.RuleSummaries = append(serviceIndex.RuleSummaries, RuleSummary{
			AVID:         r.Rule().AVDID,
			DisplayName:  r.Rule().ShortCode,
			Summary:      r.Rule().Summary,
			Remediations: remediationNames,
		})

		providers[p] = services
	}

	if err := generateIndexPages(providers, contentDir); err != nil {
		log.Printf("an error occurred creating the provider file. %v", err)
	}
}

func generateIndexPages(providers map[ProviderIndex][]*ServiceIndex, contentDir string) error {

	for provider, services := range providers {
		providerFilePath := filepath.Join(contentDir, strings.ToLower(provider.Provider.ConstName()), "_index_.md")
		providerFile, err := os.Create(providerFilePath)
		if err != nil {
			return err
		}

		serviceNames := make([]string, 0, len(services))
		for _, k := range services {
			serviceNames = append(serviceNames, k.Name)
		}

		t := template.Must(template.New("provider").Parse(providerTemplate))
		if err := t.Execute(providerFile, map[string]interface{}{
			"ProviderID":   provider.Provider.ConstName(),
			"DisplayName":  provider.Provider.DisplayName(),
			"ServiceNames": serviceNames,
			"Remediations": strings.Split(provider.Remediations, " "),
		}); err != nil {
			return err
		}

		for _, service := range services {
			serviceFilePath := filepath.Join(contentDir, strings.ToLower(provider.Provider.ConstName()), strings.ToLower(service.Name), "_index_.md")
			serviceFile, err := os.Create(serviceFilePath)
			if err != nil {
				return err
			}

			t := template.Must(template.New("service").Parse(serviceTemplate))
			if err := t.Execute(serviceFile, map[string]interface{}{
				"ProviderID":   strings.ToLower(provider.Provider.ConstName()),
				"ServiceID":    service.Name,
				"Name":         strings.Title(strings.ReplaceAll(service.Name, "-", " ")),
				"Summaries":    service.RuleSummaries,
				"Remediations": strings.Split(service.Remediations, " "),
			}); err != nil {
				return err
			}
		}

	}
	return nil
}

func generatePage(rule rules.RegisteredRule, remediations map[string]string, contentDir string, docsFile string) error {

	providerPath := strings.ToLower(rule.Rule().Provider.ConstName())
	servicePath := strings.ToLower(rule.Rule().Service)
	ruleIDPath := strings.ToLower(rule.Rule().AVDID)

	outputFilePath := filepath.Join(contentDir, providerPath, servicePath, fmt.Sprintf("%s.md", ruleIDPath))
	if err := os.MkdirAll(filepath.Dir(outputFilePath), 0777); err != nil {
		return err
	}
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}

	docsContent, err := os.ReadFile(docsFile)
	if err != nil {
		return err
	}

	var funcMap = template.FuncMap{
		"severity":           func(severity string) string { return severity },
		"remediationActions": func() string { return createRemdiation(remediations) },
	}

	var documentBody bytes.Buffer
	t := template.Must(template.New("bodyContent").Funcs(funcMap).Parse(string(docsContent)))
	if err := t.Execute(&documentBody, nil); err != nil {
		return err
	}

	remediationKeys := make([]string, 0, len(remediations))
	for k := range remediations {
		remediationKeys = append(remediationKeys, strings.ToLower(k))
	}

	shortName := strings.Title(strings.ReplaceAll(rule.Rule().ShortCode, "-", " "))
	post := DefsecPost{
		AVDID:        rule.Rule().AVDID,
		ShortName:    shortName,
		Provider:     strings.ToLower(rule.Rule().Provider.ConstName()),
		Service:      strings.ToLower(rule.Rule().Service),
		ServiceName:  strings.Title(strings.ReplaceAll(rule.Rule().Service, "-", " ")),
		Body:         documentBody.String(),
		Severity:     strings.ToLower(string(rule.Rule().Severity)),
		Remediations: remediationKeys,
	}

	t = template.Must(template.New("defsecPost").Parse(defsecTemplate))
	return t.Execute(outputFile, post)
}

func createRemdiation(remediations map[string]string) string {
	if len(remediations) == 0 {
		return ""
	}
	body := `### Recommended Actions

Follow the appropriate remediation steps below to resolve the issue.

{{< tabs groupId="remediation" >}}`
	for remediationType, content := range remediations {
		body += fmt.Sprintf(`{{%% tab name="%s" %%}}`, remediationType)
		body += content
		body += "{{% /tab %}}"
	}
	body += "{{< /tabs >}}"
	return body
}

const defsecTemplate = `---
title: "{{.AVDID}}"
severity: "{{.Severity}}"
draft: false
provider: {{.Provider}}
service: {{.ServiceName}}
remediations:
{{ range .Remediations }}  - {{ .}}
{{ end }}

menu:
  defsec:
    identifier: {{.AVDID}}
    name: {{.ShortName}}
    parent: {{.Provider}}-{{.Service}}
    remediations:
{{ range .Remediations }}    - {{ .}}
{{ end }}

avd_page_type: defsec_page
---

{{.Body}}

`

const providerTemplate = `---
menu:
  defsec:
    identifier: {{.ProviderID}}
    name: {{.DisplayName}}
remediations:
---
`

const serviceTemplate = `---
menu:
  defsec:
    identifier: {{.ProviderID}}-{{.ServiceID}}
    name: {{.Name}}
    parent: {{.ProviderID}}
remediations:
---
`
