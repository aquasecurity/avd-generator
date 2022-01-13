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
	AVDID        string
	DisplayName  string
	Summary      string
	Remediations []string
}

type Providers []*ProviderIndex

type ProviderIndex struct {
	Provider     provider.Provider
	Remediations []string
	Services     Services
}

type Services []*ServiceIndex

type ServiceIndex struct {
	ID            string
	Name          string
	Remediations  []string
	RuleSummaries RuleSummaries
}

type RuleSummaries []RuleSummary

func (p *ProviderIndex) Equals(p2 ProviderIndex) bool {

	return true
}

func (p *Providers) Get(prov *ProviderIndex) *ProviderIndex {
	for _, provider := range *p {
		if provider.Provider.ConstName() == prov.Provider.ConstName() {
			return provider
		}
	}
	return nil
}

func (p *Providers) Add(i *ProviderIndex) *ProviderIndex {
	if existing := p.Get(i); existing != nil {
		return existing
	}
	*p = append(*p, i)
	return i
}

func (s *Services) Get(svc *ServiceIndex) *ServiceIndex {
	for _, service := range *s {
		if service.Name == svc.Name {
			return service
		}
	}
	return nil
}

func (s *Services) Add(svc *ServiceIndex) *ServiceIndex {
	if existing := s.Get(svc); existing != nil {
		return existing
	}
	*s = append(*s, svc)
	return svc
}

func generateDefsecPages(remidiationDir, contentDir string, _ Clock) {

	registeredRules := rules.GetRegistered()
	var providers Providers

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

		if err := generateDefsecCheckPage(r, remediations, contentDir, docsFile); err != nil {
			log.Printf("an error occurred writing the page for %s. %v", r.Rule().AVDID, err)
		}

		remediationNames := make([]string, 0, len(remediations))
		for k := range remediations {
			remediationNames = append(remediationNames, strings.ToLower(k))
		}

		provider := providers.Add(&ProviderIndex{
			Provider:     r.Rule().Provider,
			Remediations: remediationNames,
		})

		service := provider.Services.Add(&ServiceIndex{
			ID:           r.Rule().Service,
			Name:         r.Rule().ServiceDisplayName(),
			Remediations: remediationNames,
		})

		service.RuleSummaries = append(service.RuleSummaries, RuleSummary{
			AVDID:        r.Rule().AVDID,
			DisplayName:  r.Rule().ShortCodeDisplayName(),
			Summary:      r.Rule().Summary,
			Remediations: remediationNames,
		})
	}

	if err := generateDefsecIndexPages(providers, contentDir); err != nil {
		log.Printf("an error occurred creating the provider file. %v", err)
	}
}

func generateDefsecIndexPages(providers Providers, contentDir string) error {

	for _, provider := range providers {
		providerFilePath := filepath.Join(contentDir, strings.ToLower(provider.Provider.ConstName()), "_index.md")
		providerFile, err := os.Create(providerFilePath)
		if err != nil {
			return err
		}

		t := template.Must(template.New("provider").Parse(providerTemplate))
		if err := t.Execute(providerFile, map[string]interface{}{
			"ProviderID":   strings.ToLower(provider.Provider.ConstName()),
			"DisplayName":  provider.Provider.DisplayName(),
			"Services":     provider.Services,
			"Remediations": provider.Remediations,
		}); err != nil {
			return err
		}

		for _, service := range provider.Services {
			serviceFilePath := filepath.Join(contentDir, strings.ToLower(provider.Provider.ConstName()), strings.ToLower(service.Name), "_index.md")
			serviceFile, err := os.Create(serviceFilePath)
			if err != nil {
				return err
			}

			t := template.Must(template.New("service").Parse(serviceTemplate))
			if err := t.Execute(serviceFile, map[string]interface{}{
				"ProviderID":   strings.ToLower(provider.Provider.ConstName()),
				"ServiceID":    service.ID,
				"Name":         service.Name,
				"Summaries":    service.RuleSummaries,
				"Remediations": service.Remediations,
			}); err != nil {
				return err
			}
		}

	}
	return nil
}

func generateDefsecCheckPage(rule rules.RegisteredRule, remediations map[string]string, contentDir string, docsFile string) error {

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

	post := DefsecPost{
		AVDID:        rule.Rule().AVDID,
		ShortName:    rule.Rule().ShortCodeDisplayName(),
		Provider:     strings.ToLower(rule.Rule().Provider.ConstName()),
		Service:      strings.ToLower(rule.Rule().Service),
		ServiceName:  rule.Rule().ServiceDisplayName(),
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

avd_page_type: defsec_page

remediations:
{{ range .Remediations }}  - {{ .}}
{{ end }}

menu:
  defsec:
    identifier: {{.AVDID}}
    name: {{.ShortName}}
    parent: {{.Provider}}-{{.Service}}
---

[{{.Provider}}](../../) | [{{.ServiceName}}](../)

{{.Body}}

`

const providerTemplate = `---
title: {{ .DisplayName }}
draft: false
avd_page_type: defsec_page
remediations:
{{ range .Remediations }}  - {{ .}}
{{ end }}

menu:
  defsec:
    identifier: {{.ProviderID}}
    name: {{.DisplayName}}
---
Select a service
`

const serviceTemplate = `---
title: {{ .Name }}
draft: false
avd_page_type: defsec_page
remediations:
{{ range .Remediations }}  - {{ .}}
{{ end }}

menu:
  defsec:
    identifier: {{.ProviderID}}-{{.ServiceID}}
    name: {{.Name}}
    parent: {{.ProviderID}}
---

Select a rule

`
