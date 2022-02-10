package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/aquasecurity/avd-generator/docGen/menu"
	"github.com/aquasecurity/avd-generator/docGen/util"
	_ "github.com/aquasecurity/defsec/loader"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
)

type DefsecPost struct {
	AVDID        string
	ShortName    string
	Severity     string
	Provider     string
	ProviderName string
	Service      string
	ServiceName  string
	Body         string
	ParentID     string
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

	for _, r := range registeredRules {

		avdId := r.Rule().AVDID
		topLevelID := strings.ToLower(r.Rule().Provider.ConstName())
		branchID := r.Rule().Service
		branchID = util.RemapCategory(branchID)

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

		if err := generateDefsecCheckPage(r, remediations, contentDir, docsFile, branchID); err != nil {
			log.Printf("an error occurred writing the page for %s. %v", r.Rule().AVDID, err)
		}

		remediationNames := make([]string, 0, len(remediations))
		for k := range remediations {
			remediationNames = append(remediationNames, strings.ReplaceAll(strings.ToLower(k), " ", "_"))
		}

		misConfigurationMenu.AddNode(topLevelID, r.Rule().Provider.DisplayName(), contentDir, "", remediationNames,
			[]menu.MenuCategory{
				{"Misconfiguration", "/misconfig"},
			}, "iac")
		misConfigurationMenu.AddNode(branchID, branchID, filepath.Join(contentDir, topLevelID), topLevelID, remediationNames,
			[]menu.MenuCategory{
				{"Misconfiguration", "/misconfig"},
				{r.Rule().Provider.DisplayName(), "/misconfig/" + topLevelID},
			}, "aqua")
	}

	// if err := menu.NewTopLevelMenu("Infrastructure as Code Misconfigurations", "avd_list", "content/misconfig/infra/_index.md").
	// 	WithHeading("Infrastructure as Code").
	// 	WithIcon("iac").
	// 	WithCategory("misconfig").
	// 	WithMenu("misconfig").
	// 	Generate(); err != nil {
	// 	panic(err)
	// }
}

func generateDefsecCheckPage(rule rules.RegisteredRule, remediations map[string]string, contentDir string, docsFile string, menuParent string) error {

	providerPath := strings.ToLower(rule.Rule().Provider.ConstName())
	servicePath := strings.ToLower(menuParent)
	ruleIDPath := strings.ToLower(rule.Rule().AVDID)

	outputFilePath := strings.ToLower(strings.ReplaceAll(filepath.Join(contentDir, providerPath, servicePath, fmt.Sprintf("%s.md", ruleIDPath)), " ", "-"))
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
		"remediationActions": func() string { return createRemediation(remediations) },
	}

	var documentBody bytes.Buffer
	t := template.Must(template.New("bodyContent").Funcs(funcMap).Parse(string(docsContent)))
	if err := t.Execute(&documentBody, nil); err != nil {
		return err
	}

	remediationKeys := make([]string, 0, len(remediations))
	for k := range remediations {
		remediationKeys = append(remediationKeys, strings.ReplaceAll(strings.ToLower(k), " ", "_"))
	}

	post := DefsecPost{
		AVDID:        rule.Rule().AVDID,
		ShortName:    rule.Rule().ShortCodeDisplayName(),
		Provider:     strings.ToLower(rule.Rule().Provider.ConstName()),
		ProviderName: rule.Rule().Provider.DisplayName(),
		ServiceName:  rule.Rule().ServiceDisplayName(),
		Body:         documentBody.String(),
		Severity:     strings.ToLower(string(rule.Rule().Severity)),
		ParentID:     strings.ReplaceAll(strings.ToLower(menuParent), " ", "-"),
		Remediations: remediationKeys,
	}

	t = template.Must(template.New("defsecPost").Parse(defsecTemplate))
	return t.Execute(outputFile, post)
}

func createRemediation(remediations map[string]string) string {
	if len(remediations) == 0 {
		return ""
	}
	body := `### Recommended Actions

Follow the appropriate remediation steps below to resolve the issue.

{{< tabs groupId="remediation" >}}`
	keys := make([]string, 0, len(remediations))
	for k := range remediations {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		body += fmt.Sprintf(`{{%% tab name="%s" %%}}`, k)
		body += remediations[k]
		body += "{{% /tab %}}"
	}
	body += "{{< /tabs >}}"
	return body
}

const defsecTemplate = `---
title: "{{.ShortName}}"
parent: {{ .ParentID}}
heading: Infrastructure as Code
icon: iac
category: misconfig
sidebar_category: misconfig
draft: false
shortName: {{.ShortName}}
severity: "{{.Severity}}"

avd_page_type: defsec_page

remediations:
{{ range .Remediations }}  - {{ .}}
{{ end }}

menu:
  misconfig:
    identifier: {{.ParentID}}/{{.AVDID}}
    name: {{.ShortName}}
    parent: {{.Provider}}/{{.ParentID}}
---

Misconfiguration > [{{.ProviderName}}](../../) > [{{.ServiceName}}](../) > {{.AVDID}}

## {{ .AVDID }}

{{.Body}}

`
