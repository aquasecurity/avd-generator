package menu

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/aquasecurity/avd-generator/util"
)

var headingMap = map[string]string{
	"iac":       "Misconfiguration",
	"appshield": "Misconfiguration",
}

type BreadCrumb struct {
	Name string
	Url  string
}

type menuNode struct {
	id           string
	name         string
	parentID     string
	remediations []string
	contentDir   string
	breadcrumbs  []BreadCrumb
	topLevel     bool
	icon         string
}

type menu struct {
	rootMenu   string
	contentDir string
	nodes      map[string]menuNode
}

func New(rootMenu, contentDir string) *menu {
	return &menu{
		rootMenu:   rootMenu,
		contentDir: contentDir,
		nodes:      make(map[string]menuNode),
	}
}

func (m *menu) AddNode(id, name, contentDir string, parentID string, remediations []string, categories []BreadCrumb, icon string, topLevel bool) {
	id = strings.ToLower(strings.ReplaceAll(id, " ", "-"))
	key := fmt.Sprintf("%s/%s", parentID, id)
	var workingNode menuNode
	if node, ok := m.nodes[key]; !ok {
		workingNode = menuNode{
			id:           id,
			name:         util.Nicify(name),
			parentID:     parentID,
			breadcrumbs:  make([]BreadCrumb, 0),
			contentDir:   contentDir,
			remediations: make([]string, 0),
			icon:         icon,
			topLevel:     topLevel,
		}
	} else {
		workingNode = node
	}
	workingNode.addRemediations(remediations)
	workingNode.addCategories(categories)

	m.nodes[key] = workingNode
}

func (m *menu) topLevel() []menuNode {
	var topLevelNodes []menuNode

	for _, node := range m.nodes {
		if node.parentID == "" {
			topLevelNodes = append(topLevelNodes, node)
		}
	}

	sort.Slice(topLevelNodes, func(i, j int) bool {
		return topLevelNodes[i].name < topLevelNodes[j].name
	})

	return topLevelNodes
}

func (m *menu) branches() []menuNode {
	var branches []menuNode

	for _, node := range m.nodes {
		if node.parentID != "" {
			branches = append(branches, node)
		}
	}
	return branches
}

func (m *menu) Generate() error {

	if err := m.generateTopLevelFile(); err != nil {
		return err
	}

	return m.generateBranchFiles()

}

func (m *menu) generateBranchFiles() error {
	for _, branch := range m.branches() {
		branchFilePath := filepath.Join(branch.contentDir, branch.id, "_index.md")
		if err := os.MkdirAll(filepath.Dir(branchFilePath), 0755); err != nil {
			return err
		}
		branchFile, err := os.Create(branchFilePath)
		if err != nil {
			return err
		}

		aliasID := strings.ReplaceAll(branch.id, "-", "")

		pageType := ""
		if branch.topLevel {
			pageType = "toplevel_page"
		}

		aliases := []string{
			fmt.Sprintf("cspm/%s/%s", branch.parentID, branch.id),
		}
		if branch.id != aliasID {
			aliases = append(aliases, fmt.Sprintf("cspm/%s/%s", branch.parentID, aliasID))
			aliases = append(aliases, fmt.Sprintf("misconfig/%s/%s", branch.parentID, aliasID))
		}

		t := template.Must(template.New("service").Parse(branchTemplate))
		if err := t.Execute(branchFile, map[string]interface{}{
			"RootMenu":     m.rootMenu,
			"Categories":   branch.breadcrumbs,
			"ParentID":     branch.parentID,
			"BranchID":     branch.id,
			"Name":         branch.name,
			"Remediations": branch.remediations,
			"Icon":         branch.icon,
			"Heading":      headingMap[branch.parentID],
			"PageType":     pageType,
			"AliasIDs":     aliases,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (m *menu) generateTopLevelFile() error {

	for _, topLevel := range m.topLevel() {
		providerFilePath := filepath.Join(topLevel.contentDir, topLevel.id, "_index.md")
		if err := os.MkdirAll(filepath.Dir(providerFilePath), 0755); err != nil {
			return err
		}
		providerFile, err := os.Create(providerFilePath)
		if err != nil {
			return err
		}

		pageType := ""
		if topLevel.topLevel {
			pageType = "toplevel_page"
		}

		t := template.Must(template.New("provider").Parse(topLevelTemplate))
		if err := t.Execute(providerFile, map[string]interface{}{
			"RootMenu":     m.rootMenu,
			"GroupID":      topLevel.id,
			"Categories":   topLevel.breadcrumbs,
			"Name":         topLevel.name,
			"Remediations": topLevel.remediations,
			"Icon":         topLevel.icon,
			"Heading":      headingMap[topLevel.icon],
			"PageType":     pageType,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (n *menuNode) addCategories(categories []BreadCrumb) {
	for _, newCategory := range categories {
		var found bool
		for _, category := range n.breadcrumbs {
			if newCategory.Name == category.Name {
				found = true
				break
			}
		}
		if !found {
			n.breadcrumbs = append(n.breadcrumbs, newCategory)
		}
	}
}

func (n *menuNode) addRemediations(remediations []string) {
	for _, newRemediation := range remediations {
		var found bool
		for _, remediation := range n.remediations {
			if newRemediation == remediation {
				found = true
				break
			}
		}
		if !found {
			n.remediations = append(n.remediations, newRemediation)
		}
	}
}

const topLevelTemplate = `---
title: {{ .Name }}
heading: {{ .Name }}
{{ if eq .RootMenu "misconfig" }}
aliases: [
	"/cspm/{{.GroupID}}"
]
{{ end }}
draft: false
icon: {{ .Icon }}
category: {{ .RootMenu}}

remediations:
{{ range .Remediations }}  - {{ .}}
{{ end }}

breadcrumbs:
{{ range .Categories }}  - name: {{ .Name }}
    url: {{ .Url }}
{{ end }}

avd_page_type: {{ .PageType }}
---

`

const branchTemplate = `---
title: {{ .Name }}
heading: {{ .Heading }}
{{ if eq .RootMenu "misconfig" }}
aliases: [
	{{range $i, $e := .AliasIDs}}{{if $i}},
	{{end}}"/{{ $e }}"{{end}}
]
{{ end }}
icon: {{ .Icon }}
draft: false
category: {{ .RootMenu}}


remediations:
{{ range .Remediations }}  - {{ .}}
{{ end }}

breadcrumbs:
{{ range .Categories }}  - name: {{ .Name }}
    path: {{ .Url }}
{{ end }}

avd_page_type: {{ .PageType }}
---

`
