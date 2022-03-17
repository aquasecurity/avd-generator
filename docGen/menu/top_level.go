package menu

import (
	"os"
	"text/template"
)

type Tile struct {
	Heading string
	Summary string
	Icon    string
	URL     string
}

type TopLevelMenu struct {
	Name        string
	Heading     string
	Icon        string
	Category    string
	BreadCrumbs []string
	Menu        string
	MenuID      string
	MenuParent  string
	Layout      string
	Path        string
	Tiles       []Tile
}

func NewTopLevelMenu(name, layout, path string) *TopLevelMenu {
	return &TopLevelMenu{
		Name:   name,
		Layout: layout,
		Path:   path,
	}
}

func (m *TopLevelMenu) WithHeading(heading string) *TopLevelMenu {
	m.Heading = heading
	return m
}

func (m *TopLevelMenu) WithIcon(icon string) *TopLevelMenu {
	m.Icon = icon
	return m
}

func (m *TopLevelMenu) WithMenu(menu string) *TopLevelMenu {
	m.Menu = menu
	return m
}

func (m *TopLevelMenu) WithMenuID(id string) *TopLevelMenu {
	m.MenuID = id
	return m
}

func (m *TopLevelMenu) WithMenuParent(parentMenu string) *TopLevelMenu {
	m.MenuParent = parentMenu
	return m
}

func (m *TopLevelMenu) WithCategory(category string) *TopLevelMenu {
	m.Category = category
	return m
}

func (m *TopLevelMenu) WithTile(tile Tile) *TopLevelMenu {
	if m.Tiles == nil {
		m.Tiles = make([]Tile, 0)
	}
	m.Tiles = append(m.Tiles, tile)
	return m
}

func (m *TopLevelMenu) Generate() error {

	categoryFile, err := os.Create(m.Path)
	if err != nil {
		return err
	}

	t := template.Must(template.New("service").Parse(categoryTemplate))
	if err := t.Execute(categoryFile, m); err != nil {
		return err
	}
	return nil
}

const categoryTemplate = `---
title: {{ .Name }}
heading: {{ .Heading }}
{{ if eq .Category "misconfig" }}
aliases: [
	"/cspm"
]
{{ end }}
icon: {{ .Icon }}
category: {{ .Category }}
draft: false

breadcrumbs:
{{ range .BreadCrumbs }}  - name: {{ .Name }}
    path: {{ .Url }}
{{ end }}

avd_page_type: {{ .Layout }}

{{ if .Tiles }}
tiles:
{{ range .Tiles }}  - heading: {{ .Heading }}
    url: {{ .URL }}
    icon: {{ .Icon }}
    summary: {{ .Summary }}
{{ end }}


{{ end }}
---

This is the top level page for Misconfiguration

`
