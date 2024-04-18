package main

import (
	"encoding/json"
	"fmt"
	"golang.org/x/exp/slices"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/leekchan/gtf"
	"github.com/umisama/go-cpe"

	"github.com/valyala/fastjson"

	"github.com/aquasecurity/avd-generator/menu"
	"github.com/aquasecurity/vuln-list-update/redhat"
	"github.com/aquasecurity/vuln-list-update/ubuntu"
)

var (
	CVEMap map[string]map[string]ReservedCVEInfo
)

type ReservedPage struct {
	ID     string
	Date   string
	CVEMap map[string]ReservedCVEInfo
}

type ReservedCVEInfo struct {
	Description          string
	Severity             string
	Mitigation           string // Redhat publishes mitigation
	AffectedSoftwareList []AffectedSoftware
}

type Dates struct {
	Published string
	Modified  string
}

type CVSS struct {
	V2Vector string
	V2Score  float64
	V3Vector string
	V3Score  float64
}

type RedHatCVSSInfo struct {
	CVSS
	Severity string
}

type UbuntuCVSSInfo struct {
	Severity string
}

type AffectedSoftware struct {
	Name         string
	Vendor       string
	StartVersion string
	EndVersion   string
}

type Vulnerability struct {
	ID               string
	CWEID            string
	CWEInfo          WeaknessType
	Description      string
	References       []string
	CVSS             CVSS
	NVDSeverityV2    string
	NVDSeverityV3    string
	RedHatCVSSInfo   RedHatCVSSInfo
	UbuntuCVSSInfo   UbuntuCVSSInfo
	Dates            Dates
	AffectedSoftware []AffectedSoftware
}

type VulnerabilityPost struct {
	Layout        string
	Title         string
	ShortName     string
	By            string
	Date          string
	Vulnerability Vulnerability
}

func generateVulnPages() {
	postsDir := "content/nvd"

	var wg sync.WaitGroup
	for _, year := range Years {
		year := year
		wg.Add(1)

		log.Printf("generating vuln year: %s\n", year)
		nvdDir := fmt.Sprintf("vuln-list-nvd/api/%s/", year)
		cweDir := "vuln-list/cwe"

		go func(year string) {
			defer wg.Done()
			generateVulnerabilityPages(nvdDir, cweDir, postsDir, year)
		}(year)
	}
	wg.Wait()

	indexFile := filepath.Join(postsDir, "_index.md")
	vulnIndex := menu.NewTopLevelMenu("Vulnerabilties", "toplevel_page", indexFile).
		WithHeading("Vulnerabilties").
		WithIcon("aqua").
		WithCategory("vulnerabilities").
		WithMenu("none")

	years := &Years

	sort.Sort(sort.Reverse(sort.StringSlice(*years)))

	for _, year := range Years {
		vulnIndex.WithTile(menu.Tile{
			Heading: year,
			Icon:    "cve",
			Summary: fmt.Sprintf("CVE's for %s", year),
			URL:     fmt.Sprintf("/nvd/%s/", year),
		},
		)
	}
	if err := vulnIndex.Generate(); err != nil {
		fail(err)
	}
}

func generateVulnerabilityPages(nvdDir, cweDir, postsDir, year string) {

	postsDir = fmt.Sprintf("%s/%s", postsDir, year)
	if err := os.MkdirAll(postsDir, 0755); err != nil {
		fail(err)
	}

	files, err := getAllFiles(nvdDir)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		bp, err := parseVulnerabilityJSONFile(file)
		if err != nil {
			log.Printf("unable to parse file: %s, err: %s, skipping...\n", file, err)
			continue
		}

		_ = AddCWEInformation(&bp, cweDir)

		for _, vendor := range []string{"redhat", "ubuntu"} {
			_ = AddVendorInformation(&bp, vendor, strings.ReplaceAll(nvdDir, "nvd", vendor))
		}

		// check if file exists first, if does then open, if not create
		f, err := os.OpenFile(filepath.Join(postsDir, fmt.Sprintf("%s.md", bp.Title)), os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			log.Printf("unable to create file: %s for markdown, err: %s, skipping...\n", file, err)
			continue
		}

		customContent := GetCustomContentFromMarkdown(f.Name())
		if customContent != "" { // truncate file if custom data was found
			_ = f.Truncate(0)
			_, _ = f.Seek(0, 0)
		}
		if err := VulnerabilityPostToMarkdown(bp, f, customContent); err != nil {
			log.Printf("unable to write file: %s as markdown, err: %s, skipping...\n", file, err)
			continue
		}
		_ = f.Close()
	}

	indexFile := filepath.Join(postsDir, "_index.md")
	if err := menu.NewTopLevelMenu(year, "avd_list", indexFile).
		WithHeading("Vulnerabilties").
		WithIcon("aqua").
		WithCategory("vulnerabilities").
		WithMenu(year).
		WithMenuID(year).
		WithMenuParent("vulnerabilities").
		Generate(); err != nil {
		fail(err)
	}
}

func generateReservedPages(year string, clock Clock, inputDir string, postsDir string) {
	CVEMap = map[string]map[string]ReservedCVEInfo{}
	nvdDir := fmt.Sprintf("%s/nvd/%s", inputDir, year)
	files, _ := getAllFiles(nvdDir)
	for _, file := range files {
		CVEMap[strings.ReplaceAll(file, ".json", "")] = map[string]ReservedCVEInfo{
			"nvd": {},
		}
	}

	for _, vendor := range []string{"redhat", "ubuntu"} {
		vendorDir := fmt.Sprintf("%s/%s/%s", inputDir, vendor, year)
		files, _ := getAllFiles(vendorDir)
		for _, file := range files {
			fKey := strings.ReplaceAll(filepath.Base(file), ".json", "")
			if !existsInCVEMap(CVEMap, strings.ReplaceAll(strings.ReplaceAll(file, ".json", ""), vendor, "nvd")) {
				if _, ok := CVEMap[fKey]; !ok {
					CVEMap[fKey] = make(map[string]ReservedCVEInfo)
				}
				addReservedCVE(vendorDir, CVEMap, vendor, fKey)
			}
		}
	}

	// cleanup NVD entries
	for file, vendorsMap := range CVEMap {
		for vendor := range vendorsMap {
			if vendor == "nvd" {
				delete(CVEMap, file)
			}
		}
	}

	for file, vendorsMap := range CVEMap {
		f, err := os.Create(filepath.Join(postsDir, fmt.Sprintf("%s.md", filepath.Base(file))))
		if err != nil {
			log.Printf("unable to create file: %s for markdown, err: %s, skipping...\n", file, err)
			continue
		}
		if err = ReservedPostToMarkdown(ReservedPage{
			ID:     filepath.Base(file),
			Date:   clock.Now(),
			CVEMap: vendorsMap,
		}, f); err != nil {
			log.Println("unable to create reserved post markdown, err: ", err)
			continue
		}
	}
}

func existsInCVEMap(inputMap map[string]map[string]ReservedCVEInfo, target string) bool {
	for k := range inputMap {
		if target == k {
			return true
		}
	}
	return false
}

func addReservedCVE(vendorDir string, cveMap map[string]map[string]ReservedCVEInfo, vendor string, fKey string) {
	b, _ := ioutil.ReadFile(fmt.Sprintf("%s/%s.json", vendorDir, fKey))

	switch vendor {
	case "ubuntu":
		var ua ubuntu.Vulnerability
		_ = json.Unmarshal(b, &ua)
		cveMap[fKey][vendor] = ReservedCVEInfo{
			Description: ua.Description,
			Severity:    ua.Priority,
		}
		for pkg, info := range ua.Patches {
			for release, status := range info {
				if status.Status == "released" || status.Status == "needed" || status.Status == "ignored" || status.Status == "needs-triage" {
					rp := cveMap[fKey][vendor]
					as := AffectedSoftware{
						Name:   string(pkg),
						Vendor: fmt.Sprintf("%s/%s", vendor, release),
					}
					if status.Status == "needs-triage" {
						as.StartVersion = "TBD"
						as.EndVersion = "TBD"
					} else {
						as.StartVersion = status.Note
						as.EndVersion = status.Note
					}
					rp.AffectedSoftwareList = append(rp.AffectedSoftwareList, as)
					cveMap[fKey][vendor] = rp
				}
			}
		}
	case "redhat":
		rh := &redhat.RedhatCVEJSON{}
		_ = json.Unmarshal(b, &rh)
		cveMap[fKey][vendor] = ReservedCVEInfo{
			Description: rh.Bugzilla.Description,
			Severity:    rh.ThreatSeverity,
			Mitigation:  rh.Mitigation,
		}
		for _, release := range rh.AffectedRelease {
			rp := cveMap[fKey][vendor]
			rp.AffectedSoftwareList = append(rp.AffectedSoftwareList, AffectedSoftware{
				Name:         release.ProductName,
				Vendor:       "RedHat",
				StartVersion: release.Package,
				EndVersion:   release.Package,
			})
			cveMap[fKey][vendor] = rp
		}
	}
}

func getAllMapKeys(a interface{}) []string {
	keys := reflect.ValueOf(a).MapKeys()
	strkeys := make([]string, len(keys))
	for i := 0; i < len(keys); i++ {
		strkeys[i] = keys[i].String()
	}
	return strkeys
}

func AddVendorInformation(bp *VulnerabilityPost, vendor string, vendorDir string) error {
	switch vendor {
	case "redhat":
		b, err := ioutil.ReadFile(filepath.Join(vendorDir, fmt.Sprintf("%s.json", bp.Vulnerability.ID)))
		if err != nil {
			return err
		}
		var p fastjson.Parser
		v, err := p.ParseBytes(b)
		if err != nil {
			return err
		}
		bp.Vulnerability.RedHatCVSSInfo.Severity = string(v.GetStringBytes("threat_severity"))
		bp.Vulnerability.RedHatCVSSInfo.V2Vector = string(v.GetStringBytes("cvss", "cvss_scoring_vector"))
		bp.Vulnerability.RedHatCVSSInfo.V2Score, _ = strconv.ParseFloat(string(v.GetStringBytes("cvss", "cvss_base_score")), 64)
		bp.Vulnerability.RedHatCVSSInfo.V3Vector = string(v.GetStringBytes("cvss3", "cvss3_scoring_vector"))
		bp.Vulnerability.RedHatCVSSInfo.V3Score, _ = strconv.ParseFloat(string(v.GetStringBytes("cvss3", "cvss3_base_score")), 64)

		affectedReleases := v.GetArray("affected_release")
		for _, ar := range affectedReleases {
			bp.Vulnerability.AffectedSoftware = append(bp.Vulnerability.AffectedSoftware, AffectedSoftware{
				Name:         string(ar.GetStringBytes("product_name")),
				Vendor:       "RedHat",
				StartVersion: string(ar.GetStringBytes("package")),
				EndVersion:   "*",
			})
		}

	case "ubuntu":
		b, err := ioutil.ReadFile(filepath.Join(vendorDir, fmt.Sprintf("%s.json", bp.Vulnerability.ID)))
		if err != nil {
			return err
		}
		var p fastjson.Parser
		v, err := p.ParseBytes(b)
		if err != nil {
			return err
		}
		bp.Vulnerability.UbuntuCVSSInfo.Severity = string(v.GetStringBytes("Priority"))

		patchList := v.Get("Patches")
		var patches map[string]map[string]struct {
			Status string
			Note   string
		}

		// get all patches
		_ = json.Unmarshal([]byte(patchList.String()), &patches)

		// get all packages
		packages := getAllMapKeys(patches)
		sort.Slice(packages, func(i, j int) bool {
			return packages[i] < packages[j]
		})

		for _, p := range packages {
			dists := getAllMapKeys(patches[p])
			sort.Slice(dists, func(i, j int) bool {
				return dists[i] < dists[j]
			})

			for _, d := range dists {
				status := strings.ToLower(patches[p][d].Status)
				switch status {
				case "needed", "pending", "ignored", "released":
					bp.Vulnerability.AffectedSoftware = append(bp.Vulnerability.AffectedSoftware, AffectedSoftware{
						Name:         p,
						Vendor:       "Ubuntu",
						StartVersion: d,
						EndVersion:   "*",
					})
				}
			}
		}

	}
	return nil
}

func parseVulnerabilityJSONFile(fileName string) (VulnerabilityPost, error) {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return VulnerabilityPost{}, err
	}

	var vuln Vulnerability
	var p fastjson.Parser
	v, err := p.ParseBytes(b)
	if err != nil {
		return VulnerabilityPost{}, err
	}
	vuln.Description = strings.NewReplacer(`"`, ``, `\`, ``, `'`, ``).Replace(string(v.GetStringBytes("descriptions", "0", "value")))
	vuln.ID = string(v.GetStringBytes("id"))
	if cwe := string(v.GetStringBytes("weaknesses", "0", "description", "0", "value")); cwe != "NVD-CWE-noinfo" {
		vuln.CWEID = cwe
	}

	for _, metricV2 := range v.GetArray("metrics", "cvssMetricV2") {
		source := string(metricV2.GetStringBytes("source"))
		// Save only NVD metric
		if source == "nvd@nist.gov" {
			vuln.CVSS.V2Score = metricV2.GetFloat64("cvssData", "baseScore")
			vuln.CVSS.V2Vector = string(metricV2.GetStringBytes("cvssData", "vectorString"))
			vuln.NVDSeverityV2 = string(metricV2.GetStringBytes("baseSeverity"))
		}
	}

	// Save NVD metric from v3.1,
	// if it doesn't exist - save NVD metric from v3.0
	for _, metricV3 := range append(v.GetArray("metrics", "cvssMetricV31"), v.GetArray("metrics", "cvssMetricV30")...) {
		source := string(metricV3.GetStringBytes("source"))
		// Save only NVD metric
		if source == "nvd@nist.gov" {
			vuln.CVSS.V3Score = metricV3.GetFloat64("cvssData", "baseScore")
			vuln.CVSS.V3Vector = string(metricV3.GetStringBytes("cvssData", "vectorString"))
			vuln.NVDSeverityV3 = string(metricV3.GetStringBytes("cvssData", "baseSeverity"))
		}
	}

	publishedDate, _ := time.Parse("2006-01-02T15:04:05", string(v.GetStringBytes("published")))
	modifiedDate, _ := time.Parse("2006-01-02T15:04:05", string(v.GetStringBytes("lastModified")))
	vuln.Dates = Dates{
		Published: publishedDate.UTC().Format("2006-01-02 03:04:05 -0700"),
		Modified:  modifiedDate.UTC().Format("2006-01-02 03:04:05 -0700"),
	}

	var refs []string
	for _, r := range v.GetArray("references") {
		refs = append(refs, strings.ReplaceAll(r.Get("url").String(), `"`, ``))
	}
	vuln.References = refs

	affectedSoftwares := v.GetArray("configurations", "0", "nodes", "0", "cpeMatch") // TODO: This logic should be improved to iterate over list of lists
	for _, as := range affectedSoftwares {
		uri := string(as.GetStringBytes("criteria"))
		item, err := cpe.NewItemFromFormattedString(uri)
		if err != nil {
			continue
		}

		startVersion := detectVersion(string(as.GetStringBytes("versionStartIncluding")), string(as.GetStringBytes("versionStartExcluding")), item)
		endVersion := detectVersion(string(as.GetStringBytes("versionEndIncluding")), string(as.GetStringBytes("versionEndExcluding")), item)

		affectedSoftware := AffectedSoftware{
			Name:         item.Product().String(),
			Vendor:       item.Vendor().String(),
			StartVersion: startVersion,
			EndVersion:   endVersion,
		}

		// Avoid duplicates
		if !slices.Contains(vuln.AffectedSoftware, affectedSoftware) {
			vuln.AffectedSoftware = append(vuln.AffectedSoftware, affectedSoftware)
		}
	}

	return VulnerabilityPost{
		Layout:        "vulnerability",
		Title:         vuln.ID,
		By:            "NVD",
		Date:          publishedDate.UTC().Format("2006-01-02 03:04:05 -0700"),
		Vulnerability: vuln,
	}, nil
}

func detectVersion(includeVersion, excludeVersion string, item *cpe.Item) string {
	if includeVersion != "" {
		return includeVersion + " (including)"
	}

	if excludeVersion != "" {
		return excludeVersion + " (excluding)"
	}

	version := item.Version().String()
	if version != "*" {
		if update := item.Update().String(); update != "*" && update != "-" {
			version += "-" + update
		}
		return version + " (including)"
	}

	return version
}

func VulnerabilityPostToMarkdown(blog VulnerabilityPost, outputFile *os.File, customContent string) error {
	t := template.Must(template.New("blog").Funcs(gtf.GtfTextFuncMap).Parse(vulnerabilityPostTemplate))
	err := t.Execute(outputFile, blog)
	if err != nil {
		return err
	}

	if customContent != "" {
		_, _ = outputFile.WriteString("\n" + customContent)
	}
	return nil
}

func ReservedPostToMarkdown(rpi ReservedPage, outputFile *os.File) error {
	t := template.Must(template.New("reservedCVEPost").Funcs(gtf.GtfTextFuncMap).Parse(reservedPostTemplate))
	err := t.Execute(outputFile, rpi)
	if err != nil {
		return err
	}
	return nil
}

// FIXME: Currently if existing fields are removed from a markdown and pages are generated
// this logic doesn't work as expected. Workaround is to follow steps in the README.
func GetCustomContentFromMarkdown(fileName string) string {
	b, _ := ioutil.ReadFile(fileName)

	content := strings.Split(string(b), `<!--- Add Aqua content below --->`)
	switch len(content) {
	case 0, 1:
		return ""
	default:
		return strings.TrimSpace(content[1])
	}
}

const vulnerabilityPostTemplate = `---
title: "{{.Title}}"
aliases: [
	"/nvd/{{ lower .Title}}"
]

shortName: "{{.ShortName}}"
date: {{.Date}}
category: vulnerabilities
draft: false

avd_page_type: nvd_page

date_published: {{.Vulnerability.Dates.Published}}
date_modified: {{.Vulnerability.Dates.Modified}}

header_subtitle: "{{.ShortName}}"

sidebar_additional_info_nvd: "https://nvd.nist.gov/vuln/detail/{{.Title}}"
sidebar_additional_info_cwe: "https://cwe.mitre.org/data/definitions/{{.Vulnerability.CWEID | replace "CWE-"}}.html"

cvss_nvd_v3_vector: "{{.Vulnerability.CVSS.V3Vector | default "N/A"}}"
cvss_nvd_v3_score: "{{.Vulnerability.CVSS.V3Score}}"
cvss_nvd_v3_severity: "{{.Vulnerability.NVDSeverityV3 | upper | default "N/A"}}"

cvss_nvd_v2_vector: "{{.Vulnerability.CVSS.V2Vector | default "N/A"}}"
cvss_nvd_v2_score: "{{.Vulnerability.CVSS.V2Score}}"
cvss_nvd_v2_severity: "{{.Vulnerability.NVDSeverityV2 | upper | default "N/A"}}"

redhat_v2_vector: "{{.Vulnerability.RedHatCVSSInfo.CVSS.V2Vector | default "N/A"}}"
redhat_v2_score: "{{.Vulnerability.RedHatCVSSInfo.CVSS.V2Score}}"
redhat_v2_severity: "{{.Vulnerability.RedHatCVSSInfo.Severity | upper | default "N/A" }}"

redhat_v3_vector: "{{.Vulnerability.RedHatCVSSInfo.CVSS.V3Vector | default "N/A"}}"
redhat_v3_score: "{{.Vulnerability.RedHatCVSSInfo.CVSS.V3Score}}"
redhat_v3_severity: "{{.Vulnerability.RedHatCVSSInfo.Severity | upper | default "N/A" }}"

ubuntu_vector: "N/A"
ubuntu_score: "N/A"
ubuntu_severity: "{{.Vulnerability.UbuntuCVSSInfo.Severity | upper | default "N/A"}}"

---

{{.Vulnerability.Description}}


{{- if .Vulnerability.CWEInfo.Description}}
### Weakness {.with_icon .weakness}
{{.Vulnerability.CWEInfo.Description}}
{{end}}

{{- if .Vulnerability.AffectedSoftware}}
### Affected Software {.with_icon .affected_software}
| Name | Vendor           | Start Version | End Version |
| ------------- |-------------|-----|----|{{range $s := .Vulnerability.AffectedSoftware}}
| {{$s.Name | capfirst}} | {{$s.Vendor | capfirst }} | {{$s.StartVersion}} | {{$s.EndVersion}}|{{end}}
{{end}}

{{- if .Vulnerability.CWEInfo.ExtendedDescription}}
### Extended Description{{range $ed := .Vulnerability.CWEInfo.ExtendedDescription}}
{{$ed}}{{end}}
{{end}}

{{- if .Vulnerability.CWEInfo.PotentialMitigations.Mitigation}}
### Potential Mitigations {.with_icon .mitigations}{{range $mitigation := .Vulnerability.CWEInfo.PotentialMitigations.Mitigation}}
{{- if $mitigation.Description}}{{range $d := $mitigation.Description}}
- {{$d}}{{end}}{{end}}{{end}}
{{end}}

{{- if .Vulnerability.CWEInfo.RelatedAttackPatterns.RelatedAttackPattern}}
### Related Attack Patterns {.with_icon .related_patterns}{{range $attack := .Vulnerability.CWEInfo.RelatedAttackPatterns.RelatedAttackPattern}}
- https://cwe.mitre.org/data/definitions/{{$attack.CAPECID}}.html{{end}}
{{end}}

### References  {.with_icon .references}{{range $element := .Vulnerability.References}}
- {{$element}}{{end}}

<!--- Add Aqua content below --->`

const reservedPostTemplate = `---
title: "{{.ID}}"
date: {{.Date}}
draft: false
category: vulnerabilities

avd_page_type: reserved_page
---

This vulnerability is marked as __RESERVED__ by NVD. This means that the CVE-ID is reserved for future use
by the [CVE Numbering Authority (CNA)](https://cve.mitre.org/cve/cna.html) or a security researcher, but the details of it are not yet publicly available yet. 

This page will reflect the classification results once they are available through NVD. 

Any vendor information available is shown as below.

||||
| ------------- |-------------|-----|

{{ range $vendor, $reservedCVEInfo := .CVEMap }}
### {{ $vendor | capfirst }}
{{ $reservedCVEInfo.Description }}

{{if  $reservedCVEInfo.Mitigation}}
#### Mitigation
{{ $reservedCVEInfo.Mitigation }}
{{end}}
{{if $reservedCVEInfo.AffectedSoftwareList}}
#### Affected Software List
| Name | Vendor           | Version |
| ------------- |-------------|-----|{{range $s := $reservedCVEInfo.AffectedSoftwareList}}
| {{$s.Name | capfirst}} | {{$s.Vendor | capfirst }} | {{$s.StartVersion}}|{{end}}
{{end}}
{{end}}`
