package main

import (
	"encoding/json"
	"fmt"
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
)

const vulnerabilityPostTemplate = `---
title: "{{.Title}}"
date: {{.Date}}
draft: false

avd_page_type: nvd_page

date_published: {{.Vulnerability.Dates.Published}}
date_modified: {{.Vulnerability.Dates.Modified}}

sidebar_additiona_info_nvd: "https://nvd.nist.gov/vuln/detail/{{.Title}}"
sidebar_additiona_info_cwe: "https://cwe.mitre.org/data/definitions/{{.Vulnerability.CWEID | replace "CWE-"}}.html"

cvss_nvd_v3_vector: "{{.Vulnerability.CVSS.V3Vector | default "-"}}"
cvss_nvd_v3_score: "{{.Vulnerability.CVSS.V3Score}}"
cvss_nvd_v3_severity: "{{.Vulnerability.NVDSeverityV3 | upper | default "-"}}"

cvss_nvd_v2_vector: "{{.Vulnerability.CVSS.V2Vector | default "-"}}"
cvss_nvd_v2_score: "{{.Vulnerability.CVSS.V2Score}}"
cvss_nvd_v2_severity: "{{.Vulnerability.NVDSeverityV2 | upper | default "-"}}"

redhat_v2_vector: "{{.Vulnerability.RedHatCVSSInfo.CVSS.V2Vector | default "-"}}"
redhat_v2_score: "{{.Vulnerability.RedHatCVSSInfo.CVSS.V2Score}}"
redhat_v2_severity: "{{.Vulnerability.RedHatCVSSInfo.Severity | upper | default "-" }}"

redhat_v3_vector: "{{.Vulnerability.RedHatCVSSInfo.CVSS.V3Vector | default "-"}}"
redhat_v3_score: "{{.Vulnerability.RedHatCVSSInfo.CVSS.V3Score}}"
redhat_v3_severity: "{{.Vulnerability.RedHatCVSSInfo.Severity | upper | default "-" }}"

ubuntu_vector: "-"
ubuntu_score: "-"
ubuntu_severity: "{{.Vulnerability.UbuntuCVSSInfo.Severity | upper | default "-"}}"

---

### Description
{{.Vulnerability.Description}}

{{ if .Vulnerability.CWEInfo.Name}}
### Title
{{.Vulnerability.CWEInfo.Name}}
{{end}}

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

const regoPolicyPostTemplate = `---
title: "{{.Title}}"
date: {{.Date}}
draft: false
---

### {{.Rego.ID}}

### Description
{{.Rego.Description}}

### Severity
{{ .Rego.Severity }}

### Recommended Actions 
{{ .Rego.RecommendedActions }}

### Rego Policy
` + "```\n{{ .Rego.Policy }}\n```" + `
### Links{{range $element := .Rego.Links}}
- {{$element}}{{end}}
`

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

type RelatedAttackPattern struct {
	CAPECID int
}

// The RelatedAttackPatternsType complex type contains references to attack patterns associated with this weakness. The association implies those attack patterns may be applicable if an instance of this weakness exists. Each related attack pattern is identified by a CAPEC identifier.
type RelatedAttackPatternsType struct {
	RelatedAttackPattern []RelatedAttackPattern
}

type Mitigation struct {
	Phase       []PhaseEnumeration
	Strategy    MitigationStrategyEnumeration
	Description StructuredTextType
}

// May be one of Policy, Requirements, Architecture and Design, Implementation, Build and Compilation, Testing, Documentation, Bundling, Distribution, Installation, System Configuration, Operation, Patching and Maintenance, Porting, Integration, Manufacturing
type PhaseEnumeration string

// May be one of Attack Surface Reduction, Compilation or Build Hardening, Enforcement by Conversion, Environment Hardening, Firewall, Input Validation, Language Selection, Libraries or Frameworks, Resource Limitation, Output Encoding, Parameterization, Refactoring, Sandbox or Jail, Separation of Privilege
type MitigationStrategyEnumeration string

// The PotentialMitigationsType complex type is used to describe potential mitigations associated with a weakness. It contains one or more Mitigation elements, which each represent individual mitigations for the weakness. The Phase element indicates the development life cycle phase during which this particular mitigation may be applied. The Strategy element describes a general strategy for protecting a system to which this mitigation contributes. The Effectiveness element summarizes how effective the mitigation may be in preventing the weakness. The Description element contains a description of this individual mitigation including any strengths and shortcomings of this mitigation for the weakness.
//
// The optional Mitigation_ID attribute is used by the internal CWE team to uniquely identify mitigations that are repeated across any number of individual weaknesses. To help make sure that the details of these common mitigations stay synchronized, the Mitigation_ID is used to quickly identify those mitigation elements across CWE that should be identical. The identifier is a string and should match the following format: MIT-1.
type PotentialMitigationsType struct {
	Mitigation []Mitigation
}

// The CommonConsequencesType complex type is used to specify individual consequences associated with a weakness. The required Scope element identifies the security property that is violated. The optional Impact element describes the technical impact that arises if an adversary succeeds in exploiting this weakness. The optional Likelihood element identifies how likely the specific consequence is expected to be seen relative to the other consequences. For example, there may be high likelihood that a weakness will be exploited to achieve a certain impact, but a low likelihood that it will be exploited to achieve a different impact. The optional Note element provides additional commentary about a consequence.
//
// The optional Consequence_ID attribute is used by the internal CWE team to uniquely identify examples that are repeated across any number of individual weaknesses. To help make sure that the details of these common examples stay synchronized, the Consequence_ID is used to quickly identify those examples across CWE that should be identical. The identifier is a string and should match the following format: CC-1.
type CommonConsequencesType struct {
	Consequence []Consequence
}

type Consequence struct {
	Scope  []ScopeEnumeration
	Impact []TechnicalImpactEnumeration
}

// May be one of Modify Memory, Read Memory, Modify Files or Directories, Read Files or Directories, Modify Application Data, Read Application Data, DoS: Crash, Exit, or Restart, DoS: Amplification, DoS: Instability, DoS: Resource Consumption (CPU), DoS: Resource Consumption (Memory), DoS: Resource Consumption (Other), Execute Unauthorized Code or Commands, Gain Privileges or Assume Identity, Bypass Protection Mechanism, Hide Activities, Alter Execution Logic, Quality Degradation, Unexpected State, Varies by Context, Reduce Maintainability, Reduce Performance, Reduce Reliability, Other
type TechnicalImpactEnumeration string

// May be one of Confidentiality, Integrity, Availability, Access Control, Accountability, Authentication, Authorization, Non-Repudiation, Other
type ScopeEnumeration string
type StructuredTextType []string

type WeaknessType struct {
	ID                    int
	Name                  string
	Description           string
	PotentialMitigations  PotentialMitigationsType
	RelatedAttackPatterns RelatedAttackPatternsType
	CommonConsequences    CommonConsequencesType
	ExtendedDescription   StructuredTextType
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
	By            string
	Date          string
	Vulnerability Vulnerability
}

type Rego struct {
	ID                 string
	Description        string
	Links              []string
	Severity           string
	Policy             string
	RecommendedActions string
}

type RegoPost struct {
	Layout string
	Title  string
	By     string
	Date   string
	Rego   Rego
}

func ParseVulnerabilityJSONFile(fileName string) (VulnerabilityPost, error) {
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
	vuln.Description = strings.NewReplacer(`"`, ``, `\`, ``).Replace(string(v.GetStringBytes("cve", "description", "description_data", "0", "value")))
	vuln.ID = string(v.GetStringBytes("cve", "CVE_data_meta", "ID"))
	vuln.CWEID = string(v.GetStringBytes("cve", "problemtype", "problemtype_data", "0", "description", "0", "value"))
	vuln.CVSS = CVSS{
		V2Vector: string(v.GetStringBytes("impact", "baseMetricV2", "cvssV2", "vectorString")),
		V2Score:  v.GetFloat64("impact", "baseMetricV2", "cvssV2", "baseScore"),
		V3Vector: string(v.GetStringBytes("impact", "baseMetricV3", "cvssV3", "vectorString")),
		V3Score:  v.GetFloat64("impact", "baseMetricV3", "cvssV3", "baseScore"),
	}

	vuln.NVDSeverityV2 = string(v.GetStringBytes("impact", "baseMetricV2", "severity"))
	vuln.NVDSeverityV3 = string(v.GetStringBytes("impact", "baseMetricV3", "cvssV3", "baseSeverity"))

	publishedDate, _ := time.Parse("2006-01-02T04:05Z", string(v.GetStringBytes("publishedDate")))
	modifiedDate, _ := time.Parse("2006-01-02T04:05Z", string(v.GetStringBytes("lastModifiedDate")))
	vuln.Dates = Dates{
		Published: publishedDate.UTC().Format("2006-01-02 03:04:05 -0700"),
		Modified:  modifiedDate.UTC().Format("2006-01-02 03:04:05 -0700"),
	}

	var refs []string
	for _, r := range v.GetArray("cve", "references", "reference_data") {
		refs = append(refs, strings.ReplaceAll(r.Get("url").String(), `"`, ``))
	}
	vuln.References = refs

	affectedSoftwares := v.GetArray("configurations", "nodes", "0", "cpe_match") // TODO: This logic should be improved to iterate over list of lists
	for _, as := range affectedSoftwares {
		uri := string(as.GetStringBytes("cpe23Uri"))
		item, err := cpe.NewItemFromFormattedString(uri)
		if err != nil {
			continue
		}

		startVersion := string(as.GetStringBytes("versionStartIncluding"))
		if startVersion == "" {
			startVersion = item.Version().String()
		}

		endVersion := string(as.GetStringBytes("versionEndIncluding"))
		if endVersion == "" {
			endVersion = item.Version().String()
		}

		vuln.AffectedSoftware = append(vuln.AffectedSoftware, AffectedSoftware{
			Name:         item.Product().String(),
			Vendor:       item.Vendor().String(),
			StartVersion: startVersion,
			EndVersion:   endVersion,
		})
	}

	return VulnerabilityPost{
		Layout:        "vulnerability",
		Title:         vuln.ID,
		By:            "NVD",
		Date:          publishedDate.UTC().Format("2006-01-02 03:04:05 -0700"),
		Vulnerability: vuln,
	}, nil
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

func RegoPostToMarkdown(rp RegoPost, outputFile *os.File) error {
	t := template.Must(template.New("regoPost").Parse(regoPolicyPostTemplate))
	err := t.Execute(outputFile, rp)
	if err != nil {
		return err
	}
	return nil
}

func GetAllFiles(dir string) ([]string, error) {
	var filesFound []string
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		filesFound = append(filesFound, file.Name())
	}
	return filesFound, nil
}

func GetAllFilesOfKind(dir string, include string, exclude string) ([]string, error) {
	var filteredFiles []string
	files, err := GetAllFiles(dir)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		if strings.Contains(f, include) && !strings.Contains(f, exclude) {
			filteredFiles = append(filteredFiles, f)
		}
	}
	return filteredFiles, nil
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

func ParseRegoPolicyFile(fileName string) (rp RegoPost, err error) {
	rego, err := ioutil.ReadFile(fileName)
	if err != nil {
		return RegoPost{}, err
	}

	idx := strings.Index(string(rego), "package main")
	metadata := string(rego)[:idx]

	rp.Layout = "regoPolicy"
	rp.By = "Aqua Security"
	rp.Rego.Policy = strings.TrimSpace(string(rego)[idx:])
	rp.Date = time.Unix(1594669401, 0).UTC().String()

	for _, line := range strings.Split(metadata, "\n") {
		r := strings.NewReplacer("@", "", "#", "")
		str := r.Replace(line)
		kv := strings.SplitN(str, ":", 2)
		if len(kv) >= 2 {
			val := strings.TrimSpace(kv[1])
			switch strings.ToLower(strings.TrimSpace(kv[0])) {
			case "id":
				rp.Title = val
			case "description":
				rp.Rego.Description = val
			case "recommended_actions":
				rp.Rego.RecommendedActions = val
			case "severity":
				rp.Rego.Severity = val
			case "title":
				rp.Rego.ID = val
				// TODO: Add case for parsing links
			}
		}
	}

	return
}

func main() {
	generateVulnPages()
	generateRegoPages()
}

func generateVulnPages() {
	years := []string{
		"1999", "2000", "2001", "2002", "2003", "2004", "2005",
		"2006", "2007", "2008", "2009", "2010",
		"2011", "2012", "2013", "2014", "2015",
		"2016", "2017", "2018", "2019",
		"2020",
	}

	var wg sync.WaitGroup
	for _, year := range years {
		year := year
		wg.Add(1)

		log.Printf("generating vuln year: %s\n", year)
		//nvdDir := fmt.Sprintf("goldens/json")
		//postsDir := "temp-posts"
		nvdDir := fmt.Sprintf("vuln-list/nvd/%s/", year)
		postsDir := "content/nvd"
		cweDir := fmt.Sprintf("vuln-list/cwe")

		go func(year string) {
			defer wg.Done()
			generateVulnerabilityPages(nvdDir, cweDir, postsDir)
		}(year)
	}
	wg.Wait()
}

func generateRegoPages() {
	for _, p := range []string{"kubernetes"} {
		policyDir := filepath.Join("appshield-repo", "policies", p, "policy")
		log.Printf("generating policies in: %s...", policyDir)
		generateRegoPolicyPages(policyDir, "content/appshield")
	}
}

func generateVulnerabilityPages(nvdDir string, cweDir string, postsDir string) {
	files, err := GetAllFiles(nvdDir)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		bp, err := ParseVulnerabilityJSONFile(filepath.Join(nvdDir, file))
		if err != nil {
			log.Printf("unable to parse file: %s, err: %s, skipping...\n", file, err)
			continue
		}

		_ = AddCWEInformation(&bp, cweDir)

		for _, vendor := range []string{"redhat", "ubuntu"} {
			_ = AddVendorInformation(&bp, vendor, filepath.Join(strings.ReplaceAll(nvdDir, "nvd", vendor)))
		}

		// check if file exists first, if does then open, if not create
		f, err := os.OpenFile(filepath.Join(postsDir, fmt.Sprintf("%s.md", bp.Title)), os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			log.Printf("unable to create file: %s for markdown, err: %s, skipping...\n", file, err)
			continue
		}

		customContent := GetCustomContentFromMarkdown(f.Name())
		if customContent != "" {
			_ = os.Truncate(f.Name(), 0) // truncate file if custom data was found
		}
		if err := VulnerabilityPostToMarkdown(bp, f, customContent); err != nil {
			log.Printf("unable to write file: %s as markdown, err: %s, skipping...\n", file, err)
			continue
		}
		_ = f.Close()
	}
}

func AddCWEInformation(bp *VulnerabilityPost, cweDir string) error {
	b, err := ioutil.ReadFile(filepath.Join(cweDir, fmt.Sprintf("%s.json", bp.Vulnerability.CWEID)))
	if err != nil {
		return err
	}

	var w WeaknessType
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}

	bp.Vulnerability.CWEInfo = w
	return nil
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

func generateRegoPolicyPages(policyDir string, postsDir string) {
	files, err := GetAllFilesOfKind(policyDir, "rego", "_test")

	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		rp, err := ParseRegoPolicyFile(filepath.Join(policyDir, file))
		if err != nil {
			log.Printf("unable to parse file: %s, err: %s, skipping...\n", file, err)
			continue
		}

		f, err := os.Create(filepath.Join(postsDir, fmt.Sprintf("%s.md", rp.Title)))
		if err != nil {
			log.Printf("unable to create file: %s for markdown, err: %s, skipping...\n", file, err)
			continue
		}
		if err := RegoPostToMarkdown(rp, f); err != nil {
			log.Printf("unable to write file: %s as markdown, err: %s, skipping...\n", file, err)
			continue
		}
		_ = f.Close()
	}
}
