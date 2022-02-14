package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/aquasecurity/defsec/loader"
	"github.com/aquasecurity/defsec/rules"

	"github.com/aquasecurity/avd-generator/docGen/menu"
)

var (
	Years = []string{
		"1999", "2000", "2001", "2002", "2003", "2004", "2005",
		// "2006", "2007", "2008", "2009", "2010", "2011", "2012",
		// "2013", "2014", "2015", "2016", "2017", "2018", "2019",
		// "2020", "2021",
	}

	misConfigurationMenu = menu.New("misconfig", "content/misconfig")
	runTimeSecurityMenu  = menu.New("runsec", "content/tracee")
	vulnerabilityMenu    = menu.New("vulnerabilities", "content/nvd")
)

type Clock interface {
	Now() string
}

type realClock struct{}

func (realClock) Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func getAllFiles(dir string) ([]string, error) {
	var filesFound []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		filesFound = append(filesFound, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return filesFound, nil
}

func getAllFilesOfKind(dir string, include string, exclude string) ([]string, error) { // TODO: include and exclude should be slices/variadic
	var filteredFiles []string
	files, err := getAllFiles(dir)
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

func main() {
	generateAppShieldPages("appshield-repo", "content/misconfig", realClock{})
	generateKubeHunterPages("kube-hunter-repo/docs/_kb", "content/misconfig/kubernetes/kubehunter")
	generateVulnPages()
	for _, year := range Years {
		generateReservedPages(year, realClock{}, "vuln-list", "content/nvd")
	}
	generateCloudSploitPages("cloudsploit-repo/plugins", "content/misconfig", "remediations-repo/en")
	generateTraceePages("tracee-repo/signatures", "content/tracee", realClock{})
	generateDefsecPages("defsec-repo/avd_docs", "content/misconfig", rules.GetRegistered())
	misConfigurationMenu.Generate()
	runTimeSecurityMenu.Generate()
	createTopLevelMenus()
}

func createTopLevelMenus() {

	if err := menu.NewTopLevelMenu("Providers", "toplevel_page", "content/misconfig/_index.md").
		WithHeading("Misconfiguration").
		WithIcon("aqua").
		WithCategory("misconfig").
		WithMenu("misconfig").Generate(); err != nil {
		panic(err)
	}

	if err := menu.NewTopLevelMenu("Tracee", "toplevel_page", "content/tracee/_index.md").
		WithHeading("Runtime Security").
		WithIcon("tracee").
		WithCategory("runsec").
		WithMenu("runsec").
		Generate(); err != nil {
		panic(err)
	}
}

/*


  - heading: Infrastucture as Code
   url: /misconfig/infra

    icon: iac
    summary: This is where the stuff about IaC will go
  - heading: Kube Hunter
    url: /misconfig/infra
    icon: aqua
    summary: This is where the stuff about IaC will go
  - heading: Workload Configuration
    url: /misconfig/infra
    icon: appshield
    summary: This is where the stuff about IaC will go

*/
