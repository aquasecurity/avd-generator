package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/avd-generator/menu"
	_ "github.com/aquasecurity/defsec/loader"
	"github.com/aquasecurity/defsec/rules"
)

var (
	Years = []string{
		"1999", "2000", "2001", "2002", "2003", "2004", "2005",
		"2006", "2007", "2008", "2009", "2010", "2011", "2012",
		"2013", "2014", "2015", "2016", "2017", "2018", "2019",
		"2020", "2021", "2022",
	}

	misConfigurationMenu = menu.New("misconfig", "content/misconfig")
	runTimeSecurityMenu  = menu.New("runsec", "content/tracee")
)

type Clock interface {
	Now(format ...string) string
}

type realClock struct{}

func (realClock) Now(format ...string) string {
	formatString := time.RFC3339
	if len(format) > 0 {
		formatString = format[0]
	}

	return time.Now().Format(formatString)
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
	generateKubeBenchPages("kube-bench-repo/cfg", "content/misconfig")
	generateKubeHunterPages("kube-hunter-repo/docs/_kb", "content/misconfig/kubernetes")
	generateVulnPages()
	for _, year := range Years {
		generateReservedPages(year, realClock{}, "vuln-list", "content/nvd")
	}
	generateCloudSploitPages("cloudsploit-repo/plugins", "content/misconfig", "remediations-repo/en")
	generateTraceePages("tracee-repo/signatures", "content/tracee", realClock{})
	generateDefsecPages("defsec-repo/avd_docs", "content/misconfig", rules.GetRegistered())
	generateAppShieldPages("defsec-repo", "content/misconfig", realClock{})

	if err := misConfigurationMenu.Generate(); err != nil {
		fail(err)
	}
	if err := runTimeSecurityMenu.Generate(); err != nil {
		fail(err)
	}
	createTopLevelMenus()
}

func createTopLevelMenus() {

	if err := menu.NewTopLevelMenu("Misconfiguration", "toplevel_page", "content/misconfig/_index.md").
		WithHeading("Misconfiguration Categories").
		WithIcon("aqua").
		WithCategory("misconfig").Generate(); err != nil {
		fail(err)
	}

	if err := menu.NewTopLevelMenu("Tracee", "toplevel_page", "content/tracee/_index.md").
		WithHeading("Runtime Security").
		WithIcon("tracee").
		WithCategory("runsec").
		Generate(); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Println(err)
	os.Exit(1)
}
