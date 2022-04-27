package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aquasecurity/avd-generator/menu"
	_ "github.com/aquasecurity/defsec/loader"
	"github.com/aquasecurity/defsec/rules"
)

var (
	Years []string

	misConfigurationMenu = menu.New("misconfig", "content/misconfig")
	complianceMenu       = menu.New("compliance", "content/compliance")
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

func main() {

	firstYear := 1999

	for y := firstYear; y <= time.Now().Year(); y++ {
		Years = append(Years, strconv.Itoa(y))
	}

	generateKubeBenchPages("kube-bench-repo/cfg", "content/compliance")
	generateKubeHunterPages("kube-hunter-repo/docs/_kb", "content/misconfig/kubernetes")
	generateCloudSploitPages("cloudsploit-repo/plugins", "content/misconfig", "remediations-repo/en")
	generateTraceePages("tracee-repo/signatures", "content/tracee", realClock{})
	generateDefsecPages("defsec-repo/avd_docs", "content/misconfig", rules.GetRegistered())
	generateAppShieldPages("defsec-repo", "content/misconfig", realClock{})
	generateVulnPages()

	for _, year := range Years {
		generateReservedPages(year, realClock{}, "vuln-list", "content/nvd")
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
	if err := menu.NewTopLevelMenu("Compliance", "toplevel_page", "content/compliance/_index.md").
		WithHeading("Compliance").
		WithIcon("aqua").
		WithCategory("compliance").Generate(); err != nil {
		fail(err)
	}
	if err := menu.NewTopLevelMenu("Tracee", "toplevel_page", "content/tracee/_index.md").
		WithHeading("Runtime Security").
		WithIcon("tracee").
		WithCategory("runsec").
		Generate(); err != nil {
		fail(err)
	}

	if err := misConfigurationMenu.Generate(); err != nil {
		fail(err)
	}
	if err := runTimeSecurityMenu.Generate(); err != nil {
		fail(err)
	}
	if err := complianceMenu.Generate(); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Println(err)
	os.Exit(1)
}
