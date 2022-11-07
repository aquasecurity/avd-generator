package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aquasecurity/avd-generator/menu"
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

	generateChainBenchPages("../avd-repo/chain-bench-repo/internal/checks", "../avd-repo/content/compliance")
	generateKubeBenchPages("../avd-repo/kube-bench-repo/cfg", "../avd-repo/content/compliance")
	generateDefsecComplianceSpecPages("../avd-repo/defsec-repo/internal/specs/compliance", "../avd-repo/content/compliance")
	generateKubeHunterPages("../avd-repo/kube-hunter-repo/docs/_kb", "../avd-repo/content/misconfig/kubernetes")
	generateCloudSploitPages("../avd-repo/cloudsploit-repo/plugins", "../avd-repo/content/misconfig", "../avd-repo/remediations-repo/en")
	generateTraceePages("../avd-repo/tracee-repo/signatures", "../avd-repo/content/tracee", realClock{})
	generateDefsecPages("../avd-repo/defsec-repo/avd_docs", "../avd-repo/content/misconfig")

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
