package main

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/aquasecurity/avd-generator/menu"
)

var (
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

type generatePagesFunc func()

var generators = map[string]generatePagesFunc{
	"chain-bench": func() {
		generateChainBenchPages("../avd-repo/chain-bench-repo/internal/checks", "../avd-repo/content/compliance")
	},
	"kube-bench": func() {
		generateKubeBenchPages("../avd-repo/kube-bench-repo/cfg", "../avd-repo/content/compliance")
	},
	"kube-hunter": func() {
		generateKubeHunterPages("../avd-repo/kube-hunter-repo/docs/_kb", "../avd-repo/content/misconfig/kubernetes")
	},
	"trivy-compliance": func() {
		generateDefsecComplianceSpecPages("../avd-repo/trivy-policies-repo/rules/specs/compliance", "../avd-repo/content/compliance")
	},
	"trivy-checks": func() {
		generateDefsecPages("../avd-repo/trivy-policies-repo/avd_docs", "../avd-repo/content/misconfig")
	},
	"cloudsploit": func() {
		generateCloudSploitPages("../avd-repo/cloudsploit-repo/plugins", "../avd-repo/content/misconfig", "../avd-repo/remediations-repo/en")
	},
	"tracee": func() {
		generateTraceePages("../avd-repo/tracee-repo/signatures", "../avd-repo/content/tracee", realClock{})
	},
	"nvd": func() {
		GenerateNvdPages()
	},
}

func allSources() []string {
	sources := make([]string, 0, len(generators))
	for source := range generators {
		sources = append(sources, source)
	}
	slices.Sort(sources)
	return sources
}

func main() {
	sources := stringSliceFlag(allSources())
	flag.Var(&sources, "sources", "Comma-separated list of sources to generate documentation from")
	flag.Parse()

	for _, source := range sources {
		generateFn, exists := generators[source]
		if !exists {
			fmt.Printf("Unknown source: %s\n", source)
			os.Exit(1)
		}
		fmt.Printf("Generate docs for %s\n", source)
		generateFn()
	}

	createTopLevelMenus()
}

func createTopLevelMenus() {
	if err := menu.NewTopLevelMenu("Misconfiguration", "toplevel_page", "../avd-repo/content/misconfig/_index.md").
		WithHeading("Misconfiguration Categories").
		WithIcon("aqua").
		WithCategory("misconfig").Generate(); err != nil {
		fail(err)
	}
	if err := menu.NewTopLevelMenu("Compliance", "toplevel_page", "../avd-repo/content/compliance/_index.md").
		WithHeading("Compliance").
		WithIcon("aqua").
		WithCategory("compliance").Generate(); err != nil {
		fail(err)
	}
	if err := menu.NewTopLevelMenu("Tracee", "toplevel_page", "../avd-repo/content/tracee/_index.md").
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
