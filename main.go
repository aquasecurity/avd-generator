package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	Years = []string{
		"1999", "2000", "2001", "2002", "2003", "2004", "2005",
		"2006", "2007", "2008", "2009", "2010", "2011", "2012",
		"2013", "2014", "2015", "2016", "2017", "2018", "2019",
		"2020", "2021",
	}
)

type Clock interface {
	Now() string
}

type realClock struct{}

func (realClock) Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// GetAllFiles returns the absolute file path to all files in dir
func GetAllFiles(dir string) ([]string, error) {
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

func GetAllFilesOfKind(dir string, include string, exclude string) ([]string, error) { // TODO: include and exclude should be slices/variadic
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

func main() {
	generateVulnPages()
	generateAppShieldPages("appshield-repo", "content/appshield", realClock{})
	generateKubeHunterPages("kube-hunter-repo/docs/_kb", "content/kube-hunter")
	for _, year := range Years {
		generateReservedPages(year, realClock{}, "vuln-list", "content/nvd")
	}
	generateCloudSploitPages("remediations-repo/en", "content/cspm")
	generateTraceePages("tracee-repo/tracee-rules/signatures", "content/tracee", realClock{})
}
