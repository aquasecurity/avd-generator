package main

import (
	"os"
	"path/filepath"
	"strings"
)

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
