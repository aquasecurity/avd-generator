package main

import (
	"os"
	"path/filepath"
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
