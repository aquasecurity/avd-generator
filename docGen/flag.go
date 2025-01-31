package main

import "strings"

type stringSliceFlag []string

func (s *stringSliceFlag) Set(value string) error {
	*s = strings.Split(value, ",")
	return nil
}

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}
