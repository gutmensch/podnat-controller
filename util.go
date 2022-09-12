package main

import (
	"os"
	"strings"
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func shortHostName(hostname string) string {
	if strings.Contains(hostname, ".") {
		return strings.Split(hostname, ".")[0]
	}
	return hostname
}
