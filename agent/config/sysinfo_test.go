package config

import (
	"testing"
)

func TestReadFile2Map(t *testing.T) {
	result := ReadFile2Map("/etc/server.info")
	println(result)
}
