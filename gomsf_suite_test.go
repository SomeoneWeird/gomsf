package gomsf_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"testing"
)

func TestGomsf(t *testing.T) {

	RegisterFailHandler(Fail)
	RunSpecs(t, "Gomsf Suite")
}
