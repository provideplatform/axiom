package main

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestProvidibrightAPI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Providibright API Suite")
}

var _ = Describe("Main", func() {

})
