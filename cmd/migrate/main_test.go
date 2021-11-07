package main

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestIdentMigrations(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Ident Migrations Suite")
}

var _ = Describe("Main", func() {

})
