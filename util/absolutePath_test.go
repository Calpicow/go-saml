package util_test

import (
	"strings"
	"testing"

	"github.com/bmanth60/go-saml/util"
	"github.com/stretchr/testify/assert"
)

func TestAbsoluteFilePath(t *testing.T) {
	path := util.AbsolutePath("/go/src/github.com/bmanth60/go-saml/certs/default.crt")
	assert.Equal(t, "/go/src/github.com/bmanth60/go-saml/certs/default.crt", path)
}

func TestRelativeFilePath(t *testing.T) {
	path := util.AbsolutePath("./../certs/sp-default.crt")
	assert.NotContains(t, path, "./../certs/sp-default.crt", "Dots should be expanded")
	assert.True(t, strings.HasSuffix(path, "/certs/sp-default.crt"))
}

func TestAbsoluteDirectory(t *testing.T) {
	path := util.AbsolutePath("/go/src/github.com/bmanth60/go-saml/certs")
	assert.Equal(t, "/go/src/github.com/bmanth60/go-saml/certs", path)
}

func TestRelativeDirectory(t *testing.T) {
	path := util.AbsolutePath("./../certs")
	assert.NotContains(t, path, "./../certs", "Dots should be expanded")
	assert.True(t, strings.HasSuffix(path, "/certs"))
}
