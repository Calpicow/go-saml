package util_test

import (
	"testing"

	"github.com/bmanth60/go-saml/util"
	"github.com/stretchr/testify/assert"
)

func TestIDGenerated(t *testing.T) {
	var uuid interface{}
	assert.NotPanics(t, func() { util.ID() }, "ID creation should not panic")

	uuid = util.ID()
	_, ok := uuid.(string)
	assert.True(t, ok)
}
