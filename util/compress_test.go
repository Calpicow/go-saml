package util_test

import (
	"testing"

	"github.com/bmanth60/go-saml/util"
	"github.com/stretchr/testify/assert"
)

func TestCompressString(t *testing.T) {
	expected := "This is the test string"
	compressed := util.CompressString(expected)
	decompressed := util.DecompressString(compressed)
	assert.Equal(t, expected, decompressed)
	assert.True(t, len(compressed) > len(decompressed))
}

func TestCompress(t *testing.T) {
	expected := []byte("This is the test string")
	compressed := util.Compress(expected)
	decompressed := util.Decompress(compressed)
	assert.Equal(t, expected, decompressed)
	assert.True(t, len(compressed) > len(decompressed))
}
