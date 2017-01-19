package util

import (
	"bytes"
	"compress/flate"
	"io"
	"strings"
)

//CompressString using compress/flate library
func CompressString(in string) string {
	buf := new(bytes.Buffer)
	compressor, _ := flate.NewWriter(buf, 9)
	compressor.Write([]byte(in))
	compressor.Close()
	return buf.String()
}

//DecompressString using compress/flate library
func DecompressString(in string) string {
	buf := new(bytes.Buffer)
	decompressor := flate.NewReader(strings.NewReader(in))
	io.Copy(buf, decompressor)
	decompressor.Close()
	return buf.String()
}

//Compress binary using compress/flate library
func Compress(in []byte) []byte {
	buf := new(bytes.Buffer)
	compressor, _ := flate.NewWriter(buf, 9)
	compressor.Write(in)
	compressor.Close()
	return buf.Bytes()
}

//Decompress binary using compress/flate library
func Decompress(in []byte) []byte {
	buf := new(bytes.Buffer)
	decompressor := flate.NewReader(bytes.NewReader(in))
	io.Copy(buf, decompressor)
	decompressor.Close()
	return buf.Bytes()
}
