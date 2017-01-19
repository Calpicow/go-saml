package packager

import (
	"encoding/base64"
	"encoding/xml"

	"github.com/bmanth60/go-saml/util"
)

//String get string representation of xml document
func String(data interface{}) (string, error) {
	b, err := xml.MarshalIndent(data, "", "    ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

//SignedString sign the xml document and return string representation
func SignedString(data interface{}, privateKeyPath string) (string, error) {
	str, err := String(data)
	if err != nil {
		return "", err
	}

	return Sign(str, privateKeyPath)
}

//EncodedSignedString get base64 encoded, xml signed string representation of xml document
func EncodedSignedString(data interface{}, privateKeyPath string) (string, error) {
	signed, err := SignedString(data, privateKeyPath)
	if err != nil {
		return "", err
	}

	b64XML := EncodeString([]byte(signed))
	return b64XML, nil
}

//CompressedEncodedSignedStringFromKey sign string with sp key, compress, then base64 encode the xml document
func CompressedEncodedSignedStringFromKey(data interface{}, key string) (string, error) {
	str, err := String(data)
	if err != nil {
		return "", err
	}

	signed, err := SignWithKey(str, key)
	if err != nil {
		return "", err
	}

	b64XML := DeflateAndEncodeString([]byte(signed))
	return b64XML, nil
}

//CompressedEncodedSignedString sign xml document, compress, then base64 encode the xml document
func CompressedEncodedSignedString(data interface{}, privateKeyPath string) (string, error) {
	signed, err := SignedString(data, privateKeyPath)
	if err != nil {
		return "", err
	}

	b64XML := DeflateAndEncodeString([]byte(signed))
	return b64XML, nil
}

//EncodedString base64 encode xml document
func EncodedString(data interface{}) (string, error) {
	saml, err := String(data)
	if err != nil {
		return "", err
	}

	b64XML := EncodeString([]byte(saml))
	return b64XML, nil
}

//CompressedEncodedString compress, then base64 encode the xml document
func CompressedEncodedString(data interface{}) (string, error) {
	saml, err := String(data)
	if err != nil {
		return "", err
	}

	b64XML := DeflateAndEncodeString([]byte(saml))
	return b64XML, nil
}

//EncodeString base64 encode string
func EncodeString(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

//DeflateAndEncodeString deflate string then base 64 encode
func DeflateAndEncodeString(data []byte) string {
	compressed := util.Compress(data)
	return EncodeString(compressed)
}

//DecodeAndInflateString base64 decode and inflate string
func DecodeAndInflateString(data string) ([]byte, error) {
	compressedXML, err := DecodeString(data)
	if err != nil {
		return nil, err
	}
	bXML := util.Decompress(compressedXML)
	return bXML, nil
}

//DecodeString base64 decode string
func DecodeString(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}
