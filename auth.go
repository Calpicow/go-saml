package saml

// This is the main auth class to coordinate typical calls
// for the sp and idp. It performs the following functions:
//
//SP
//Get auth request
//Parse auth response
//Get logout request
//Parse logout response
//
//IDP
//Parse auth request
//Create auth reponse TODO
//Parse logout request
//Create logout response TODO

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"net/url"

	"github.com/bmanth60/go-saml/packager"

	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
)

//Document interface for saml document methods
type Document interface {
	String() (string, error)
	SignedString(s *Settings) (string, error)
}

//GetAuthnRequestURL as SP, generate authentication request url to perform sso
func GetAuthnRequestURL(s Settings, state string) (string, error) {
	r := ApplyAuthnRequest(s, NewAuthnRequest())

	// Sign the request
	b64XML, err := packager.CompressedEncodedSignedStringFromKey(r, s.SPPrivateKey())
	if err != nil {
		return "", err
	}

	u, err := url.Parse(s.IDP.SingleSignOnURL)
	if err != nil {
		return "", err
	}

	return BuildRequestURL(s, u, state, b64XML)
}

//ParseAuthnRequest as IDP, parse incoming authentication request
func ParseAuthnRequest(s Settings, b64RequestXML string) (*AuthnRequest, error) {
	var err error
	var bytesXML []byte

	if s.Compress.Request {
		bytesXML, err = packager.DecodeAndInflateString(b64RequestXML)
	} else {
		bytesXML, err = packager.DecodeString(b64RequestXML)
	}

	if err != nil {
		return nil, err
	}

	request := new(AuthnRequest)
	err = xml.Unmarshal(bytesXML, request)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	request.originalString = string(bytesXML)
	return request, nil
}

//ParseAuthnResponse as SP, parse incoming authentication response
func ParseAuthnResponse(s Settings, b64ResponseXML string) (*Response, error) {
	var err error
	var bytesXML []byte

	if s.Compress.Response {
		bytesXML, err = packager.DecodeAndInflateString(b64ResponseXML)
	} else {
		bytesXML, err = packager.DecodeString(b64ResponseXML)
	}

	if err != nil {
		return nil, ErrCannotDecode
	}

	response := NewAuthnResponse()
	err = xml.Unmarshal(bytesXML, response)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	response.originalString = string(bytesXML)
	return response, nil
}

//GetLogoutRequestURL as SP, generate logout request url to perform slo
func GetLogoutRequestURL(s Settings, state string, nameID string, sessionIndex string) (string, error) {
	r := ApplyLogoutRequest(&s, NewLogoutRequest(), nameID, sessionIndex)

	// Sign the request
	b64XML, err := packager.CompressedEncodedSignedStringFromKey(r, s.SPPrivateKey())
	if err != nil {
		return "", err
	}

	u, err := url.Parse(s.IDP.SingleLogoutURL)
	if err != nil {
		return "", err
	}

	return BuildRequestURL(s, u, state, b64XML)
}

//ParseLogoutRequest as IDP, parse incoming logout request
func ParseLogoutRequest(s Settings, b64RequestXML string) (*LogoutRequest, error) {
	var err error
	var bytesXML []byte

	if s.Compress.Request {
		bytesXML, err = packager.DecodeAndInflateString(b64RequestXML)
	} else {
		bytesXML, err = packager.DecodeString(b64RequestXML)
	}

	if err != nil {
		return nil, err
	}

	request := new(LogoutRequest)
	err = xml.Unmarshal(bytesXML, request)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	request.originalString = string(bytesXML)
	return request, nil
}

//ParseLogoutResponse as SP, parse incoming logout response
func ParseLogoutResponse(s Settings, b64ResponseXML string) (*Response, error) {
	var err error
	var bytesXML []byte

	if s.Compress.Response {
		bytesXML, err = packager.DecodeAndInflateString(b64ResponseXML)
	} else {
		bytesXML, err = packager.DecodeString(b64ResponseXML)
	}

	if err != nil {
		return nil, err
	}

	response := NewLogoutResponse()
	err = xml.Unmarshal(bytesXML, response)
	if err != nil {
		return nil, err
	}

	// There is a bug with XML namespaces in Go that's causing XML attributes with colons to not be roundtrip
	// marshal and unmarshaled so we'll keep the original string around for validation.
	response.originalString = string(bytesXML)
	return response, nil
}

//BuildRequestURL build request url with signature
func BuildRequestURL(s Settings, u *url.URL, state string, b64XML string) (string, error) {
	q := u.Query()
	q.Add("SAMLRequest", b64XML)
	q.Add("RelayState", state)

	if s.SP.SignRequest {
		q.Set("SigAlg", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")

		//Build signature string. Digest must be in this order.
		sigstr := "SAMLRequest=" + url.QueryEscape(q.Get("SAMLRequest")) +
			"&RelayState=" + url.QueryEscape(q.Get("RelayState")) +
			"&SigAlg=" + url.QueryEscape(q.Get("SigAlg"))

		sig, err := GetRequestSignature(sigstr, s.SPPrivateKey())
		if err != nil {
			return "", err
		}

		q.Set("Signature", sig)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

//GetRequestSignature for the request url
func GetRequestSignature(data string, key string) (string, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return "", ErrPEMFormat
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes) //x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}

	digest := sha1.Sum([]byte(data))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA1, digest[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sigBytes), nil
}
