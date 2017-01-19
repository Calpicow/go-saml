// Copyright 2014 Matthew Baird, Andrew Mussey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package saml

import (
	"encoding/xml"
	"time"

	"github.com/bmanth60/go-saml/packager"
	"github.com/bmanth60/go-saml/util"
)

//Validate authentication request
func (r *AuthnRequest) Validate(publicCertPath string) error {
	if r.Version != "2.0" {
		return ErrUnsupportedVersion
	}

	if len(r.ID) == 0 {
		return ErrMissingID
	}

	// TODO more validation

	err := packager.Verify(r.originalString, publicCertPath)
	if err != nil {
		return err
	}

	return nil
}

//ApplyAuthnRequest returns an authentication request object based on SAML Settings
//passed in
func ApplyAuthnRequest(s Settings, r *AuthnRequest) *AuthnRequest {
	r.AssertionConsumerServiceURL = s.SP.AssertionConsumerServiceURL
	r.Destination = s.IDP.SingleSignOnURL
	r.Issuer.URL = s.SP.EntityID
	r.Signature.KeyInfo.X509Data.X509Certificate.Cert = s.SPPublicCert()
	r.NameIDPolicy.Format = s.IDP.NameIDFormat

	if !s.SP.SignRequest {
		r.SAMLSIG = ""
		r.Signature = nil
	}

	return r
}

//NewAuthnRequest get a new authentication request object
func NewAuthnRequest() *AuthnRequest {
	id := util.ID()
	return &AuthnRequest{
		XMLName: xml.Name{
			Local: "samlp:AuthnRequest",
		},
		RootXML: &RootXML{
			SAMLP:   "urn:oasis:names:tc:SAML:2.0:protocol",
			SAML:    "urn:oasis:names:tc:SAML:2.0:assertion",
			SAMLSIG: "http://www.w3.org/2000/09/xmldsig#",
			ID:      id,
			Version: "2.0",
			Issuer: Issuer{
				XMLName: xml.Name{
					Local: "saml:Issuer",
				},
				URL:  "", // caller must populate ar.AppSettings.Issuer
				SAML: "urn:oasis:names:tc:SAML:2.0:assertion",
			},
			IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
			Signature:    packager.GetSignatureEntity(id),
		},
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		AssertionConsumerServiceURL: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
		NameIDPolicy: NameIDPolicy{
			XMLName: xml.Name{
				Local: "samlp:NameIDPolicy",
			},
			AllowCreate: true,
			Format:      "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		},
		RequestedAuthnContext: &RequestedAuthnContext{
			XMLName: xml.Name{
				Local: "samlp:RequestedAuthnContext",
			},
			SAMLP:      "urn:oasis:names:tc:SAML:2.0:protocol",
			Comparison: "exact",
			AuthnContextClassRef: AuthnContextClassRef{
				XMLName: xml.Name{
					Local: "saml:AuthnContextClassRef",
				},
				SAML:      "urn:oasis:names:tc:SAML:2.0:assertion",
				Transport: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
		},
	}
}

//String get string representation of authentication request
func (r *AuthnRequest) String() (string, error) {
	return packager.String(r)
}

//SignedString get xml signed string representation of authentication request
func (r *AuthnRequest) SignedString(s *Settings) (string, error) {
	if !s.SP.SignRequest {
		return "", ErrInvalidSettings
	}

	xmldoc, err := r.String()
	if err != nil {
		return "", err
	}

	return packager.SignWithKey(xmldoc, s.SPPrivateKey())
}

//EncodedSignedString get base64 encoded and xml signed string representation of authentication request
func (r *AuthnRequest) EncodedSignedString(privateKeyPath string) (string, error) {
	return packager.EncodedSignedString(r, privateKeyPath)
}

//CompressedEncodedSignedString get compressed, base64 encoded and xml signed string representation of authentication request
func (r *AuthnRequest) CompressedEncodedSignedString(privateKeyPath string) (string, error) {
	return packager.CompressedEncodedSignedString(r, privateKeyPath)
}

//EncodedString get base64 encoded string representation of authentication request object
func (r *AuthnRequest) EncodedString() (string, error) {
	return packager.EncodedString(r)
}

//CompressedEncodedString get compressed and base64 encoded string representation of authentication request object
func (r *AuthnRequest) CompressedEncodedString() (string, error) {
	return packager.CompressedEncodedString(r)
}
