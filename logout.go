package saml

import (
	"encoding/xml"
	"time"

	"github.com/bmanth60/go-saml/packager"
	"github.com/bmanth60/go-saml/util"
)

//NewLogoutResponse create new logout response entity
func NewLogoutResponse() *Response {
	r := NewAuthnResponse()
	r.XMLName.Local = "samlp:LogoutResponse"
	return r
}

//NewLogoutRequest create new logout request entity
func NewLogoutRequest() *LogoutRequest {
	id := util.ID()
	return &LogoutRequest{
		XMLName: xml.Name{
			Local: "samlp:LogoutRequest",
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
		NameID: NameID{
			XMLName: xml.Name{
				Local: "saml:NameID",
			},
			Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
			Value:  "",
		},
		SessionIndex: SessionIndex{
			XMLName: xml.Name{
				Local: "samlp:SessionIndex",
			},
			Value: "",
		},
	}
}

//ApplyLogoutRequest entity as specified by provided parameters
func ApplyLogoutRequest(settings *Settings, r *LogoutRequest, nameID string, sessionIndex string) *LogoutRequest {
	r.Destination = settings.IDP.SingleLogoutURL
	r.Issuer.URL = settings.SP.EntityID
	r.Signature.KeyInfo.X509Data.X509Certificate.Cert = settings.SPPublicCert()
	r.NameID.Format = settings.IDP.NameIDFormat
	r.NameID.Value = nameID
	r.SessionIndex.Value = sessionIndex

	if !settings.SP.SignRequest {
		r.SAMLSIG = ""
		r.Signature = nil
	}

	return r
}

//String get string representation of logout request
func (r *LogoutRequest) String() (string, error) {
	return packager.String(r)
}

//SignedString get xml signed string representation of logout request
func (r *LogoutRequest) SignedString(s *Settings) (string, error) {
	if !s.SP.SignRequest {
		return "", ErrInvalidSettings
	}

	xmldoc, err := r.String()
	if err != nil {
		return "", err
	}

	return packager.SignWithKey(xmldoc, s.SPPrivateKey())
}
