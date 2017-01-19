package saml

import (
	"encoding/xml"
	"errors"
	"time"

	"github.com/bmanth60/go-saml/packager"
	"github.com/bmanth60/go-saml/util"
)

//Validate saml response
func (r *Response) Validate(s *Settings) error {
	if r.Version != "2.0" {
		return ErrUnsupportedVersion
	}

	if len(r.ID) == 0 {
		return ErrMissingID
	}

	if len(r.Assertion.ID) == 0 {
		return errors.New("no Assertions")
	}

	if len(r.Signature.SignatureValue.Value) == 0 && len(r.Assertion.Signature.SignatureValue.Value) == 0 {
		return errors.New("no signature")
	}

	if r.Destination != s.SP.AssertionConsumerServiceURL {
		return errors.New("destination mismath expected: " + s.SP.AssertionConsumerServiceURL + " not " + r.Destination)
	}

	if r.Assertion.Subject.SubjectConfirmation.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
		return errors.New("assertion method exception")
	}

	if r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != s.SP.AssertionConsumerServiceURL {
		return errors.New("subject recipient mismatch, expected: " + s.SP.AssertionConsumerServiceURL + " not " + r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient)
	}

	err := packager.VerifyWithCert(r.originalString, s.IDPPublicCert())
	if err != nil {
		return err
	}

	//CHECK TIMES
	expires := r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter
	notOnOrAfter, e := time.Parse(time.RFC3339, expires)
	if e != nil {
		return e
	}
	if notOnOrAfter.Before(time.Now()) {
		return errors.New("assertion has expired on: " + expires)
	}

	return nil
}

//NewAuthnResponse get new signed response object
func NewAuthnResponse() *Response {
	id := util.ID()
	return &Response{
		XMLName: xml.Name{
			Local: "samlp:Response",
		},
		RootXML: &RootXML{
			SAMLP:        "urn:oasis:names:tc:SAML:2.0:protocol",
			SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
			SAMLSIG:      "http://www.w3.org/2000/09/xmldsig#",
			ID:           id,
			Version:      "2.0",
			IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
			Issuer: Issuer{
				XMLName: xml.Name{
					Local: "saml:Issuer",
				},
				URL: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
			},
			Signature: packager.GetSignatureEntity(id),
		},
		Status: Status{
			XMLName: xml.Name{
				Local: "samlp:Status",
			},
			StatusCode: StatusCode{
				XMLName: xml.Name{
					Local: "samlp:StatusCode",
				},
				// TODO unsuccesful responses??
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
		Assertion: Assertion{
			XMLName: xml.Name{
				Local: "saml:Assertion",
			},
			XS:           "http://www.w3.org/2001/XMLSchema",
			XSI:          "http://www.w3.org/2001/XMLSchema-instance",
			SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
			Version:      "2.0",
			ID:           util.ID(),
			IssueInstant: time.Now().UTC().Format(time.RFC3339Nano),
			Issuer: Issuer{
				XMLName: xml.Name{
					Local: "saml:Issuer",
				},
				URL: "", // caller must populate ar.AppSettings.AssertionConsumerServiceURL,
			},
			Subject: Subject{
				XMLName: xml.Name{
					Local: "saml:Subject",
				},
				NameID: NameID{
					XMLName: xml.Name{
						Local: "saml:NameID",
					},
					Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
					Value:  "",
				},
				SubjectConfirmation: SubjectConfirmation{
					XMLName: xml.Name{
						Local: "saml:SubjectConfirmation",
					},
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: SubjectConfirmationData{
						InResponseTo: "",
						NotOnOrAfter: time.Now().Add(time.Minute * 5).UTC().Format(time.RFC3339Nano),
						Recipient:    "",
					},
				},
			},
			Conditions: Conditions{
				XMLName: xml.Name{
					Local: "saml:Conditions",
				},
				NotBefore:    time.Now().Add(time.Minute * -5).UTC().Format(time.RFC3339Nano),
				NotOnOrAfter: time.Now().Add(time.Minute * 5).UTC().Format(time.RFC3339Nano),
			},
			AuthnStatement: AuthnStatement{
				XMLName: xml.Name{
					Local: "saml:AuthnStatement",
				},
				AuthnInstant: "",
				SessionIndex: "",
				AuthnContext: RequestedAuthnContext{
					XMLName: xml.Name{
						Local: "saml:AuthnContext",
					},
					AuthnContextClassRef: AuthnContextClassRef{
						XMLName: xml.Name{
							Local: "saml:AuthnContextClassRef",
						},
						Transport: "",
					},
				},
			},
			AttributeStatement: AttributeStatement{
				XMLName: xml.Name{
					Local: "saml:AttributeStatement",
				},
				Attributes: []Attribute{},
			},
		},
	}
}

//AddAttribute add strong attribute to the Response
func (r *Response) AddAttribute(name, value string) {
	r.Assertion.AttributeStatement.Attributes = append(r.Assertion.AttributeStatement.Attributes, Attribute{
		XMLName: xml.Name{
			Local: "saml:Attribute",
		},
		Name:       name,
		NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		AttributeValues: []AttributeValue{
			{
				XMLName: xml.Name{
					Local: "saml:AttributeValue",
				},
				Type:  "xs:string",
				Value: value,
			},
		},
	})
}

// GetAttribute by Name or by FriendlyName. Return blank string if not found
func (r *Response) GetAttribute(name string) string {
	for _, attr := range r.Assertion.AttributeStatement.Attributes {
		if attr.Name == name || attr.FriendlyName == name {
			return attr.AttributeValues[0].Value
		}
	}
	return ""
}

//GetAttributeValues from attribute name or FriendlyName. Return string slice of values.
func (r *Response) GetAttributeValues(name string) []string {
	var values []string
	for _, attr := range r.Assertion.AttributeStatement.Attributes {
		if attr.Name == name || attr.FriendlyName == name {
			for _, v := range attr.AttributeValues {
				values = append(values, v.Value)
			}
		}
	}
	return values
}

//String get string representation of response object
func (r *Response) String() (string, error) {
	return packager.String(r)
}

//SignedString get xml signed string representation of response object
func (r *Response) SignedString(s *Settings) (string, error) {
	xmldoc, err := r.String()
	if err != nil {
		return "", err
	}

	return packager.SignWithKey(xmldoc, s.SPPrivateKey())
}

//EncodedSignedString get base64 encoded and xml signed string representation of authentication response object
func (r *Response) EncodedSignedString(privateKeyPath string) (string, error) {
	return packager.EncodedSignedString(r, privateKeyPath)
}

//CompressedEncodedSignedString get compressed, base64 encoded and xml signed string representation of authentication response object
func (r *Response) CompressedEncodedSignedString(privateKeyPath string) (string, error) {
	return packager.CompressedEncodedSignedString(r, privateKeyPath)
}
