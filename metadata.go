package saml

import (
	"encoding/xml"
	"fmt"

	"github.com/bmanth60/go-saml/packager"
)

//GetEntityDescriptor get saml entity metadata XML as specified by
//http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml1x-metadata-cs-01.html
func (s *Settings) GetEntityDescriptor() (string, error) {
	d := EntityDescriptor{
		XMLName: xml.Name{
			Local: "md:EntityDescriptor",
		},
		DS:       "http://www.w3.org/2000/09/xmldsig#",
		XMLNS:    "urn:oasis:names:tc:SAML:2.0:metadata",
		MD:       "urn:oasis:names:tc:SAML:2.0:metadata",
		EntityID: s.SP.EntityID,

		Extensions: Extensions{
			XMLName: xml.Name{
				Local: "md:Extensions",
			},
			Alg:    "urn:oasis:names:tc:SAML:metadata:algsupport",
			MDAttr: "urn:oasis:names:tc:SAML:metadata:attribute",
			MDRPI:  "urn:oasis:names:tc:SAML:metadata:rpi",
		},
		SPSSODescriptor: SPSSODescriptor{
			AuthnRequestsSigned:        s.SP.SignRequest,
			WantAssertionsSigned:       s.SP.SignRequest,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			SigningKeyDescriptor: KeyDescriptor{
				XMLName: xml.Name{
					Local: "md:KeyDescriptor",
				},

				Use:     "signing",
				KeyInfo: packager.GetKeyInfoEntity("ds"),
			},
			EncryptionKeyDescriptor: KeyDescriptor{
				XMLName: xml.Name{
					Local: "md:KeyDescriptor",
				},

				Use:     "encryption",
				KeyInfo: packager.GetKeyInfoEntity("ds"),
			},
			SingleLogoutService: SingleLogoutService{
				XMLName: xml.Name{
					Local: "md:SingleLogoutService",
				},
				Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
				Location: s.SP.SingleLogoutServiceURL,
			},
			AssertionConsumerServices: []AssertionConsumerService{
				{
					XMLName: xml.Name{
						Local: "md:AssertionConsumerService",
					},
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: s.SP.AssertionConsumerServiceURL,
					Index:    "0",
				},
				{
					XMLName: xml.Name{
						Local: "md:AssertionConsumerService",
					},
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
					Location: s.SP.AssertionConsumerServiceURL,
					Index:    "1",
				},
			},
		},
	}

	d.SPSSODescriptor.SigningKeyDescriptor.KeyInfo.X509Data.X509Certificate.Cert = s.SPPublicCert()
	d.SPSSODescriptor.EncryptionKeyDescriptor.KeyInfo.X509Data.X509Certificate.Cert = s.SPPublicCert()

	metaxml, err := packager.String(d)
	if err != nil {
		return "", err
	}

	metadata := fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?>\n%s", metaxml)
	return metadata, nil
}
