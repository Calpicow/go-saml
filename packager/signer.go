package packager

import (
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"io/ioutil"

	"github.com/ma314smith/signedxml"
)

//GetKeyInfoEntity for specified namespace
func GetKeyInfoEntity(namespace string) KeyInfo {
	return KeyInfo{
		XMLName: xml.Name{
			Local: namespace + ":KeyInfo",
		},
		X509Data: X509Data{
			XMLName: xml.Name{
				Local: namespace + ":X509Data",
			},
			X509Certificate: X509Certificate{
				XMLName: xml.Name{
					Local: namespace + ":X509Certificate",
				},
				Cert: "", // caller must populate cert,
			},
		},
	}
}

//GetSignatureEntity get an xml signature entity
func GetSignatureEntity(id string) *Signature {
	return &Signature{
		XMLName: xml.Name{
			Local: "samlsig:Signature",
		},
		ID: "Signature1",
		SignedInfo: SignedInfo{
			XMLName: xml.Name{
				Local: "samlsig:SignedInfo",
			},
			CanonicalizationMethod: CanonicalizationMethod{
				XMLName: xml.Name{
					Local: "samlsig:CanonicalizationMethod",
				},
				Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
			},
			SignatureMethod: SignatureMethod{
				XMLName: xml.Name{
					Local: "samlsig:SignatureMethod",
				},
				Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
			},
			SamlsigReference: SamlsigReference{
				XMLName: xml.Name{
					Local: "samlsig:Reference",
				},
				URI: "#" + id,
				Transforms: Transforms{
					XMLName: xml.Name{
						Local: "samlsig:Transforms",
					},
					Transform: Transform{
						XMLName: xml.Name{
							Local: "samlsig:Transform",
						},
						Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
					},
				},
				DigestMethod: DigestMethod{
					XMLName: xml.Name{
						Local: "samlsig:DigestMethod",
					},
					Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
				},
				DigestValue: DigestValue{
					XMLName: xml.Name{
						Local: "samlsig:DigestValue",
					},
				},
			},
		},
		SignatureValue: SignatureValue{
			XMLName: xml.Name{
				Local: "samlsig:SignatureValue",
			},
		},
		KeyInfo: GetKeyInfoEntity("samlsig"),
	}
}

//Sign creates a signature for an XML document and returns it
func Sign(xml string, privateKeyPath string) (string, error) {
	pemString, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return "", err
	}
	return SignWithKey(xml, string(pemString))
}

//SignWithKey create signature for xml document using pem formatted
//string representing x509 key. Returns signed xml document.
func SignWithKey(xml string, pemKey string) (string, error) {
	pemBlock, _ := pem.Decode([]byte(pemKey))
	if pemBlock == nil {
		return "", errors.New("Could not parse private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return "", err
	}

	signer, err := signedxml.NewSigner(xml)
	if err != nil {
		return "", err
	}

	samlSignedRequestXML, err := signer.Sign(key)
	if err != nil {
		return "", err
	}

	return samlSignedRequestXML, nil
}

//Verify validates the signature of an XML document
func Verify(xml string, publicCertPath string) error {
	pemString, err := ioutil.ReadFile(publicCertPath)
	if err != nil {
		return err
	}

	return VerifyWithCert(xml, string(pemString))
}

//VerifyWithCert validate xml document using pem formatted string
func VerifyWithCert(xml string, certPem string) error {
	pemBlock, _ := pem.Decode([]byte(certPem))
	if pemBlock == nil {
		return errors.New("Could not parse certificate")
	}

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return err
	}

	validator, err := signedxml.NewValidator(xml)
	if err != nil {
		return err
	}

	validator.Certificates = append(validator.Certificates, *cert)

	err = validator.Validate()
	if err != nil {
		return err
	}
	return nil
}
