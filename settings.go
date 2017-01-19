package saml

import (
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
)

//Settings to configure saml properties for
//one idp and/or one sp.
//If you need to configure multipe IDPs for an SP
//then configure multiple instances of this object
type Settings struct {
	SP       ServiceProviderSettings
	IDP      IdentityProviderSettings
	Compress CompressionSettings

	hasInit bool
}

//CompressionSettings to determine if requests and responses should be compressed
type CompressionSettings struct {
	Request  bool
	Response bool
}

//ServiceProviderSettings provides settings to configure server acting as a SAML Service Provider.
//Expect only one IDP per SP in this configuration.
type ServiceProviderSettings struct {
	EntityID                    string
	PublicCertPath              string
	PublicCertString            string
	PrivateKeyPath              string
	PrivateKeyString            string
	AssertionConsumerServiceURL string
	SingleLogoutServiceURL      string
	SignRequest                 bool

	publicCert *pem.Block
	privateKey *pem.Block
}

//IdentityProviderSettings to configure idp specific settings
type IdentityProviderSettings struct {
	SingleLogoutURL           string
	SingleSignOnURL           string
	SingleSignOnDescriptorURL string
	PublicCertPath            string
	PublicCertString          string
	NameIDFormat              string

	publicCert *pem.Block
}

//Init settings and load configuration files as needed
//This will panic on error as SP/IDP fails to load
func (s *Settings) Init() (err error) {
	if s.hasInit {
		return nil
	}
	s.hasInit = true

	if s.SP.SignRequest {
		s.SP.privateKey = s.loadPEM("SP-Pivate Key", s.SP.PrivateKeyString, s.SP.PrivateKeyPath)
		s.SP.publicCert = s.loadPEM("SP-Public Cert", s.SP.PublicCertString, s.SP.PublicCertPath)
		s.IDP.publicCert = s.loadPEM("IDP-Public Cert", s.IDP.PublicCertString, s.IDP.PublicCertPath)
	} else {
		s.SP.privateKey = &pem.Block{}
		s.SP.publicCert = &pem.Block{}
		s.SP.publicCert = &pem.Block{}
	}

	//Set the sp entity id to acs url if not found for
	//backwards compatibility with old configuration
	if s.SP.EntityID == "" && s.SP.AssertionConsumerServiceURL != "" {
		s.SP.EntityID = s.SP.AssertionConsumerServiceURL
	}

	return nil
}

func (s *Settings) loadPEM(pemType string, pemString string, pemPath string) *pem.Block {
	var block *pem.Block
	if pemString != "" {
		block, _ = pem.Decode([]byte(pemString))
	} else {
		block = readPEMFile(pemPath)
	}

	if block == nil {
		panic("Unable to load PEM: " + pemType)
	}

	return block
}

func readPEMFile(path string) *pem.Block {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(bytes)
	return block
}

//SPPublicCert get loaded sp public certificate data
func (s *Settings) SPPublicCert() string {
	if !s.hasInit {
		s.Init()
	}
	return base64.StdEncoding.EncodeToString(s.SP.publicCert.Bytes)
}

//SPPrivateKey get loaded sp private key in pem format
func (s *Settings) SPPrivateKey() string {
	if !s.hasInit {
		s.Init()
	}
	return string(pem.EncodeToMemory(s.SP.privateKey))
}

//IDPPublicCert get loaded idp public certificate in pem format
func (s *Settings) IDPPublicCert() string {
	if !s.hasInit {
		s.Init()
	}
	return string(pem.EncodeToMemory(s.IDP.publicCert))
}
