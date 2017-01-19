package saml

//This class contains types modeled after the elements found in the
//SAML 2.0 specifications. More details can be found:
//http://docs.oasis-open.org/security/saml/v2.0/sstc-saml-approved-errata-2.0.html

import (
	"encoding/xml"

	"github.com/bmanth60/go-saml/packager"
)

//AuthnRequest saml authentication request
type AuthnRequest struct {
	*RootXML

	XMLName                        xml.Name
	ProtocolBinding                string                 `xml:"ProtocolBinding,attr"`
	AssertionConsumerServiceURL    string                 `xml:"AssertionConsumerServiceURL,attr"`
	AssertionConsumerServiceIndex  int                    `xml:"AssertionConsumerServiceIndex,attr"`
	AttributeConsumingServiceIndex int                    `xml:"AttributeConsumingServiceIndex,attr"`
	NameIDPolicy                   NameIDPolicy           `xml:"NameIDPolicy"`
	RequestedAuthnContext          *RequestedAuthnContext `xml:"RequestedAuthnContext,omitempty"`
}

//Issuer request issuer
type Issuer struct {
	XMLName xml.Name
	SAML    string `xml:"xmlns:saml,attr,omitempty"`
	URL     string `xml:",innerxml"`
}

//NameIDPolicy policy for saml nameid
type NameIDPolicy struct {
	XMLName     xml.Name
	AllowCreate bool   `xml:"AllowCreate,attr"`
	Format      string `xml:"Format,attr"`
}

//RequestedAuthnContext requested authentication context
type RequestedAuthnContext struct {
	XMLName              xml.Name
	SAMLP                string               `xml:"xmlns:samlp,attr,omitempty"`
	Comparison           string               `xml:"Comparison,attr"`
	AuthnContextClassRef AuthnContextClassRef `xml:"AuthnContextClassRef"`
}

//AuthnContextClassRef authentication context to use for saml interaction
type AuthnContextClassRef struct {
	XMLName   xml.Name
	SAML      string `xml:"xmlns:saml,attr,omitempty"`
	Transport string `xml:",innerxml"`
}

//EntityDescriptor saml metadata descriptor
type EntityDescriptor struct {
	XMLName  xml.Name
	DS       string `xml:"xmlns:ds,attr"`
	XMLNS    string `xml:"xmlns,attr"`
	MD       string `xml:"xmlns:md,attr"`
	EntityID string `xml:"entityID,attr"`

	Extensions      Extensions      `xml:"Extensions"`
	SPSSODescriptor SPSSODescriptor `xml:"SPSSODescriptor"`
}

//Extensions TODO needs description
type Extensions struct {
	XMLName xml.Name
	Alg     string `xml:"xmlns:alg,attr"`
	MDAttr  string `xml:"xmlns:mdattr,attr"`
	MDRPI   string `xml:"xmlns:mdrpi,attr"`

	EntityAttributes string `xml:"EntityAttributes"`
}

//SPSSODescriptor TODO needs description
type SPSSODescriptor struct {
	XMLName                    xml.Name
	AuthnRequestsSigned        bool   `xml:",attr"`
	WantAssertionsSigned       bool   `xml:"wantAssertionsSigned,attr"`
	ProtocolSupportEnumeration string `xml:"protocolSupportEnumeration,attr"`
	SigningKeyDescriptor       KeyDescriptor
	EncryptionKeyDescriptor    KeyDescriptor
	SingleLogoutService        SingleLogoutService `xml:"SingleLogoutService"`
	AssertionConsumerServices  []AssertionConsumerService
}

//EntityAttributes TODO needs description
type EntityAttributes struct {
	XMLName          xml.Name
	SAML             string      `xml:"xmlns:saml,attr"`
	EntityAttributes []Attribute `xml:"Attribute"` // should be array??
}

//KeyDescriptor TODO needs description
type KeyDescriptor struct {
	XMLName xml.Name
	Use     string           `xml:"use,attr"`
	KeyInfo packager.KeyInfo `xml:"KeyInfo"`
}

//SingleLogoutService logout service metadata
type SingleLogoutService struct {
	XMLName  xml.Name
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

//AssertionConsumerService sso assertion metadata
type AssertionConsumerService struct {
	XMLName  xml.Name
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    string `xml:"index,attr"`
}

//Response saml responses
type Response struct {
	*RootXML

	XMLName      xml.Name
	InResponseTo string    `xml:"InResponseTo,attr"`
	Assertion    Assertion `xml:"Assertion"`
	Status       Status    `xml:"Status"`
}

//Assertion saml response assertion information
type Assertion struct {
	XMLName            xml.Name
	ID                 string `xml:"ID,attr"`
	Version            string `xml:"Version,attr"`
	XS                 string `xml:"xmlns:xs,attr"`
	XSI                string `xml:"xmlns:xsi,attr"`
	SAML               string `xml:"saml,attr"`
	IssueInstant       string `xml:"IssueInstant,attr"`
	Issuer             Issuer `xml:"Issuer"`
	Signature          packager.Signature
	Subject            Subject
	Conditions         Conditions
	AttributeStatement AttributeStatement
	AuthnStatement     AuthnStatement `xml:"AuthnStatement,omitempty"`
}

//Conditions of assertion
type Conditions struct {
	XMLName      xml.Name
	NotBefore    string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
}

//Subject of assertion
type Subject struct {
	XMLName             xml.Name
	NameID              NameID
	SubjectConfirmation SubjectConfirmation
}

//SubjectConfirmation TODO needs description
type SubjectConfirmation struct {
	XMLName                 xml.Name
	Method                  string `xml:",attr"`
	SubjectConfirmationData SubjectConfirmationData
}

//Status of response
type Status struct {
	XMLName    xml.Name
	StatusCode StatusCode `xml:"StatusCode"`
}

//SubjectConfirmationData TODO needs description
type SubjectConfirmationData struct {
	InResponseTo string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
	Recipient    string `xml:",attr"`
}

//NameID information
type NameID struct {
	XMLName xml.Name
	Format  string `xml:",attr"`
	Value   string `xml:",innerxml"`
}

//StatusCode TODO needs description
type StatusCode struct {
	XMLName xml.Name
	Value   string `xml:",attr"`
}

//AttributeValue of subject attribute
type AttributeValue struct {
	XMLName xml.Name
	Type    string `xml:"xsi:type,attr"`
	Value   string `xml:",innerxml"`
}

//Attribute of subject
type Attribute struct {
	XMLName         xml.Name
	Name            string           `xml:",attr"`
	FriendlyName    string           `xml:",attr"`
	NameFormat      string           `xml:",attr"`
	AttributeValues []AttributeValue `xml:"AttributeValue"`
}

//AttributeStatement TODO needs description
type AttributeStatement struct {
	XMLName    xml.Name
	Attributes []Attribute `xml:"Attribute"`
}

//AuthnStatement statement for session information
type AuthnStatement struct {
	XMLName             xml.Name
	AuthnInstant        string                `xml:",attr"`
	SessionIndex        string                `xml:",attr,omitempty"`
	SessionNotOnOrAfter string                `xml:",attr,omitempty"`
	AuthnContext        RequestedAuthnContext `xml:"AuthnContext"`
}

//RootXML saml root xml data
//Although all root xml elements have XMLName, it is not
//marshalled properly without explicit addition to the type
type RootXML struct {
	SAMLP          string              `xml:"xmlns:samlp,attr"`
	SAML           string              `xml:"xmlns:saml,attr"`
	SAMLSIG        string              `xml:"xmlns:samlsig,attr,omitempty"`
	ID             string              `xml:"ID,attr"`
	Version        string              `xml:"Version,attr"`
	Destination    string              `xml:"Destination,attr"`
	IssueInstant   string              `xml:"IssueInstant,attr"`
	Issuer         Issuer              `xml:"Issuer"`
	Signature      *packager.Signature `xml:"Signature,omitempty"`
	originalString string
}

//LogoutRequest saml logout request
type LogoutRequest struct {
	*RootXML

	XMLName      xml.Name
	NameID       NameID       `xml:"NameID"`
	SessionIndex SessionIndex `xml:",omitempty"`
}

//SessionIndex request session information
type SessionIndex struct {
	XMLName xml.Name
	Value   string `xml:",innerxml"`
}
