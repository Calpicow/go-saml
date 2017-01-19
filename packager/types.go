package packager

import "encoding/xml"

//Signature xml signature
type Signature struct {
	XMLName        xml.Name
	ID             string `xml:"Id,attr"`
	SignedInfo     SignedInfo
	SignatureValue SignatureValue
	KeyInfo        KeyInfo
}

//SignedInfo xml signature information
type SignedInfo struct {
	XMLName                xml.Name
	CanonicalizationMethod CanonicalizationMethod
	SignatureMethod        SignatureMethod
	SamlsigReference       SamlsigReference
}

//SignatureValue signature information data
type SignatureValue struct {
	XMLName xml.Name
	Value   string `xml:",innerxml"`
}

//KeyInfo key information for signature
type KeyInfo struct {
	XMLName  xml.Name
	X509Data X509Data `xml:",innerxml"`
}

//CanonicalizationMethod TODO needs description
type CanonicalizationMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

//SignatureMethod Algorithm for signature
type SignatureMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

//SamlsigReference TODO needs description
type SamlsigReference struct {
	XMLName      xml.Name
	URI          string       `xml:"URI,attr"`
	Transforms   Transforms   `xml:",innerxml"`
	DigestMethod DigestMethod `xml:",innerxml"`
	DigestValue  DigestValue  `xml:",innerxml"`
}

//X509Data X.509 formatted data
type X509Data struct {
	XMLName         xml.Name
	X509Certificate X509Certificate `xml:",innerxml"`
}

//Transforms set of transforms applied to signature
type Transforms struct {
	XMLName   xml.Name
	Transform Transform
}

//DigestMethod algorithm used to create signature digest
type DigestMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

//DigestValue resulting signature digest
type DigestValue struct {
	XMLName xml.Name
}

//X509Certificate X.509 formatted certificate
type X509Certificate struct {
	XMLName xml.Name
	Cert    string `xml:",innerxml"`
}

//Transform algorithm transform for signature
type Transform struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}
