package saml_test

import (
	"testing"

	"github.com/bmanth60/go-saml"
	"github.com/stretchr/testify/assert"
)

func TestCreateAuthnResponse(t *testing.T) {
	settings := GetStandardSettings()
	response := saml.NewAuthnResponse()
	response.ID = "id"
	response.IssueInstant = "statictime"
	response.Signature.SignedInfo.SamlsigReference.URI = "#id"
	response.Assertion.ID = "id"
	response.Assertion.IssueInstant = "statictime"
	response.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter = "statictime"
	response.Assertion.Conditions.NotBefore = "statictime"
	response.Assertion.Conditions.NotOnOrAfter = "statictime"

	xmldoc, err := response.SignedString(&settings)
	assert.NoError(t, err)

	expected := `
	<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="id" Version="2.0" Destination="" IssueInstant="statictime" InResponseTo="">
	    <saml:Issuer/>
	    <samlsig:Signature Id="Signature1">
	        <samlsig:SignedInfo xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#">
	            <samlsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	            <samlsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
	            <samlsig:Reference URI="#id">
	                <samlsig:Transforms>
	                    <samlsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
	                </samlsig:Transforms>
	                <samlsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	                <samlsig:DigestValue>uzLwpwqinaGv4P2LQByn4aXlgds=</samlsig:DigestValue>
	            </samlsig:Reference>
	        </samlsig:SignedInfo>
	        <samlsig:SignatureValue>y4Zwk1esRbhFYOLICZanZ1W8eiq79gXDtHMqByEiOG7oHlgL0CREh0ynl0AlGOdx16nbeZ6dfAY58ZAPvhT4BMfQgtXT81Im0Of/kFv0EoAoo8q4xaK8XxahoX4f+jxyYlNH070N2nsDWBJIScIU2Iqu+kUd3+FZYPqIWXtq4MpxrMv8MP54PUAYp/IFVGkbogHQCWTCL1UikLE7bAtE7RXFTDINy/tNYgaILT1YLVY8CrnryF5xw/xN+WDdWv5rcO2p2VqGbAUiXcMT7XRTmu6dZCjzLdgy63xd+0s3oqyKYJkx52ZbYJJ9vMt01VDzIAWNofIxsYv7MgyUnKLvaISSL+hVCVOcYR75keAQ7lXLAfgDR433qlu2tNCN4jz3Io0p72dYXbsD1GWAtPtzw8mc2ekDnd+tXQeHe/mztajJMZmwP7bcmJvmYwXfdmpmg+zGmb91Jy42UgIwpivsviHT1WFRgGJeesOHCS/zGYtP05rUiVXa6xe0RZPdxkJMC4WBybehL2u/SwUuTB69hNOcbprp6RxI3uIIVIAR5wmDX+suRq9Za5XiLs5FnnwNXugS6pGl3P5zVjCO3RFkCeH3N1Apy8oajXmni1oSMdMWzQEWYByi2tu9+QjRe8jFoJgcWjvt3Cn2Grar/N1d/WlA0Y1yYvQxiR6SpjlWv2Y=</samlsig:SignatureValue>
	        <samlsig:KeyInfo>
	            <samlsig:X509Data>
	                <samlsig:X509Certificate/>
	            </samlsig:X509Data>
	        </samlsig:KeyInfo>
	    </samlsig:Signature>
	    <saml:Assertion ID="id" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" saml="urn:oasis:names:tc:SAML:2.0:assertion" IssueInstant="statictime">
	        <saml:Issuer/>
	        <Signature Id="">
	            <SignedInfo>
	                <CanonicalizationMethod Algorithm=""/>
	                <SignatureMethod Algorithm=""/>
	                <SamlsigReference URI="">
	                    <Transforms>
	                        <Transform Algorithm=""/>
	                    </Transforms>
	                    <DigestMethod Algorithm=""/>
	                    <DigestValue/>
	                </SamlsigReference>
	            </SignedInfo>
	            <SignatureValue/>
	            <KeyInfo>
	                <X509Data>
	                    <X509Certificate/>
	                </X509Data>
	            </KeyInfo>
	        </Signature>
	        <saml:Subject>
	            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"/>
	            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
	                <SubjectConfirmationData InResponseTo="" NotOnOrAfter="statictime" Recipient=""/>
	            </saml:SubjectConfirmation>
	        </saml:Subject>
	        <saml:Conditions NotBefore="statictime" NotOnOrAfter="statictime"/>
	        <saml:AttributeStatement/>
	        <saml:AuthnStatement AuthnInstant="">
	            <saml:AuthnContext Comparison="">
	                <saml:AuthnContextClassRef/>
	            </saml:AuthnContext>
	        </saml:AuthnStatement>
	    </saml:Assertion>
	    <samlp:Status>
	        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
	    </samlp:Status>
	</samlp:Response>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(xmldoc))
}
