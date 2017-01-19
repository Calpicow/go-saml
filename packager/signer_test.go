package packager_test

import (
	"testing"

	"github.com/bmanth60/go-saml/packager"
	"github.com/stretchr/testify/assert"
)

func TestRequest(t *testing.T) {
	requestXML := `
	<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="_5a3267ae-5faf-4322-6bef-87c13a6bea5a" Version="2.0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://www.onelogin.net/acs" Destination="http://www.onelogin.net" IssueInstant="2017-01-17T19:05:24.15287472Z" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="0">
	    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://www.onelogin.net/metadata</saml:Issuer>
	    <samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>
	    <samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact">
	        <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
	    </samlp:RequestedAuthnContext>
	    <samlsig:Signature Id="Signature1">
	        <samlsig:SignedInfo xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#">
	            <samlsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	            <samlsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
	            <samlsig:Reference URI="#_5a3267ae-5faf-4322-6bef-87c13a6bea5a">
	                <samlsig:Transforms>
	                    <samlsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
	                </samlsig:Transforms>
	                <samlsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	                <samlsig:DigestValue></samlsig:DigestValue>
	            </samlsig:Reference>
	        </samlsig:SignedInfo>
	        <samlsig:SignatureValue></samlsig:SignatureValue>
	        <samlsig:KeyInfo>
	            <samlsig:X509Data>
	                <samlsig:X509Certificate></samlsig:X509Certificate>
	            </samlsig:X509Data>
	        </samlsig:KeyInfo>
	    </samlsig:Signature>
	</samlp:AuthnRequest>
	`

	signedXML, err := packager.Sign(requestXML, "/go/src/github.com/bmanth60/go-saml/certs/default.key")
	assert.NoError(t, err)
	assert.NotEmpty(t, signedXML)

	err = packager.Verify(signedXML, "/go/src/github.com/bmanth60/go-saml/certs/default.crt")
	assert.NoError(t, err)
}
