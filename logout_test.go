package saml_test

import (
	"testing"

	"github.com/bmanth60/go-saml"
	"github.com/stretchr/testify/assert"
)

func TestApplyLogoutRequest(t *testing.T) {
	settings := GetStandardSettings()
	request := saml.ApplyLogoutRequest(&settings, saml.NewLogoutRequest(), "nameid", "sessionindex")
	request.ID = "id"
	request.IssueInstant = "statictime"
	request.Signature.SignedInfo.SamlsigReference.URI = "#id"

	result, err := request.SignedString(&settings)
	assert.NoError(t, err)

	expected := `
	<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="id" Version="2.0" Destination="http://www.onelogin.net" IssueInstant="statictime">
	    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://localhost:8000/auth/saml/metadata</saml:Issuer>
	    <samlsig:Signature Id="Signature1">
	        <samlsig:SignedInfo xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#">
	            <samlsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	            <samlsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
	            <samlsig:Reference URI="#id">
	                <samlsig:Transforms>
	                    <samlsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
	                </samlsig:Transforms>
	                <samlsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	                <samlsig:DigestValue>sP4dVEOzrRSZy7LwHt30lPzfGd4=</samlsig:DigestValue>
	            </samlsig:Reference>
	        </samlsig:SignedInfo>
	        <samlsig:SignatureValue>Z74GrXeQhaOToYwQM0Lw4wx0SH2+hXGYop8F0e5cUeUGkHgrGLlBub+JjPVF8BqFU3B+QZI29ZZHGOtKVwKRgV2vX/fCMdAsdXUuhMPowlouTZCJXz28k6WR7aqSAKyjDDE7TNuuZJX+cz9TNIs4MQasyUtEXbt5KCitO7Ci4SUTgIf51aUpaV6b3WCWfulpNz74Q5LqwWjU5BR752ekYP5MDecvoxg8QozAe217ZJIhj4L1+W76hhU7rtBTpZLGtS4TKBRd/1+Lpu/7IL7OYRBrQVeTJw22ja4walIwgwygh1BwPspEtxhxecfmHP4DKj+cY5vAPTY0b7c0oY/6OwsAliXQJLrbDA9XB2+zNdMN1EHo5PJ8qzX/IlX0OW7w0xN76OcvDIi/ZChvdfpclCEnjpCA5JYGUzrjwacUFJHvqc1ZBq3khMeUqBKxhACfhxBQ/40tia9beZ9hRHLXMhRYrMrgr6+lCDpbm4Gf0xv7YuLVplfehW2Ssc/6Hhbs/PZtzBjYPfLssxFFZB7BTcld4GqduydZPwhVhEXlrLu1zfxJ/MxC/vw+OBlFmUN9cPTIWU3NLa27jtHmodr8cQCTtlsretfbSsFJk8PWUwIAjmS8ELuH4hPVppbexM1mms+tA77kjLwd8KHF7ja4IHIr/28ZTtFDEoAO2JRzwyU=</samlsig:SignatureValue>
	        <samlsig:KeyInfo>
	            <samlsig:X509Data>
	                <samlsig:X509Certificate>MIIFYTCCA0mgAwIBAgIJAI1a1evtQYDkMA0GCSqGSIb3DQEBBQUAME8xCzAJBgNVBAYTAkZSMQ4wDAYDVQQHEwVQYXJpczEOMAwGA1UEChMFRWtpbm8xDzANBgNVBAsTBkRldk9wczEPMA0GA1UEAxMGZ29zYW1sMB4XDTE1MDcyMDIyNDE1OFoXDTI1MDcxNzIyNDE1OFowTzELMAkGA1UEBhMCRlIxDjAMBgNVBAcTBVBhcmlzMQ4wDAYDVQQKEwVFa2lubzEPMA0GA1UECxMGRGV2T3BzMQ8wDQYDVQQDEwZnb3NhbWwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDoo/DTqWoyJyXR0K+hF4pw4qBkaLL0gbbKoiKH+7wvdzHONOoFBfF5NQj02M4JJyeOQ6+hHYV4QjtUG41zMf1XoH/U6Ey/oURkuCJJCGhW9AyD+A4WP4YS4Ag/uN7o0P3nuj7hJipefY1Bzmg2n89iHDcpHvwKTtVWZYdj6Dgbwh9ZH9QiRRRp+GZHXu7nW+VCZM0mE+9qjxK4Mw+KEDD6LIgSOAzRLWLyUmb2Kwvc++DhwDtIoThVHYoNd4Sk9j6/4B3DmPa83i/1dZKyFaMCDUn7+i6KhwIWbGfg6uQMM8G6XzF4V5x5agmg8DK24VXs3yb1lOIUczNVq4ZHkApc4jwHWiXncab88UnDPG7pVm87whaMghWNwrYAt//QEInExkxjNhWwxNFlelg/8b9fUsdH58FeZiZ+mNnwACXnggmZEE+lUX5Fh8l79bke+dnQbJAhQfi+OhmNlqmc+ouKDPYqk0/IC9q/3Tg65Ej9Miq918IAvQAVtlwwwp6I5/02Aa5iqZozBTUXYqWE/qXixlpWh2tP5ljecgGazuw58tGj2+nXS9DA9wVgGUAl4xJFO/s8emna52lSPzwvcr6j+BMifXHr0WBIEcTbtzXhxUpfC6IC14yfPOf8g4WKKgg1Wq3H4dGiE11y66ceYeh1RZlWXq/JEtJ1FVLoGq4qLwIDAQABo0AwPjA8BgNVHREENTAzghBsb2dzLmV4YW1wbGUuY29tghNtZXRyaWNzLmV4YW1wbGUuY29thwTAqAABhwQKAAAyMA0GCSqGSIb3DQEBBQUAA4ICAQAcaLdziL6dNZ3lXtm3nsI9ceSVwp2yKfpsswjs524bOsLK97Ucf4hhlh1bq5hywWbm85N7iuxdpBuhSmeJ94ryFAPDUkhR1Mzcl48c6R8tPbJVhabhbfg+uIHi4BYUA0olesdsyTOsRHprM4iV+PlKZ85SQT04ZNyaqIDzmNEP7YXDl/Wl3Q0N5E1UyGfDTBxo07srqrAM2E5X7hN9bwdZX0Hbo/C4q3wgRHAts/wJXXWSSTe1jbIWYXemEkwAEd01BiMBj1LYK/sJ8s4fONdLxIyKqLUh1Ja46moqpgl5AHuPbqnwPdgGGvEdiBzz5ppHs0wXFopk+J4rzYRhya6a3BMXiDjg+YOSwFgCysmWmCrxoImmfcQWUZJy5eMow+hBBiKgT2DxggqVzReN3C7uwsFZLZCsv8+MjvFQz52oEp/GWqFepggFQiRIK7/QmwcsDdz6zBobZJaJstq3R2mHYkhaVUIOqEuqyD2N7qms8bek7xzq6F9KkYLkPK/d2Crkxq1bnvM7oO8IsA6vHdTexfZ1SRPf7Mxpg8DMV788qE09BDZ5mLFOkRbwFY7MHRX6Mz59gfnAcRwK/0HnG6c8EZCJH8jMStzqA0bUjzDiyN2ZgzFkTUA9Cr8jkq8grtVMsp40mjFnSg/FR+O+rG32D/rbfvNYFCR8wawOcYrGyA==</samlsig:X509Certificate>
	            </samlsig:X509Data>
	        </samlsig:KeyInfo>
	    </samlsig:Signature>
	    <saml:NameID Format="">nameid</saml:NameID>
	    <samlp:SessionIndex>sessionindex</samlp:SessionIndex>
	</samlp:LogoutRequest>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(result))
}

func TestCreateLogoutResponse(t *testing.T) {
	settings := GetStandardSettings()
	response := saml.NewLogoutResponse()
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
	<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="id" Version="2.0" Destination="" IssueInstant="statictime" InResponseTo="">
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
	                <samlsig:DigestValue>pAh0rZ03A+eIpLnpDZ5cCR6iHaM=</samlsig:DigestValue>
	            </samlsig:Reference>
	        </samlsig:SignedInfo>
	        <samlsig:SignatureValue>Iff10xa2FYGDY65C3KLHoL2eAD2/ZsioCDCT2UQNQ2XdULyLFA0ERbbpaac/GuHK/KRzHvuhZIZIr5Oj90ZUCoQsCnAgTGxhGrFcetqBkQbn9ROqGzXJ6Iuc+4kYASiU01ciEkKBYHxsVMbN7hCD84wuTdWGhd/dJVb7tKR0Dode6AxL6lMgtR5HUUdSNA7/VRss682mGjFWrBWMD0MJJBJheHHA4ZKBIN4AVmTqh/UBNyFlmhbCPRpSvhYOq8NIyljrTHSyFZpbohgfeBjPOLkgN8Nhe8IEVYK9Mw6WDjA7szFWRSZfeQuXS4KlvdsoU6xk058aXkMxSHauVj3q5Kg9FUA9VjBn7w9GI494GiS9M52OxrVcc/ZOnRYBRvLi57DAp04R0CAhUmqHRBKkCjbq80A61CtBabgOBel2g16uija11jR96NI7utI7g9qCz/booX/Nn9CTSj/AIVOS8oiwcIuIwe1VnbTwzgvAnYBHiwdsrin/wpU/P96y1h7M4mU05ugZH5M0iwx25G3dJZqIBolXkBsFsx8f7q/4Hb7FH377ybRljpkLYFqh4WJqHV4whxFmCdJm6m1iI7bddT6Y3C7VXlm4UlXY6ddauQAor2pEwEf6skjM04TRv5xFY8tOg5zBp5y1wX6T+Fih4VTNn0A0EKGVWFcIXcNpmhU=</samlsig:SignatureValue>
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
	</samlp:LogoutResponse>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(xmldoc))
}
