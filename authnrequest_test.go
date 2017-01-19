package saml_test

import (
	"testing"

	"github.com/bmanth60/go-saml"
	"github.com/stretchr/testify/assert"
)

func TestGetSignedRequest(t *testing.T) {
	settings := GetStandardSettings()
	err := settings.Init()
	assert.NoError(t, err)

	// Construct an AuthnRequest
	request := saml.ApplyAuthnRequest(settings, saml.NewAuthnRequest())
	request.ID = "id"
	request.IssueInstant = "statictime"
	request.Signature.SignedInfo.SamlsigReference.URI = "#id"

	result, err := request.SignedString(&settings)
	assert.NoError(t, err)

	expected := `
	<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="id" Version="2.0" Destination="http://www.onelogin.net" IssueInstant="statictime" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://localhost:8000/auth/saml/acs" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="0">
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
	                <samlsig:DigestValue>KQMUHM48EjYwMvpv9DYeGUPAUZE=</samlsig:DigestValue>
	            </samlsig:Reference>
	        </samlsig:SignedInfo>
	        <samlsig:SignatureValue>B22PuLWyczmPJ/tb6Fu+P5eplz5tIj+XIHl2Kkrv1rpB28mSCCEhANWs8Vehp436DVkgodVdfkreZeQ13JxMg1j2AZoDrckfYXVdgxIeGktAJc7ABM3uKwoSN5pbA/gii79Gp4jDSK+X/gP+kqnXoj7c2088UUj7tuMxBL9E8zsOW86SC66q8KwCFO5W1GMJ/Hj3OmeJuh99e7IXIXsOfXPiieI+4FWkp65Bgh3N049Bpdc88DSiML1myyyuZEsgbI9m/SV4W2uFGoGtJJAldCIiiDFn9uew//gT2xkGJwDkscK5QA/LqRBO3PFvuI5Zk03TvgJASBR8l7/X1Pg/tyLV+xEQghSjFOzvm58KkwfZGK5Wphza6r6h3l7c+CdQu7u+3DWzMO8pueUWVgoqiAiHmjm6nBOlrVOB0EqxWnnCNgoZAKr74N+03OdYxrFzIb3zhMoiafoZme4xKvYmGvuEs4DchGwCkL0eNEU4WVUwcnlwerMHyOlzulkN1xZtqbkzgrPRjttBCb6BV9LpENuyB7oIKFdS64XmATMofF97KSL+x3VdEazmxQhEsMY7kycBtj+OctK7sgpvP4AINB1ZVdJvomYmUWgTvOFvSzraW8XN+gNVvTPuTO708wLkPfsZwWCXdnMIF5T7AiPsOkJX4bJmz0swSef1g0QOvho=</samlsig:SignatureValue>
	        <samlsig:KeyInfo>
	            <samlsig:X509Data>
	                <samlsig:X509Certificate>MIIFYTCCA0mgAwIBAgIJAI1a1evtQYDkMA0GCSqGSIb3DQEBBQUAME8xCzAJBgNVBAYTAkZSMQ4wDAYDVQQHEwVQYXJpczEOMAwGA1UEChMFRWtpbm8xDzANBgNVBAsTBkRldk9wczEPMA0GA1UEAxMGZ29zYW1sMB4XDTE1MDcyMDIyNDE1OFoXDTI1MDcxNzIyNDE1OFowTzELMAkGA1UEBhMCRlIxDjAMBgNVBAcTBVBhcmlzMQ4wDAYDVQQKEwVFa2lubzEPMA0GA1UECxMGRGV2T3BzMQ8wDQYDVQQDEwZnb3NhbWwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDoo/DTqWoyJyXR0K+hF4pw4qBkaLL0gbbKoiKH+7wvdzHONOoFBfF5NQj02M4JJyeOQ6+hHYV4QjtUG41zMf1XoH/U6Ey/oURkuCJJCGhW9AyD+A4WP4YS4Ag/uN7o0P3nuj7hJipefY1Bzmg2n89iHDcpHvwKTtVWZYdj6Dgbwh9ZH9QiRRRp+GZHXu7nW+VCZM0mE+9qjxK4Mw+KEDD6LIgSOAzRLWLyUmb2Kwvc++DhwDtIoThVHYoNd4Sk9j6/4B3DmPa83i/1dZKyFaMCDUn7+i6KhwIWbGfg6uQMM8G6XzF4V5x5agmg8DK24VXs3yb1lOIUczNVq4ZHkApc4jwHWiXncab88UnDPG7pVm87whaMghWNwrYAt//QEInExkxjNhWwxNFlelg/8b9fUsdH58FeZiZ+mNnwACXnggmZEE+lUX5Fh8l79bke+dnQbJAhQfi+OhmNlqmc+ouKDPYqk0/IC9q/3Tg65Ej9Miq918IAvQAVtlwwwp6I5/02Aa5iqZozBTUXYqWE/qXixlpWh2tP5ljecgGazuw58tGj2+nXS9DA9wVgGUAl4xJFO/s8emna52lSPzwvcr6j+BMifXHr0WBIEcTbtzXhxUpfC6IC14yfPOf8g4WKKgg1Wq3H4dGiE11y66ceYeh1RZlWXq/JEtJ1FVLoGq4qLwIDAQABo0AwPjA8BgNVHREENTAzghBsb2dzLmV4YW1wbGUuY29tghNtZXRyaWNzLmV4YW1wbGUuY29thwTAqAABhwQKAAAyMA0GCSqGSIb3DQEBBQUAA4ICAQAcaLdziL6dNZ3lXtm3nsI9ceSVwp2yKfpsswjs524bOsLK97Ucf4hhlh1bq5hywWbm85N7iuxdpBuhSmeJ94ryFAPDUkhR1Mzcl48c6R8tPbJVhabhbfg+uIHi4BYUA0olesdsyTOsRHprM4iV+PlKZ85SQT04ZNyaqIDzmNEP7YXDl/Wl3Q0N5E1UyGfDTBxo07srqrAM2E5X7hN9bwdZX0Hbo/C4q3wgRHAts/wJXXWSSTe1jbIWYXemEkwAEd01BiMBj1LYK/sJ8s4fONdLxIyKqLUh1Ja46moqpgl5AHuPbqnwPdgGGvEdiBzz5ppHs0wXFopk+J4rzYRhya6a3BMXiDjg+YOSwFgCysmWmCrxoImmfcQWUZJy5eMow+hBBiKgT2DxggqVzReN3C7uwsFZLZCsv8+MjvFQz52oEp/GWqFepggFQiRIK7/QmwcsDdz6zBobZJaJstq3R2mHYkhaVUIOqEuqyD2N7qms8bek7xzq6F9KkYLkPK/d2Crkxq1bnvM7oO8IsA6vHdTexfZ1SRPf7Mxpg8DMV788qE09BDZ5mLFOkRbwFY7MHRX6Mz59gfnAcRwK/0HnG6c8EZCJH8jMStzqA0bUjzDiyN2ZgzFkTUA9Cr8jkq8grtVMsp40mjFnSg/FR+O+rG32D/rbfvNYFCR8wawOcYrGyA==</samlsig:X509Certificate>
	            </samlsig:X509Data>
	        </samlsig:KeyInfo>
	    </samlsig:Signature>
	    <samlp:NameIDPolicy AllowCreate="true" Format=""/>
	    <samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact">
	        <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
	    </samlp:RequestedAuthnContext>
	</samlp:AuthnRequest>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(result))
}

func TestGetUnsignedRequest(t *testing.T) {
	settings := GetStandardSettings()
	settings.SP.SignRequest = false

	err := settings.Init()
	assert.NoError(t, err)

	// Construct an AuthnRequest
	request := saml.ApplyAuthnRequest(settings, saml.NewAuthnRequest())
	request.ID = "id"
	request.IssueInstant = "statictime"

	reqxml, err := request.String()
	assert.NoError(t, err)

	expected := `
	<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id" Version="2.0" Destination="http://www.onelogin.net" IssueInstant="statictime" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://localhost:8000/auth/saml/acs" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="0">
	    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://localhost:8000/auth/saml/metadata</saml:Issuer>
	    <samlp:NameIDPolicy AllowCreate="true" Format=""></samlp:NameIDPolicy>
	    <samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact">
	        <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
	    </samlp:RequestedAuthnContext>
	</samlp:AuthnRequest>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(reqxml))
}

func TestGetSignedRequestFromStringPEM(t *testing.T) {
	settings := GetStandardSettings()
	settings.SP.PrivateKeyPath = ""
	settings.SP.PrivateKeyString = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`

	settings.SP.PublicCertPath = ""
	settings.SP.PublicCertString = `
-----BEGIN CERTIFICATE-----
MIIFYTCCA0mgAwIBAgIJAI1a1evtQYDkMA0GCSqGSIb3DQEBBQUAME8xCzAJBgNV
BAYTAkZSMQ4wDAYDVQQHEwVQYXJpczEOMAwGA1UEChMFRWtpbm8xDzANBgNVBAsT
BkRldk9wczEPMA0GA1UEAxMGZ29zYW1sMB4XDTE1MDcyMDIyNDE1OFoXDTI1MDcx
NzIyNDE1OFowTzELMAkGA1UEBhMCRlIxDjAMBgNVBAcTBVBhcmlzMQ4wDAYDVQQK
EwVFa2lubzEPMA0GA1UECxMGRGV2T3BzMQ8wDQYDVQQDEwZnb3NhbWwwggIiMA0G
CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDoo/DTqWoyJyXR0K+hF4pw4qBkaLL0
gbbKoiKH+7wvdzHONOoFBfF5NQj02M4JJyeOQ6+hHYV4QjtUG41zMf1XoH/U6Ey/
oURkuCJJCGhW9AyD+A4WP4YS4Ag/uN7o0P3nuj7hJipefY1Bzmg2n89iHDcpHvwK
TtVWZYdj6Dgbwh9ZH9QiRRRp+GZHXu7nW+VCZM0mE+9qjxK4Mw+KEDD6LIgSOAzR
LWLyUmb2Kwvc++DhwDtIoThVHYoNd4Sk9j6/4B3DmPa83i/1dZKyFaMCDUn7+i6K
hwIWbGfg6uQMM8G6XzF4V5x5agmg8DK24VXs3yb1lOIUczNVq4ZHkApc4jwHWiXn
cab88UnDPG7pVm87whaMghWNwrYAt//QEInExkxjNhWwxNFlelg/8b9fUsdH58Fe
ZiZ+mNnwACXnggmZEE+lUX5Fh8l79bke+dnQbJAhQfi+OhmNlqmc+ouKDPYqk0/I
C9q/3Tg65Ej9Miq918IAvQAVtlwwwp6I5/02Aa5iqZozBTUXYqWE/qXixlpWh2tP
5ljecgGazuw58tGj2+nXS9DA9wVgGUAl4xJFO/s8emna52lSPzwvcr6j+BMifXHr
0WBIEcTbtzXhxUpfC6IC14yfPOf8g4WKKgg1Wq3H4dGiE11y66ceYeh1RZlWXq/J
EtJ1FVLoGq4qLwIDAQABo0AwPjA8BgNVHREENTAzghBsb2dzLmV4YW1wbGUuY29t
ghNtZXRyaWNzLmV4YW1wbGUuY29thwTAqAABhwQKAAAyMA0GCSqGSIb3DQEBBQUA
A4ICAQAcaLdziL6dNZ3lXtm3nsI9ceSVwp2yKfpsswjs524bOsLK97Ucf4hhlh1b
q5hywWbm85N7iuxdpBuhSmeJ94ryFAPDUkhR1Mzcl48c6R8tPbJVhabhbfg+uIHi
4BYUA0olesdsyTOsRHprM4iV+PlKZ85SQT04ZNyaqIDzmNEP7YXDl/Wl3Q0N5E1U
yGfDTBxo07srqrAM2E5X7hN9bwdZX0Hbo/C4q3wgRHAts/wJXXWSSTe1jbIWYXem
EkwAEd01BiMBj1LYK/sJ8s4fONdLxIyKqLUh1Ja46moqpgl5AHuPbqnwPdgGGvEd
iBzz5ppHs0wXFopk+J4rzYRhya6a3BMXiDjg+YOSwFgCysmWmCrxoImmfcQWUZJy
5eMow+hBBiKgT2DxggqVzReN3C7uwsFZLZCsv8+MjvFQz52oEp/GWqFepggFQiRI
K7/QmwcsDdz6zBobZJaJstq3R2mHYkhaVUIOqEuqyD2N7qms8bek7xzq6F9KkYLk
PK/d2Crkxq1bnvM7oO8IsA6vHdTexfZ1SRPf7Mxpg8DMV788qE09BDZ5mLFOkRbw
FY7MHRX6Mz59gfnAcRwK/0HnG6c8EZCJH8jMStzqA0bUjzDiyN2ZgzFkTUA9Cr8j
kq8grtVMsp40mjFnSg/FR+O+rG32D/rbfvNYFCR8wawOcYrGyA==
-----END CERTIFICATE-----
`
	err := settings.Init()
	assert.NoError(t, err)

	// Construct an AuthnRequest
	request := saml.ApplyAuthnRequest(settings, saml.NewAuthnRequest())
	request.ID = "id"
	request.IssueInstant = "statictime"
	request.Signature.SignedInfo.SamlsigReference.URI = "#id"

	result, err := request.SignedString(&settings)
	assert.NoError(t, err)

	expected := `
	<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="id" Version="2.0" Destination="http://www.onelogin.net" IssueInstant="statictime" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://localhost:8000/auth/saml/acs" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="0">
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
	                <samlsig:DigestValue>KQMUHM48EjYwMvpv9DYeGUPAUZE=</samlsig:DigestValue>
	            </samlsig:Reference>
	        </samlsig:SignedInfo>
	        <samlsig:SignatureValue>B22PuLWyczmPJ/tb6Fu+P5eplz5tIj+XIHl2Kkrv1rpB28mSCCEhANWs8Vehp436DVkgodVdfkreZeQ13JxMg1j2AZoDrckfYXVdgxIeGktAJc7ABM3uKwoSN5pbA/gii79Gp4jDSK+X/gP+kqnXoj7c2088UUj7tuMxBL9E8zsOW86SC66q8KwCFO5W1GMJ/Hj3OmeJuh99e7IXIXsOfXPiieI+4FWkp65Bgh3N049Bpdc88DSiML1myyyuZEsgbI9m/SV4W2uFGoGtJJAldCIiiDFn9uew//gT2xkGJwDkscK5QA/LqRBO3PFvuI5Zk03TvgJASBR8l7/X1Pg/tyLV+xEQghSjFOzvm58KkwfZGK5Wphza6r6h3l7c+CdQu7u+3DWzMO8pueUWVgoqiAiHmjm6nBOlrVOB0EqxWnnCNgoZAKr74N+03OdYxrFzIb3zhMoiafoZme4xKvYmGvuEs4DchGwCkL0eNEU4WVUwcnlwerMHyOlzulkN1xZtqbkzgrPRjttBCb6BV9LpENuyB7oIKFdS64XmATMofF97KSL+x3VdEazmxQhEsMY7kycBtj+OctK7sgpvP4AINB1ZVdJvomYmUWgTvOFvSzraW8XN+gNVvTPuTO708wLkPfsZwWCXdnMIF5T7AiPsOkJX4bJmz0swSef1g0QOvho=</samlsig:SignatureValue>
	        <samlsig:KeyInfo>
	            <samlsig:X509Data>
	                <samlsig:X509Certificate>MIIFYTCCA0mgAwIBAgIJAI1a1evtQYDkMA0GCSqGSIb3DQEBBQUAME8xCzAJBgNVBAYTAkZSMQ4wDAYDVQQHEwVQYXJpczEOMAwGA1UEChMFRWtpbm8xDzANBgNVBAsTBkRldk9wczEPMA0GA1UEAxMGZ29zYW1sMB4XDTE1MDcyMDIyNDE1OFoXDTI1MDcxNzIyNDE1OFowTzELMAkGA1UEBhMCRlIxDjAMBgNVBAcTBVBhcmlzMQ4wDAYDVQQKEwVFa2lubzEPMA0GA1UECxMGRGV2T3BzMQ8wDQYDVQQDEwZnb3NhbWwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDoo/DTqWoyJyXR0K+hF4pw4qBkaLL0gbbKoiKH+7wvdzHONOoFBfF5NQj02M4JJyeOQ6+hHYV4QjtUG41zMf1XoH/U6Ey/oURkuCJJCGhW9AyD+A4WP4YS4Ag/uN7o0P3nuj7hJipefY1Bzmg2n89iHDcpHvwKTtVWZYdj6Dgbwh9ZH9QiRRRp+GZHXu7nW+VCZM0mE+9qjxK4Mw+KEDD6LIgSOAzRLWLyUmb2Kwvc++DhwDtIoThVHYoNd4Sk9j6/4B3DmPa83i/1dZKyFaMCDUn7+i6KhwIWbGfg6uQMM8G6XzF4V5x5agmg8DK24VXs3yb1lOIUczNVq4ZHkApc4jwHWiXncab88UnDPG7pVm87whaMghWNwrYAt//QEInExkxjNhWwxNFlelg/8b9fUsdH58FeZiZ+mNnwACXnggmZEE+lUX5Fh8l79bke+dnQbJAhQfi+OhmNlqmc+ouKDPYqk0/IC9q/3Tg65Ej9Miq918IAvQAVtlwwwp6I5/02Aa5iqZozBTUXYqWE/qXixlpWh2tP5ljecgGazuw58tGj2+nXS9DA9wVgGUAl4xJFO/s8emna52lSPzwvcr6j+BMifXHr0WBIEcTbtzXhxUpfC6IC14yfPOf8g4WKKgg1Wq3H4dGiE11y66ceYeh1RZlWXq/JEtJ1FVLoGq4qLwIDAQABo0AwPjA8BgNVHREENTAzghBsb2dzLmV4YW1wbGUuY29tghNtZXRyaWNzLmV4YW1wbGUuY29thwTAqAABhwQKAAAyMA0GCSqGSIb3DQEBBQUAA4ICAQAcaLdziL6dNZ3lXtm3nsI9ceSVwp2yKfpsswjs524bOsLK97Ucf4hhlh1bq5hywWbm85N7iuxdpBuhSmeJ94ryFAPDUkhR1Mzcl48c6R8tPbJVhabhbfg+uIHi4BYUA0olesdsyTOsRHprM4iV+PlKZ85SQT04ZNyaqIDzmNEP7YXDl/Wl3Q0N5E1UyGfDTBxo07srqrAM2E5X7hN9bwdZX0Hbo/C4q3wgRHAts/wJXXWSSTe1jbIWYXemEkwAEd01BiMBj1LYK/sJ8s4fONdLxIyKqLUh1Ja46moqpgl5AHuPbqnwPdgGGvEdiBzz5ppHs0wXFopk+J4rzYRhya6a3BMXiDjg+YOSwFgCysmWmCrxoImmfcQWUZJy5eMow+hBBiKgT2DxggqVzReN3C7uwsFZLZCsv8+MjvFQz52oEp/GWqFepggFQiRIK7/QmwcsDdz6zBobZJaJstq3R2mHYkhaVUIOqEuqyD2N7qms8bek7xzq6F9KkYLkPK/d2Crkxq1bnvM7oO8IsA6vHdTexfZ1SRPf7Mxpg8DMV788qE09BDZ5mLFOkRbwFY7MHRX6Mz59gfnAcRwK/0HnG6c8EZCJH8jMStzqA0bUjzDiyN2ZgzFkTUA9Cr8jkq8grtVMsp40mjFnSg/FR+O+rG32D/rbfvNYFCR8wawOcYrGyA==</samlsig:X509Certificate>
	            </samlsig:X509Data>
	        </samlsig:KeyInfo>
	    </samlsig:Signature>
	    <samlp:NameIDPolicy AllowCreate="true" Format=""/>
	    <samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact">
	        <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
	    </samlp:RequestedAuthnContext>
	</samlp:AuthnRequest>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(result))
}
