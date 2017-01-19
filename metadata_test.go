package saml_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEntityDescriptor(t *testing.T) {
	settings := GetStandardSettings()
	meta, err := settings.GetEntityDescriptor()
	assert.NoError(t, err)

	expected := `
	<?xml version='1.0' encoding='UTF-8'?>
	<md:EntityDescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://localhost:8000/auth/saml/metadata">
	    <md:Extensions xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi">
	        <EntityAttributes></EntityAttributes>
	    </md:Extensions>
	    <SPSSODescriptor AuthnRequestsSigned="true" wantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
	        <md:KeyDescriptor use="signing">
	            <ds:KeyInfo>
	                <ds:X509Data>
	                    <ds:X509Certificate>MIIFYTCCA0mgAwIBAgIJAI1a1evtQYDkMA0GCSqGSIb3DQEBBQUAME8xCzAJBgNVBAYTAkZSMQ4wDAYDVQQHEwVQYXJpczEOMAwGA1UEChMFRWtpbm8xDzANBgNVBAsTBkRldk9wczEPMA0GA1UEAxMGZ29zYW1sMB4XDTE1MDcyMDIyNDE1OFoXDTI1MDcxNzIyNDE1OFowTzELMAkGA1UEBhMCRlIxDjAMBgNVBAcTBVBhcmlzMQ4wDAYDVQQKEwVFa2lubzEPMA0GA1UECxMGRGV2T3BzMQ8wDQYDVQQDEwZnb3NhbWwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDoo/DTqWoyJyXR0K+hF4pw4qBkaLL0gbbKoiKH+7wvdzHONOoFBfF5NQj02M4JJyeOQ6+hHYV4QjtUG41zMf1XoH/U6Ey/oURkuCJJCGhW9AyD+A4WP4YS4Ag/uN7o0P3nuj7hJipefY1Bzmg2n89iHDcpHvwKTtVWZYdj6Dgbwh9ZH9QiRRRp+GZHXu7nW+VCZM0mE+9qjxK4Mw+KEDD6LIgSOAzRLWLyUmb2Kwvc++DhwDtIoThVHYoNd4Sk9j6/4B3DmPa83i/1dZKyFaMCDUn7+i6KhwIWbGfg6uQMM8G6XzF4V5x5agmg8DK24VXs3yb1lOIUczNVq4ZHkApc4jwHWiXncab88UnDPG7pVm87whaMghWNwrYAt//QEInExkxjNhWwxNFlelg/8b9fUsdH58FeZiZ+mNnwACXnggmZEE+lUX5Fh8l79bke+dnQbJAhQfi+OhmNlqmc+ouKDPYqk0/IC9q/3Tg65Ej9Miq918IAvQAVtlwwwp6I5/02Aa5iqZozBTUXYqWE/qXixlpWh2tP5ljecgGazuw58tGj2+nXS9DA9wVgGUAl4xJFO/s8emna52lSPzwvcr6j+BMifXHr0WBIEcTbtzXhxUpfC6IC14yfPOf8g4WKKgg1Wq3H4dGiE11y66ceYeh1RZlWXq/JEtJ1FVLoGq4qLwIDAQABo0AwPjA8BgNVHREENTAzghBsb2dzLmV4YW1wbGUuY29tghNtZXRyaWNzLmV4YW1wbGUuY29thwTAqAABhwQKAAAyMA0GCSqGSIb3DQEBBQUAA4ICAQAcaLdziL6dNZ3lXtm3nsI9ceSVwp2yKfpsswjs524bOsLK97Ucf4hhlh1bq5hywWbm85N7iuxdpBuhSmeJ94ryFAPDUkhR1Mzcl48c6R8tPbJVhabhbfg+uIHi4BYUA0olesdsyTOsRHprM4iV+PlKZ85SQT04ZNyaqIDzmNEP7YXDl/Wl3Q0N5E1UyGfDTBxo07srqrAM2E5X7hN9bwdZX0Hbo/C4q3wgRHAts/wJXXWSSTe1jbIWYXemEkwAEd01BiMBj1LYK/sJ8s4fONdLxIyKqLUh1Ja46moqpgl5AHuPbqnwPdgGGvEdiBzz5ppHs0wXFopk+J4rzYRhya6a3BMXiDjg+YOSwFgCysmWmCrxoImmfcQWUZJy5eMow+hBBiKgT2DxggqVzReN3C7uwsFZLZCsv8+MjvFQz52oEp/GWqFepggFQiRIK7/QmwcsDdz6zBobZJaJstq3R2mHYkhaVUIOqEuqyD2N7qms8bek7xzq6F9KkYLkPK/d2Crkxq1bnvM7oO8IsA6vHdTexfZ1SRPf7Mxpg8DMV788qE09BDZ5mLFOkRbwFY7MHRX6Mz59gfnAcRwK/0HnG6c8EZCJH8jMStzqA0bUjzDiyN2ZgzFkTUA9Cr8jkq8grtVMsp40mjFnSg/FR+O+rG32D/rbfvNYFCR8wawOcYrGyA==</ds:X509Certificate>
	                </ds:X509Data>
	            </ds:KeyInfo>
	        </md:KeyDescriptor>
	        <md:KeyDescriptor use="encryption">
	            <ds:KeyInfo>
	                <ds:X509Data>
	                    <ds:X509Certificate>MIIFYTCCA0mgAwIBAgIJAI1a1evtQYDkMA0GCSqGSIb3DQEBBQUAME8xCzAJBgNVBAYTAkZSMQ4wDAYDVQQHEwVQYXJpczEOMAwGA1UEChMFRWtpbm8xDzANBgNVBAsTBkRldk9wczEPMA0GA1UEAxMGZ29zYW1sMB4XDTE1MDcyMDIyNDE1OFoXDTI1MDcxNzIyNDE1OFowTzELMAkGA1UEBhMCRlIxDjAMBgNVBAcTBVBhcmlzMQ4wDAYDVQQKEwVFa2lubzEPMA0GA1UECxMGRGV2T3BzMQ8wDQYDVQQDEwZnb3NhbWwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDoo/DTqWoyJyXR0K+hF4pw4qBkaLL0gbbKoiKH+7wvdzHONOoFBfF5NQj02M4JJyeOQ6+hHYV4QjtUG41zMf1XoH/U6Ey/oURkuCJJCGhW9AyD+A4WP4YS4Ag/uN7o0P3nuj7hJipefY1Bzmg2n89iHDcpHvwKTtVWZYdj6Dgbwh9ZH9QiRRRp+GZHXu7nW+VCZM0mE+9qjxK4Mw+KEDD6LIgSOAzRLWLyUmb2Kwvc++DhwDtIoThVHYoNd4Sk9j6/4B3DmPa83i/1dZKyFaMCDUn7+i6KhwIWbGfg6uQMM8G6XzF4V5x5agmg8DK24VXs3yb1lOIUczNVq4ZHkApc4jwHWiXncab88UnDPG7pVm87whaMghWNwrYAt//QEInExkxjNhWwxNFlelg/8b9fUsdH58FeZiZ+mNnwACXnggmZEE+lUX5Fh8l79bke+dnQbJAhQfi+OhmNlqmc+ouKDPYqk0/IC9q/3Tg65Ej9Miq918IAvQAVtlwwwp6I5/02Aa5iqZozBTUXYqWE/qXixlpWh2tP5ljecgGazuw58tGj2+nXS9DA9wVgGUAl4xJFO/s8emna52lSPzwvcr6j+BMifXHr0WBIEcTbtzXhxUpfC6IC14yfPOf8g4WKKgg1Wq3H4dGiE11y66ceYeh1RZlWXq/JEtJ1FVLoGq4qLwIDAQABo0AwPjA8BgNVHREENTAzghBsb2dzLmV4YW1wbGUuY29tghNtZXRyaWNzLmV4YW1wbGUuY29thwTAqAABhwQKAAAyMA0GCSqGSIb3DQEBBQUAA4ICAQAcaLdziL6dNZ3lXtm3nsI9ceSVwp2yKfpsswjs524bOsLK97Ucf4hhlh1bq5hywWbm85N7iuxdpBuhSmeJ94ryFAPDUkhR1Mzcl48c6R8tPbJVhabhbfg+uIHi4BYUA0olesdsyTOsRHprM4iV+PlKZ85SQT04ZNyaqIDzmNEP7YXDl/Wl3Q0N5E1UyGfDTBxo07srqrAM2E5X7hN9bwdZX0Hbo/C4q3wgRHAts/wJXXWSSTe1jbIWYXemEkwAEd01BiMBj1LYK/sJ8s4fONdLxIyKqLUh1Ja46moqpgl5AHuPbqnwPdgGGvEdiBzz5ppHs0wXFopk+J4rzYRhya6a3BMXiDjg+YOSwFgCysmWmCrxoImmfcQWUZJy5eMow+hBBiKgT2DxggqVzReN3C7uwsFZLZCsv8+MjvFQz52oEp/GWqFepggFQiRIK7/QmwcsDdz6zBobZJaJstq3R2mHYkhaVUIOqEuqyD2N7qms8bek7xzq6F9KkYLkPK/d2Crkxq1bnvM7oO8IsA6vHdTexfZ1SRPf7Mxpg8DMV788qE09BDZ5mLFOkRbwFY7MHRX6Mz59gfnAcRwK/0HnG6c8EZCJH8jMStzqA0bUjzDiyN2ZgzFkTUA9Cr8jkq8grtVMsp40mjFnSg/FR+O+rG32D/rbfvNYFCR8wawOcYrGyA==</ds:X509Certificate>
	                </ds:X509Data>
	            </ds:KeyInfo>
	        </md:KeyDescriptor>
	        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:8000/auth/saml/sls"></md:SingleLogoutService>
	        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8000/auth/saml/acs" index="0"></md:AssertionConsumerService>
	        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="http://localhost:8000/auth/saml/acs" index="1"></md:AssertionConsumerService>
	    </SPSSODescriptor>
	</md:EntityDescriptor>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(meta))
}
