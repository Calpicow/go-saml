package packager_test

import (
	"encoding/xml"
	"io/ioutil"
	"regexp"
	"strings"
	"testing"

	"github.com/bmanth60/go-saml/packager"
	"github.com/stretchr/testify/assert"
)

type TestData struct {
	XMLName      xml.Name
	SAMLP        string              `xml:"xmlns:samlp,attr"`
	SAML         string              `xml:"xmlns:saml,attr"`
	SAMLSIG      string              `xml:"xmlns:samlsig,attr,omitempty"`
	ID           string              `xml:"ID,attr"`
	Version      string              `xml:"Version,attr"`
	Destination  string              `xml:"Destination,attr"`
	IssueInstant string              `xml:"IssueInstant,attr"`
	Signature    *packager.Signature `xml:"Signature,omitempty"`
}

//SquashWhitespace Squashes multiple whitespaces into single space
func SquashWhitespace(data string) string {
	regSquashWhiteSpace := regexp.MustCompile(`[\s\p{Zs}]{1,}`)
	return regSquashWhiteSpace.ReplaceAllString(strings.TrimSpace(data), " ")
}

//GetTestData get test xml data object
func GetTestData() *TestData {
	return &TestData{
		XMLName: xml.Name{
			Local: "samlp:AuthnRequest",
		},
		SAMLP:        "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
		SAMLSIG:      "http://www.w3.org/2000/09/xmldsig#",
		ID:           "id",
		Version:      "2.0",
		IssueInstant: "2017-01-17T19:05:24.15287472Z",
		Signature:    packager.GetSignatureEntity("id"),
	}
}

func TestSignedString(t *testing.T) {
	xmlreq := GetTestData()
	signed, err := packager.SignedString(xmlreq, "/go/src/github.com/bmanth60/go-saml/certs/default.key")
	assert.NoError(t, err)

	expected := `
	<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="id" Version="2.0" Destination="" IssueInstant="2017-01-17T19:05:24.15287472Z">
	    <samlsig:Signature Id="Signature1">
	        <samlsig:SignedInfo xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#">
	            <samlsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	            <samlsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
	            <samlsig:Reference URI="#id">
	                <samlsig:Transforms>
	                    <samlsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
	                </samlsig:Transforms>
	                <samlsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	                <samlsig:DigestValue>TM7GuhDFajQAb8paaC07ShmMyf0=</samlsig:DigestValue>
	            </samlsig:Reference>
	        </samlsig:SignedInfo>
	        <samlsig:SignatureValue>FayUnGOPjnvlV1mm5JftzuKNyf/L05E1LZAxsRGxydu0r022Wz4BNBGnn8x8wztMaXZPPpSJpFVdko7jgJdhCsl1IhUTUAKfJZZfFZ8cDoqALg3lz2V0REN247U/+zGO7oLTNhzSWM2MynQLZjmjxShwNKI8PGy0a8EOZBSemdQklZvVTga3/i/7z+h/VVS53CL8YVjlFlbxlLlQXkG1EVyt9Ve6syLwFfQL7P39hd2z05iI8Tpgizi90/eGCd20y6c9btohkXWSTGYq2lFEszYJneHOb2OKO5dE8n4Up4OtNlctL15HmE0gWbqfNd2ePu5US/8Ow4raH8JQWtH0KEDog4yiE/LVl/AxbdGgx+opGGLr5v/IR8+yl+mNZJtj+ECaY58J5FrY60gxZvEf9HHY23CS91Q4UxLNYP52gaI08ChhrYbEp23O2/0ShepAkQFtlDEqJimZ4ZvI2kTRCMgyqd8uniQEld3WHSStnxllc08RNKq86QXW192E/cSWVwnDyPV/vk/A1wz5pQs9q8u8hUPNEm4n7tJcfRqwcZfdauVymoKWttMGiUKeN7HhbGv+bgr00ZDqLTamnHw0QnMV1BC+vZR765E3O+5l0ak+XBJ0wMdTo8QpZ3HgQ/jYhiTSAqn6vzMyKNwwsPjfwejrl+oW1iU/J2fWF2gPRxk=</samlsig:SignatureValue>
	        <samlsig:KeyInfo>
	            <samlsig:X509Data>
	                <samlsig:X509Certificate/>
	            </samlsig:X509Data>
	        </samlsig:KeyInfo>
	    </samlsig:Signature>
	</samlp:AuthnRequest>
	`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(signed))
}

func TestEncodedSignedString(t *testing.T) {
	xmlreq := GetTestData()
	signed, err := packager.EncodedSignedString(xmlreq, "/go/src/github.com/bmanth60/go-saml/certs/default.key")
	assert.NoError(t, err)

	expected := `PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiB4bWxuczpzYW1sc2lnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIiBJRD0iaWQiIFZlcnNpb249IjIuMCIgRGVzdGluYXRpb249IiIgSXNzdWVJbnN0YW50PSIyMDE3LTAxLTE3VDE5OjA1OjI0LjE1Mjg3NDcyWiI+CiAgICA8c2FtbHNpZzpTaWduYXR1cmUgSWQ9IlNpZ25hdHVyZTEiPgogICAgICAgIDxzYW1sc2lnOlNpZ25lZEluZm8geG1sbnM6c2FtbHNpZz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+CiAgICAgICAgICAgIDxzYW1sc2lnOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz4KICAgICAgICAgICAgPHNhbWxzaWc6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+CiAgICAgICAgICAgIDxzYW1sc2lnOlJlZmVyZW5jZSBVUkk9IiNpZCI+CiAgICAgICAgICAgICAgICA8c2FtbHNpZzpUcmFuc2Zvcm1zPgogICAgICAgICAgICAgICAgICAgIDxzYW1sc2lnOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+CiAgICAgICAgICAgICAgICA8L3NhbWxzaWc6VHJhbnNmb3Jtcz4KICAgICAgICAgICAgICAgIDxzYW1sc2lnOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+CiAgICAgICAgICAgICAgICA8c2FtbHNpZzpEaWdlc3RWYWx1ZT5UTTdHdWhERmFqUUFiOHBhYUMwN1NobU15ZjA9PC9zYW1sc2lnOkRpZ2VzdFZhbHVlPgogICAgICAgICAgICA8L3NhbWxzaWc6UmVmZXJlbmNlPgogICAgICAgIDwvc2FtbHNpZzpTaWduZWRJbmZvPgogICAgICAgIDxzYW1sc2lnOlNpZ25hdHVyZVZhbHVlPkZheVVuR09Qam52bFYxbW01SmZ0enVLTnlmL0wwNUUxTFpBeHNSR3h5ZHUwcjAyMld6NEJOQkdubjh4OHd6dE1hWFpQUHBTSnBGVmRrbzdqZ0pkaENzbDFJaFVUVUFLZkpaWmZGWjhjRG9xQUxnM2x6MlYwUkVOMjQ3VS8rekdPN29MVE5oelNXTTJNeW5RTFpqbWp4U2h3TktJOFBHeTBhOEVPWkJTZW1kUWtsWnZWVGdhMy9pLzd6K2gvVlZTNTNDTDhZVmpsRmxieGxMbFFYa0cxRVZ5dDlWZTZzeUx3RmZRTDdQMzloZDJ6MDVpSThUcGdpemk5MC9lR0NkMjB5NmM5YnRvaGtYV1NUR1lxMmxGRXN6WUpuZUhPYjJPS081ZEU4bjRVcDRPdE5sY3RMMTVIbUUwZ1dicWZOZDJlUHU1VVMvOE93NHJhSDhKUVd0SDBLRURvZzR5aUUvTFZsL0F4YmRHZ3grb3BHR0xyNXYvSVI4K3lsK21OWkp0aitFQ2FZNThKNUZyWTYwZ3hadkVmOUhIWTIzQ1M5MVE0VXhMTllQNTJnYUkwOENoaHJZYkVwMjNPMi8wU2hlcEFrUUZ0bERFcUppbVo0WnZJMmtUUkNNZ3lxZDh1bmlRRWxkM1dIU1N0bnhsbGMwOFJOS3E4NlFYVzE5MkUvY1NXVnduRHlQVi92ay9BMXd6NXBRczlxOHU4aFVQTkVtNG43dEpjZlJxd2NaZmRhdVZ5bW9LV3R0TUdpVUtlTjdIaGJHditiZ3IwMFpEcUxUYW1uSHcwUW5NVjFCQyt2WlI3NjVFM08rNWwwYWsrWEJKMHdNZFRvOFFwWjNIZ1EvalloaVRTQXFuNnZ6TXlLTnd3c1BqZndlanJsK29XMWlVL0oyZldGMmdQUnhrPTwvc2FtbHNpZzpTaWduYXR1cmVWYWx1ZT4KICAgICAgICA8c2FtbHNpZzpLZXlJbmZvPgogICAgICAgICAgICA8c2FtbHNpZzpYNTA5RGF0YT4KICAgICAgICAgICAgICAgIDxzYW1sc2lnOlg1MDlDZXJ0aWZpY2F0ZS8+CiAgICAgICAgICAgIDwvc2FtbHNpZzpYNTA5RGF0YT4KICAgICAgICA8L3NhbWxzaWc6S2V5SW5mbz4KICAgIDwvc2FtbHNpZzpTaWduYXR1cmU+Cjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg==`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(signed))
}

func TestCompressedEncodedSignedStringFromKey(t *testing.T) {
	cert, err := ioutil.ReadFile("/go/src/github.com/bmanth60/go-saml/certs/default.key")
	assert.NoError(t, err)

	xmlreq := GetTestData()
	signed, err := packager.CompressedEncodedSignedStringFromKey(xmlreq, string(cert))
	assert.NoError(t, err)

	expected := `nFVbc6LOF3zfT2Gxj1YyA0pAa02VUcQLoohi5G2E4aLDgMwgl0//r83uPxs3ydb+9pE5fXq6Dz11vjGUkKw/LHhEN/hSYMZbVUIo678UBkKR036KWMz6FCWY9bnXt4dLoy/dw36Wpzz1UiK8aflzB2IM5zxO6dsWFocDIeI86wNQluV92blP8xBIEEIAe6BKiM/i8KvQmo0HQuwLLQfnLE7pQJDuodAaY8ZjivjLidCaMVbgGWUcUT4QJCgqd1C8E5Wt2OtDuS9170VZUpWuIrnC45dWq9X69lNE345DiniR49bMHwivX+JP3Dss9mc0SP/ByS++G84RoimNPUTi5sXOEvMo9VtDEqZ5zKPkE24RiPA79x2uvDtP7NKvAvjkhldPf0l9Iztn6I5FSPyUfYMDnGPq4dZuMxsIX2P/N6c36G2OKAvSPGHvQR8D/5tcTK+YpBn279j/Xf+u/OUa8DeCXsWM4xAz/i/j+2h0H1A7iBT4cbtU9CIaT9DJGh7VDKERVOwoWdYBHPxS/Lbjy8emXv/JmwyD9yH+JOEvU/vBP0H1juqr9YleiSMmiTwPeFMszDoABpQ10XCHFdvoVe0XMIeStG+6T+aTTqlaqWXDl+jZXa8ze55NHP+cKqdw7kcjRsRZtNvuhotg7rrBxFW9cXoZGmGHNJIDN5opdZUdaDf6SkmNrRk19n4pLWtqGe4pOVV2VJqLmbrWa4hUbeU+2TjxrTNxr842RB0QA6VpR8BxbLkzMtSDcyITcqyIQaznsy5qTs17Dn5gtVFOAstQ1p1e5EsNlOOZus3CuIl7EGB95EuwfvB6R55G5+e9vdUPF4lMNNYc5hRPV0dptVjJvqbS7i7rrrhJPG6I8jTRYLg/XgLTl/C6kHc2UFdlN0dTdW7t+RQutHEadutYA4ZDwLA6+npYtdNM141cvoLZRm3XpJ2Y7pyf2toIHWR1Lk/ywwMMK/eqBb3p9CB1RnZPtLq7yjAPa1kK0QyqoyjKD0ctkzorCUA7wtnwbE04GWuXeZy4Xfc6k87bzWgZ1hdfLWhsacTv7Ke2zWlFiAfVjbm4qA/W817sSRrw7L1T0nG9dsD1DIZi2ciZxXoXtVCj3drUki5V+NwLNpfScwMfFU6dpIs950s93i2wqUyjo35tH8McQnd8MbYoodMSWnTpiE+j9tXdKA+y1lm1ZQLRuf38NIfl0t+mqpW5nWlogdMhirf28EIfrs2yXphlydanoMSnnLTTvRjvwFwK9hMpXG+q8+A24W9C/D7lC1zf5v+m+izD3hhx9IdX+x0y+r7UgthDHIPPHuJ7ql+1GxEfiH/88uPwdlE//i8AAP//`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(signed))
}

func TestCompressedEncodedSignedString(t *testing.T) {
	xmlreq := GetTestData()
	signed, err := packager.CompressedEncodedSignedString(xmlreq, "/go/src/github.com/bmanth60/go-saml/certs/default.key")
	assert.NoError(t, err)

	expected := `nFVbc6LOF3zfT2Gxj1YyA0pAa02VUcQLoohi5G2E4aLDgMwgl0//r83uPxs3ydb+9pE5fXq6Dz11vjGUkKw/LHhEN/hSYMZbVUIo678UBkKR036KWMz6FCWY9bnXt4dLoy/dw36Wpzz1UiK8aflzB2IM5zxO6dsWFocDIeI86wNQluV92blP8xBIEEIAe6BKiM/i8KvQmo0HQuwLLQfnLE7pQJDuodAaY8ZjivjLidCaMVbgGWUcUT4QJCgqd1C8E5Wt2OtDuS9170VZUpWuIrnC45dWq9X69lNE345DiniR49bMHwivX+JP3Dss9mc0SP/ByS++G84RoimNPUTi5sXOEvMo9VtDEqZ5zKPkE24RiPA79x2uvDtP7NKvAvjkhldPf0l9Iztn6I5FSPyUfYMDnGPq4dZuMxsIX2P/N6c36G2OKAvSPGHvQR8D/5tcTK+YpBn279j/Xf+u/OUa8DeCXsWM4xAz/i/j+2h0H1A7iBT4cbtU9CIaT9DJGh7VDKERVOwoWdYBHPxS/Lbjy8emXv/JmwyD9yH+JOEvU/vBP0H1juqr9YleiSMmiTwPeFMszDoABpQ10XCHFdvoVe0XMIeStG+6T+aTTqlaqWXDl+jZXa8ze55NHP+cKqdw7kcjRsRZtNvuhotg7rrBxFW9cXoZGmGHNJIDN5opdZUdaDf6SkmNrRk19n4pLWtqGe4pOVV2VJqLmbrWa4hUbeU+2TjxrTNxr842RB0QA6VpR8BxbLkzMtSDcyITcqyIQaznsy5qTs17Dn5gtVFOAstQ1p1e5EsNlOOZus3CuIl7EGB95EuwfvB6R55G5+e9vdUPF4lMNNYc5hRPV0dptVjJvqbS7i7rrrhJPG6I8jTRYLg/XgLTl/C6kHc2UFdlN0dTdW7t+RQutHEadutYA4ZDwLA6+npYtdNM141cvoLZRm3XpJ2Y7pyf2toIHWR1Lk/ywwMMK/eqBb3p9CB1RnZPtLq7yjAPa1kK0QyqoyjKD0ctkzorCUA7wtnwbE04GWuXeZy4Xfc6k87bzWgZ1hdfLWhsacTv7Ke2zWlFiAfVjbm4qA/W817sSRrw7L1T0nG9dsD1DIZi2ciZxXoXtVCj3drUki5V+NwLNpfScwMfFU6dpIs950s93i2wqUyjo35tH8McQnd8MbYoodMSWnTpiE+j9tXdKA+y1lm1ZQLRuf38NIfl0t+mqpW5nWlogdMhirf28EIfrs2yXphlydanoMSnnLTTvRjvwFwK9hMpXG+q8+A24W9C/D7lC1zf5v+m+izD3hhx9IdX+x0y+r7UgthDHIPPHuJ7ql+1GxEfiH/88uPwdlE//i8AAP//`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(signed))
}

func TestEncodedString(t *testing.T) {
	xmlreq := GetTestData()
	signed, err := packager.EncodedString(xmlreq)
	assert.NoError(t, err)

	expected := `PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiB4bWxuczpzYW1sc2lnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIiBJRD0iaWQiIFZlcnNpb249IjIuMCIgRGVzdGluYXRpb249IiIgSXNzdWVJbnN0YW50PSIyMDE3LTAxLTE3VDE5OjA1OjI0LjE1Mjg3NDcyWiI+CiAgICA8c2FtbHNpZzpTaWduYXR1cmUgSWQ9IlNpZ25hdHVyZTEiPgogICAgICAgIDxzYW1sc2lnOlNpZ25lZEluZm8+CiAgICAgICAgICAgIDxzYW1sc2lnOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiPjwvc2FtbHNpZzpDYW5vbmljYWxpemF0aW9uTWV0aG9kPgogICAgICAgICAgICA8c2FtbHNpZzpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiPjwvc2FtbHNpZzpTaWduYXR1cmVNZXRob2Q+CiAgICAgICAgICAgIDxzYW1sc2lnOlJlZmVyZW5jZSBVUkk9IiNpZCI+CiAgICAgICAgICAgICAgICA8c2FtbHNpZzpUcmFuc2Zvcm1zPgogICAgICAgICAgICAgICAgICAgIDxzYW1sc2lnOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIj48L3NhbWxzaWc6VHJhbnNmb3JtPgogICAgICAgICAgICAgICAgPC9zYW1sc2lnOlRyYW5zZm9ybXM+CiAgICAgICAgICAgICAgICA8c2FtbHNpZzpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSI+PC9zYW1sc2lnOkRpZ2VzdE1ldGhvZD4KICAgICAgICAgICAgICAgIDxzYW1sc2lnOkRpZ2VzdFZhbHVlPjwvc2FtbHNpZzpEaWdlc3RWYWx1ZT4KICAgICAgICAgICAgPC9zYW1sc2lnOlJlZmVyZW5jZT4KICAgICAgICA8L3NhbWxzaWc6U2lnbmVkSW5mbz4KICAgICAgICA8c2FtbHNpZzpTaWduYXR1cmVWYWx1ZT48L3NhbWxzaWc6U2lnbmF0dXJlVmFsdWU+CiAgICAgICAgPHNhbWxzaWc6S2V5SW5mbz4KICAgICAgICAgICAgPHNhbWxzaWc6WDUwOURhdGE+CiAgICAgICAgICAgICAgICA8c2FtbHNpZzpYNTA5Q2VydGlmaWNhdGU+PC9zYW1sc2lnOlg1MDlDZXJ0aWZpY2F0ZT4KICAgICAgICAgICAgPC9zYW1sc2lnOlg1MDlEYXRhPgogICAgICAgIDwvc2FtbHNpZzpLZXlJbmZvPgogICAgPC9zYW1sc2lnOlNpZ25hdHVyZT4KPC9zYW1scDpBdXRoblJlcXVlc3Q+`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(signed))
}

func TestCompressedEncodedString(t *testing.T) {
	xmlreq := GetTestData()
	signed, err := packager.CompressedEncodedString(xmlreq)
	assert.NoError(t, err)

	expected := `nFRNj9owEL3zKyxzTmynIIpFkNByidq9sNtV1ZuVDImlxKYep9D++gp2m80HpLRHZt6b994w8QpVVR7kpvaF2cH3GtCTU1UalJdGTGtnpFWoURpVAUqfyqfN42cZhVwenPU2tSVtUcYZChGc19a0KajzmBbeHyRjx+MxPH4IrctZxDlnfMlOVZmhzqeUJNuY6oySF3CorYlpFHJKtoBeG+UvFUoSxBoSg14ZH9OIi0XARSAWz2Ip+VxGs1DMo4+L2SL6RtcTQghZvZmQTzo3ytcOSJLFtPkl3nADLGSJ2dv3ZgfwoIw1OlWl/nXx9gi+sBnZlLl12hfVjciCCX6OHMApDVIxM1O6XrHxoTccNAHulO5s26EKsFCird4beEN2B3twYFIgX3ZJTKc6o11kB/3slMG9dRUOQdeB/5YDzA8o7QGyAP+4b0dqpl6xyO7x2Pjb6hzQ/8+q+2tuT/qr4IsqaxiQX6uT63GaP6h11mzsrocX1VftNYbMT/Bz5Fv5OufLrfJqJO0Z8nB+O/Y6Vb6t3e/cSD3UeO913F1JtZ68FrsP5fp3AAAA//8=`
	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(signed))
}

func TestDecodeAndInflateString(t *testing.T) {
	data := `nFVbc6LOF3zfT2Gxj1YyA0pAa02VUcQLoohi5G2E4aLDgMwgl0//r83uPxs3ydb+9pE5fXq6Dz11vjGUkKw/LHhEN/hSYMZbVUIo678UBkKR036KWMz6FCWY9bnXt4dLoy/dw36Wpzz1UiK8aflzB2IM5zxO6dsWFocDIeI86wNQluV92blP8xBIEEIAe6BKiM/i8KvQmo0HQuwLLQfnLE7pQJDuodAaY8ZjivjLidCaMVbgGWUcUT4QJCgqd1C8E5Wt2OtDuS9170VZUpWuIrnC45dWq9X69lNE345DiniR49bMHwivX+JP3Dss9mc0SP/ByS++G84RoimNPUTi5sXOEvMo9VtDEqZ5zKPkE24RiPA79x2uvDtP7NKvAvjkhldPf0l9Iztn6I5FSPyUfYMDnGPq4dZuMxsIX2P/N6c36G2OKAvSPGHvQR8D/5tcTK+YpBn279j/Xf+u/OUa8DeCXsWM4xAz/i/j+2h0H1A7iBT4cbtU9CIaT9DJGh7VDKERVOwoWdYBHPxS/Lbjy8emXv/JmwyD9yH+JOEvU/vBP0H1juqr9YleiSMmiTwPeFMszDoABpQ10XCHFdvoVe0XMIeStG+6T+aTTqlaqWXDl+jZXa8ze55NHP+cKqdw7kcjRsRZtNvuhotg7rrBxFW9cXoZGmGHNJIDN5opdZUdaDf6SkmNrRk19n4pLWtqGe4pOVV2VJqLmbrWa4hUbeU+2TjxrTNxr842RB0QA6VpR8BxbLkzMtSDcyITcqyIQaznsy5qTs17Dn5gtVFOAstQ1p1e5EsNlOOZus3CuIl7EGB95EuwfvB6R55G5+e9vdUPF4lMNNYc5hRPV0dptVjJvqbS7i7rrrhJPG6I8jTRYLg/XgLTl/C6kHc2UFdlN0dTdW7t+RQutHEadutYA4ZDwLA6+npYtdNM141cvoLZRm3XpJ2Y7pyf2toIHWR1Lk/ywwMMK/eqBb3p9CB1RnZPtLq7yjAPa1kK0QyqoyjKD0ctkzorCUA7wtnwbE04GWuXeZy4Xfc6k87bzWgZ1hdfLWhsacTv7Ke2zWlFiAfVjbm4qA/W817sSRrw7L1T0nG9dsD1DIZi2ciZxXoXtVCj3drUki5V+NwLNpfScwMfFU6dpIs950s93i2wqUyjo35tH8McQnd8MbYoodMSWnTpiE+j9tXdKA+y1lm1ZQLRuf38NIfl0t+mqpW5nWlogdMhirf28EIfrs2yXphlydanoMSnnLTTvRjvwFwK9hMpXG+q8+A24W9C/D7lC1zf5v+m+izD3hhx9IdX+x0y+r7UgthDHIPPHuJ7ql+1GxEfiH/88uPwdlE//i8AAP//`
	inflated, err := packager.DecodeAndInflateString(data)
	assert.NoError(t, err)

	expected := `
	<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="id" Version="2.0" Destination="" IssueInstant="2017-01-17T19:05:24.15287472Z">
	    <samlsig:Signature Id="Signature1">
	        <samlsig:SignedInfo xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#">
	            <samlsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	            <samlsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
	            <samlsig:Reference URI="#id">
	                <samlsig:Transforms>
	                    <samlsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
	                </samlsig:Transforms>
	                <samlsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	                <samlsig:DigestValue>TM7GuhDFajQAb8paaC07ShmMyf0=</samlsig:DigestValue>
	            </samlsig:Reference>
	        </samlsig:SignedInfo>
	        <samlsig:SignatureValue>FayUnGOPjnvlV1mm5JftzuKNyf/L05E1LZAxsRGxydu0r022Wz4BNBGnn8x8wztMaXZPPpSJpFVdko7jgJdhCsl1IhUTUAKfJZZfFZ8cDoqALg3lz2V0REN247U/+zGO7oLTNhzSWM2MynQLZjmjxShwNKI8PGy0a8EOZBSemdQklZvVTga3/i/7z+h/VVS53CL8YVjlFlbxlLlQXkG1EVyt9Ve6syLwFfQL7P39hd2z05iI8Tpgizi90/eGCd20y6c9btohkXWSTGYq2lFEszYJneHOb2OKO5dE8n4Up4OtNlctL15HmE0gWbqfNd2ePu5US/8Ow4raH8JQWtH0KEDog4yiE/LVl/AxbdGgx+opGGLr5v/IR8+yl+mNZJtj+ECaY58J5FrY60gxZvEf9HHY23CS91Q4UxLNYP52gaI08ChhrYbEp23O2/0ShepAkQFtlDEqJimZ4ZvI2kTRCMgyqd8uniQEld3WHSStnxllc08RNKq86QXW192E/cSWVwnDyPV/vk/A1wz5pQs9q8u8hUPNEm4n7tJcfRqwcZfdauVymoKWttMGiUKeN7HhbGv+bgr00ZDqLTamnHw0QnMV1BC+vZR765E3O+5l0ak+XBJ0wMdTo8QpZ3HgQ/jYhiTSAqn6vzMyKNwwsPjfwejrl+oW1iU/J2fWF2gPRxk=</samlsig:SignatureValue>
	        <samlsig:KeyInfo>
	            <samlsig:X509Data>
	                <samlsig:X509Certificate/>
	            </samlsig:X509Data>
	        </samlsig:KeyInfo>
	    </samlsig:Signature>
	</samlp:AuthnRequest>
	`

	assert.Equal(t, SquashWhitespace(expected), SquashWhitespace(string(inflated)))
}
