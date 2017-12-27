package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

const (
	SAMLResponseTmpl = `
		<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Destination="{{.Destination}}" ID="{{.AssertionID}}" IssueInstant="{{.IssueInstant}}" Version="2.0">
			<Signature xmlns="http://www.w3.org/2000/09/xmldsig#" />
			<samlp:Status>
				<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
			</samlp:Status>
			<saml:Assertion ID="{{.AssertionID}}" IssueInstant="{{.IssueInstant}}" Version="2.0">
				<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" />
				<saml:Subject>
					<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified">{{.Profile.ID}}</saml:NameID>
					<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer" />
				</saml:Subject>
				<saml:AuthnStatement AuthnInstant="{{.IssueInstant}}">
					<saml:AuthnContext>
						<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
					</saml:AuthnContext>
				</saml:AuthnStatement>
				<saml:AttributeStatement>
					<saml:Attribute Name="Email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
						<saml:AttributeValue xsi:type="xs:string">{{.Profile.Email}}</saml:AttributeValue>
					</saml:Attribute>
					<saml:Attribute Name="Username" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
						<saml:AttributeValue xsi:type="xs:string">{{.Profile.Username}}</saml:AttributeValue>
					</saml:Attribute>
					<saml:Attribute Name="FirstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
						<saml:AttributeValue xsi:type="xs:string">{{.Profile.FirstName}}</saml:AttributeValue>
					</saml:Attribute>
					<saml:Attribute Name="LastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
						<saml:AttributeValue xsi:type="xs:string">{{.Profile.LastName}}</saml:AttributeValue>
					</saml:Attribute>
					<saml:Attribute Name="NickName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
						<saml:AttributeValue xsi:type="xs:string">{{.Profile.NickName}}</saml:AttributeValue>
					</saml:Attribute>
					<saml:Attribute Name="Locale" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
						<saml:AttributeValue xsi:type="xs:string">{{.Profile.Locale}}</saml:AttributeValue>
					</saml:Attribute>
				</saml:AttributeStatement>
			</saml:Assertion>
		</samlp:Response>
	`

	ResponseFormTmpl = `
		<html>
			<form method="post" action="{{.URL}}" id="SAMLResponseForm">
				<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />
				<input type="hidden" name="RelayState" value="" />
				<input id="SAMLSubmitButton" type="submit" value="Continue" />
			</form>
			<script>
				document.getElementById('SAMLSubmitButton').style.visibility="hidden";
				document.getElementById('SAMLResponseForm').submit();
			</script>
		</html>
	`
)

type Profile struct {
	ID        string
	Email     string
	Username  string
	FirstName string
	LastName  string
	NickName  string
	Locale    string
}

type SAMLRequest struct {
	ID           string    `xml:"ID,attr"`
	ConsumerURL  string    `xml:"AssertionConsumerServiceURL,attr"`
	IssueInstant time.Time `xml:"IssueInstant,attr"`
	Issuer       string    `xml:"saml\:Issuer"`
}

type SAMLResponseContext struct {
	AssertionID  string
	Destination  string
	IssueInstant time.Time
	Profile      Profile
}

func BuildSAMLResponse(id string, destination string) string {
	var buf bytes.Buffer

	ctx := SAMLResponseContext{id, destination, time.Now(), Profile{
		ID:        "U001",
		Email:     "user1@example.com",
		Username:  "user1",
		FirstName: "User",
		LastName:  "One",
		NickName:  "",
		Locale:    "en",
	}}

	tmpl := template.Must(template.New("saml-response").Parse(SAMLResponseTmpl))
	tmpl.Execute(&buf, ctx)

	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func DecompressSAMLRequest(u *url.URL) ([]byte, error) {
	compressedRequest, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil {
		return nil, fmt.Errorf("Cannot decode request: %s", err)
	}
	buf, err := ioutil.ReadAll(flate.NewReader(bytes.NewReader(compressedRequest)))
	if err != nil {
		return nil, fmt.Errorf("Cannot decompress request: %s", err)
	}
	return buf, nil
}

func HandleSamlRequest(w http.ResponseWriter, r *http.Request) {
	data, err := DecompressSAMLRequest(r.URL)
	if err != nil {
		fmt.Printf("Failed to decompress request: %s", err)
		return
	}

	var samlRequest SAMLRequest
	if err := xml.Unmarshal(data, &samlRequest); err != nil {
		fmt.Printf("Failed to unmarshal SAML request: %s", err)
		return
	}

	fmt.Printf("SAML auth requested: %s\n", samlRequest)

	samlResponse := BuildSAMLResponse(
		samlRequest.ID,
		samlRequest.ConsumerURL,
	)
	fmt.Printf("SAML response built: %s\n", samlResponse)

	var buf bytes.Buffer
	t := template.Must(template.New("saml-post-form").Parse(ResponseFormTmpl))
	t.Execute(&buf, struct {
		SAMLResponse string
		URL          string
	}{
		samlResponse,
		samlRequest.ConsumerURL,
	})

	fmt.Fprint(w, buf.String())
}

func main() {
	fmt.Println("Welcome to the SAML 2.0 Test Server!")
	fmt.Println("Will listen HTTP request to port 3912 and any path")

	http.HandleFunc("/*", HandleSamlRequest)
	http.ListenAndServe(":3912", nil)
}
