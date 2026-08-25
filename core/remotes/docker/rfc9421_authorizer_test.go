/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package docker

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	testAccessKey    = "TESTACCESSKEY"
	testSessionToken = "test-session-token"
	testRegion       = "us-east-1"
	testRegistryHost = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
)

type staticSigningContext struct {
	accessKeyID  string
	sessionToken string
	date         string
	region       string
	service      string
	terminal     string
}

func (c *staticSigningContext) AccessKeyID() string  { return c.accessKeyID }
func (c *staticSigningContext) SessionToken() string { return c.sessionToken }
func (c *staticSigningContext) Date() string         { return c.date }
func (c *staticSigningContext) Region() string       { return c.region }
func (c *staticSigningContext) Service() string      { return c.service }
func (c *staticSigningContext) Terminal() string     { return c.terminal }

type recordingMessageSigner struct {
	signingContext    SigningContext
	signature         []byte
	credentialContext []byte
	signedMessage     []byte
}

func (s *recordingMessageSigner) NewSigningContext(
	_ context.Context,
	_ time.Time,
	credentialContext []byte,
) (SigningContext, error) {
	s.credentialContext = bytes.Clone(credentialContext)
	return s.signingContext, nil
}

func (s *recordingMessageSigner) Sign(
	_ context.Context,
	signingContext SigningContext,
	message []byte,
) ([]byte, error) {
	if signingContext != s.signingContext {
		return nil, context.Canceled
	}
	s.signedMessage = bytes.Clone(message)
	return bytes.Clone(s.signature), nil
}

func newTestRFC9421Authorizer(t *testing.T) (Authorizer, *recordingMessageSigner) {
	t.Helper()
	signer := &recordingMessageSigner{
		signingContext: &staticSigningContext{
			accessKeyID:  testAccessKey,
			sessionToken: testSessionToken,
			date:         "20260824",
			region:       testRegion,
			service:      awsSigningService,
			terminal:     awsSigningTerminal,
		},
		signature: []byte("test-signature"),
	}
	authorizer, err := NewRFC9421Authorizer(
		testRegistryHost,
		signer,
		WithRFC9421Clock(func() time.Time {
			return time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
		}),
		WithRFC9421NonceReader(bytes.NewReader(make([]byte, 16))),
	)
	if err != nil {
		t.Fatal(err)
	}
	return authorizer, signer
}

func TestRFC9421AuthorizerSignsPullRequest(t *testing.T) {
	authorizer, signer := newTestRFC9421Authorizer(t)
	req, err := http.NewRequest(
		http.MethodGet,
		"https://"+testRegistryHost+"/v2/team/app/manifests/latest?ns=example",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := authorizer.Authorize(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	signatureInput := req.Header.Get("Signature-Input")
	if !strings.Contains(signatureInput, `created=1787572800`) {
		t.Fatalf("Signature-Input does not contain fixed creation time: %s", signatureInput)
	}
	if !strings.Contains(signatureInput, `keyid="TESTACCESSKEY/20260824/us-east-1/ecr/aws4_request"`) {
		t.Fatalf("Signature-Input does not contain AWS credential scope: %s", signatureInput)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != testSessionToken {
		t.Fatalf("unexpected session token %q", got)
	}

	parameters := strings.TrimPrefix(signatureInput, rfc9421SignatureID+"=")
	base := buildRFC9421SignatureBase(req, parameters)
	expectedBase := "\"@method\": GET\n" +
		"\"@authority\": 123456789012.dkr.ecr.us-east-1.amazonaws.com\n" +
		"\"@path\": /v2/team/app/manifests/latest\n" +
		"\"@query\": ?ns=example\n" +
		"\"x-amz-security-token\": test-session-token\n" +
		"\"@signature-params\": " +
		"(\"@method\" \"@authority\" \"@path\" \"@query\" \"x-amz-security-token\")" +
		";created=1787572800;expires=1787573100;" +
		"nonce=\"AAAAAAAAAAAAAAAAAAAAAA\";alg=\"hmac-sha256\";" +
		"keyid=\"TESTACCESSKEY/20260824/us-east-1/ecr/aws4_request\""
	if base != expectedBase {
		t.Fatalf("unexpected signature base:\n%s", base)
	}
	if got := string(signer.signedMessage); got != base {
		t.Fatalf("signer received an unexpected signature base:\n%s", got)
	}
	expected := base64.StdEncoding.EncodeToString([]byte("test-signature"))
	if got := req.Header.Get("Signature"); got != "ecr=:"+expected+":" {
		t.Fatalf("unexpected signature %q", got)
	}
}

func TestRFC9421AuthorizerSignsAbsentQueryAsQuestionMark(t *testing.T) {
	authorizer, _ := newTestRFC9421Authorizer(t)
	req, err := http.NewRequest(
		http.MethodGet,
		"https://"+testRegistryHost+"/v2/team/app/manifests/latest",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := authorizer.Authorize(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	parameters := strings.TrimPrefix(req.Header.Get("Signature-Input"), rfc9421SignatureID+"=")
	base := buildRFC9421SignatureBase(req, parameters)
	if !strings.Contains(base, "\"@query\": ?\n") {
		t.Fatalf("signature base does not contain the RFC 9421 absent-query value:\n%s", base)
	}
}

func TestRFC9421AuthorizerRemovesCredentialsOnCrossHostRedirect(t *testing.T) {
	authorizer, _ := newTestRFC9421Authorizer(t)
	req, err := http.NewRequest(http.MethodGet, "https://example-bucket.s3.amazonaws.com/layer", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic secret")
	req.Header.Set("Signature", "ecr=:secret:")
	req.Header.Set("Signature-Input", "ecr=(...)")
	req.Header.Set("X-Amz-Security-Token", testSessionToken)

	if err := authorizer.Authorize(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"Authorization", "Signature", "Signature-Input", "X-Amz-Security-Token"} {
		if value := req.Header.Get(header); value != "" {
			t.Fatalf("%s leaked to redirect host", header)
		}
	}
}

func TestRFC9421AuthorizerRejectsPush(t *testing.T) {
	authorizer, _ := newTestRFC9421Authorizer(t)
	req, err := http.NewRequest(http.MethodPut, "https://"+testRegistryHost+"/v2/team/app/manifests/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizer.Authorize(context.Background(), req); err == nil {
		t.Fatal("expected PUT request to be rejected")
	}
}

func TestRFC9421AuthorizerRejectsIncompleteSigningContext(t *testing.T) {
	signer := &recordingMessageSigner{
		signingContext: &staticSigningContext{
			accessKeyID: testAccessKey,
			date:        "20260824",
			region:      testRegion,
			service:     awsSigningService,
			terminal:    awsSigningTerminal,
		},
	}
	authorizer, err := NewRFC9421Authorizer(testRegistryHost, signer)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://"+testRegistryHost+"/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizer.Authorize(context.Background(), request); err == nil {
		t.Fatal("expected an incomplete signing context to be rejected")
	}
}
