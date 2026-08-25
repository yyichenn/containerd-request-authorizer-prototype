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
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/containerd/errdefs"
)

const (
	rfc9421SignatureID = "ecr"
	rfc9421Algorithm   = "hmac-sha256"
	awsSigningService  = "ecr"
	awsSigningTerminal = "aws4_request"
)

var rfc9421CoveredComponents = []string{
	"@method",
	"@authority",
	"@path",
	"@query",
	"x-amz-security-token",
}

// SigningContext contains the public metadata for one request-signing operation.
// Implementations may retain private key material in their concrete context type.
type SigningContext interface {
	AccessKeyID() string
	SessionToken() string
	Date() string
	Region() string
	Service() string
	Terminal() string
}

// MessageSigner signs registry request signature bases without coupling the
// registry client to an in-process or node-local credential source.
type MessageSigner interface {
	NewSigningContext(context.Context, time.Time, []byte) (SigningContext, error)
	Sign(context.Context, SigningContext, []byte) ([]byte, error)
}

type rfc9421Authorizer struct {
	host              string
	signer            MessageSigner
	credentialContext []byte
	now               func() time.Time
	nonceReader       io.Reader
}

// RFC9421AuthorizerOpt configures the request-signing authorizer.
type RFC9421AuthorizerOpt func(*rfc9421Authorizer)

// WithRFC9421Clock overrides the clock, primarily for deterministic tests.
func WithRFC9421Clock(clock func() time.Time) RFC9421AuthorizerOpt {
	return func(authorizer *rfc9421Authorizer) {
		authorizer.now = clock
	}
}

// WithRFC9421NonceReader overrides the nonce source, primarily for deterministic tests.
func WithRFC9421NonceReader(reader io.Reader) RFC9421AuthorizerOpt {
	return func(authorizer *rfc9421Authorizer) {
		authorizer.nonceReader = reader
	}
}

// WithRFC9421CredentialContext binds an opaque credential context to the
// authorizer. Only the selected signer interprets this value.
func WithRFC9421CredentialContext(credentialContext []byte) RFC9421AuthorizerOpt {
	return func(authorizer *rfc9421Authorizer) {
		authorizer.credentialContext = bytes.Clone(credentialContext)
	}
}

// NewRFC9421Authorizer creates a pull-only request-signing authorizer for one
// exact registry authority.
func NewRFC9421Authorizer(host string, signer MessageSigner, opts ...RFC9421AuthorizerOpt) (Authorizer, error) {
	if strings.TrimSpace(host) == "" {
		return nil, errors.New("request-signing registry host is required")
	}
	if signer == nil {
		return nil, errors.New("message signer is required")
	}
	authorizer := &rfc9421Authorizer{
		host:        strings.ToLower(host),
		signer:      signer,
		now:         time.Now,
		nonceReader: rand.Reader,
	}
	for _, opt := range opts {
		opt(authorizer)
	}
	return authorizer, nil
}

func (a *rfc9421Authorizer) Authorize(ctx context.Context, req *http.Request) error {
	removeRegistryCredentials(req.Header)
	if !strings.EqualFold(req.URL.Host, a.host) {
		return nil
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return fmt.Errorf("RFC 9421 registry authentication supports GET and HEAD only, got %s", req.Method)
	}

	now := a.now().UTC()
	signingContext, err := a.signer.NewSigningContext(ctx, now, a.credentialContext)
	if err != nil {
		return fmt.Errorf("create signing context: %w", err)
	}
	if err := validateSigningContext(signingContext); err != nil {
		return err
	}

	nonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(a.nonceReader, nonceBytes); err != nil {
		return fmt.Errorf("create request-signing nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	keyID := strings.Join([]string{
		signingContext.AccessKeyID(),
		signingContext.Date(),
		signingContext.Region(),
		signingContext.Service(),
		signingContext.Terminal(),
	}, "/")

	req.Header.Set("X-Amz-Security-Token", signingContext.SessionToken())
	signatureParameters := fmt.Sprintf(
		"(%s);created=%d;expires=%d;nonce=\"%s\";alg=\"%s\";keyid=\"%s\"",
		quotedComponents(rfc9421CoveredComponents),
		now.Unix(),
		now.Add(5*time.Minute).Unix(),
		nonce,
		rfc9421Algorithm,
		keyID,
	)
	signatureBase := buildRFC9421SignatureBase(req, signatureParameters)
	signature, err := a.signer.Sign(ctx, signingContext, []byte(signatureBase))
	if err != nil {
		return fmt.Errorf("sign registry request: %w", err)
	}

	req.Header.Set("Signature-Input", rfc9421SignatureID+"="+signatureParameters)
	req.Header.Set(
		"Signature",
		rfc9421SignatureID+"=:"+base64.StdEncoding.EncodeToString(signature)+":",
	)
	return nil
}

func (a *rfc9421Authorizer) AddResponses(context.Context, []*http.Response) error {
	return fmt.Errorf("RFC 9421 request signing does not use registry challenges: %w", errdefs.ErrNotImplemented)
}

func validateSigningContext(signingContext SigningContext) error {
	if signingContext == nil {
		return errors.New("message signer returned a nil signing context")
	}
	values := map[string]string{
		"access key ID": signingContext.AccessKeyID(),
		"session token": signingContext.SessionToken(),
		"date":          signingContext.Date(),
		"region":        signingContext.Region(),
		"service":       signingContext.Service(),
		"terminal":      signingContext.Terminal(),
	}
	for name, value := range values {
		if value == "" {
			return fmt.Errorf("message signer returned an empty %s", name)
		}
		if strings.ContainsAny(value, "\";") {
			return fmt.Errorf("message signer returned an invalid %s", name)
		}
	}
	if signingContext.Service() != awsSigningService || signingContext.Terminal() != awsSigningTerminal {
		return errors.New("message signer returned an unsupported AWS credential scope")
	}
	return nil
}

func quotedComponents(components []string) string {
	quoted := make([]string, len(components))
	for index, component := range components {
		quoted[index] = `"` + component + `"`
	}
	return strings.Join(quoted, " ")
}

func buildRFC9421SignatureBase(req *http.Request, signatureParameters string) string {
	query := "?"
	if req.URL.RawQuery != "" {
		query = "?" + req.URL.RawQuery
	}
	requestPath := req.URL.Path
	if requestPath == "" {
		requestPath = "/"
	}
	return fmt.Sprintf(
		"\"@method\": %s\n\"@authority\": %s\n\"@path\": %s\n\"@query\": %s\n"+
			"\"x-amz-security-token\": %s\n\"@signature-params\": %s",
		req.Method,
		normalizedAuthority(req),
		requestPath,
		query,
		strings.TrimSpace(req.Header.Get("X-Amz-Security-Token")),
		signatureParameters,
	)
}

func normalizedAuthority(req *http.Request) string {
	authority := strings.ToLower(req.URL.Host)
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return authority
	}
	if (req.URL.Scheme == "https" && port == "443") || (req.URL.Scheme == "http" && port == "80") {
		return host
	}
	return authority
}

func removeRegistryCredentials(header http.Header) {
	header.Del("Authorization")
	header.Del("Signature")
	header.Del("Signature-Input")
	header.Del("X-Amz-Security-Token")
}
