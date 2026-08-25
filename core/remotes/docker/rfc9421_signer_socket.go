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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	rfc9421SignerContextPath = "/v1/signing-context"
	rfc9421SignerSignPath    = "/v1/sign"
	rfc9421SignerMaxBody     = 1 << 20
	rfc9421SignerHTTPTimeout = 5 * time.Second
)

type signingContextRequest struct {
	UnixTime          int64  `json:"unixTime"`
	CredentialContext []byte `json:"credentialContext,omitempty"`
}

type signingContextResponse struct {
	ContextID    string `json:"contextId"`
	AccessKeyID  string `json:"accessKeyId"`
	SessionToken string `json:"sessionToken"`
	Date         string `json:"date"`
	Region       string `json:"region"`
	Service      string `json:"service"`
	Terminal     string `json:"terminal"`
}

type signMessageRequest struct {
	ContextID string `json:"contextId"`
	Message   string `json:"message"`
}

type signMessageResponse struct {
	Signature string `json:"signature"`
}

type signerErrorResponse struct {
	Message string `json:"message"`
}

type unixSocketMessageSigner struct {
	client  *http.Client
	baseURL string
}

type unixSocketSigningContext struct {
	contextID    string
	accessKeyID  string
	sessionToken string
	date         string
	region       string
	service      string
	terminal     string
}

func (c *unixSocketSigningContext) AccessKeyID() string  { return c.accessKeyID }
func (c *unixSocketSigningContext) SessionToken() string { return c.sessionToken }
func (c *unixSocketSigningContext) Date() string         { return c.date }
func (c *unixSocketSigningContext) Region() string       { return c.region }
func (c *unixSocketSigningContext) Service() string      { return c.service }
func (c *unixSocketSigningContext) Terminal() string     { return c.terminal }

// NewUnixSocketMessageSigner creates a signer backed by a node-local process.
// The AWS secret and derived signing key remain in that process.
func NewUnixSocketMessageSigner(socketPath string) (MessageSigner, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, errors.New("request signer socket path is required")
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &unixSocketMessageSigner{
		client: &http.Client{
			Transport: transport,
			Timeout:   rfc9421SignerHTTPTimeout,
		},
		baseURL: "http://rfc9421-signer",
	}, nil
}

func (s *unixSocketMessageSigner) NewSigningContext(
	ctx context.Context,
	now time.Time,
	credentialContext []byte,
) (SigningContext, error) {
	var response signingContextResponse
	if err := s.postJSON(
		ctx,
		rfc9421SignerContextPath,
		signingContextRequest{
			UnixTime:          now.Unix(),
			CredentialContext: credentialContext,
		},
		&response,
	); err != nil {
		return nil, err
	}
	return &unixSocketSigningContext{
		contextID:    response.ContextID,
		accessKeyID:  response.AccessKeyID,
		sessionToken: response.SessionToken,
		date:         response.Date,
		region:       response.Region,
		service:      response.Service,
		terminal:     response.Terminal,
	}, nil
}

func (s *unixSocketMessageSigner) Sign(
	ctx context.Context,
	signingContext SigningContext,
	message []byte,
) ([]byte, error) {
	socketContext, ok := signingContext.(*unixSocketSigningContext)
	if !ok {
		return nil, errors.New("signing context was not created by the Unix-socket signer")
	}

	var response signMessageResponse
	if err := s.postJSON(
		ctx,
		rfc9421SignerSignPath,
		signMessageRequest{
			ContextID: socketContext.contextID,
			Message:   base64.StdEncoding.EncodeToString(message),
		},
		&response,
	); err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(response.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signer response: %w", err)
	}
	return signature, nil
}

func (s *unixSocketMessageSigner) postJSON(
	ctx context.Context,
	path string,
	requestValue any,
	responseValue any,
) error {
	requestBody, err := json.Marshal(requestValue)
	if err != nil {
		return fmt.Errorf("encode signer request: %w", err)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.baseURL+path,
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return fmt.Errorf("create signer request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("call request signer: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var errorResponse signerErrorResponse
		_ = json.NewDecoder(io.LimitReader(response.Body, rfc9421SignerMaxBody)).Decode(&errorResponse)
		if errorResponse.Message == "" {
			errorResponse.Message = response.Status
		}
		return fmt.Errorf("request signer rejected request: %s", errorResponse.Message)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, rfc9421SignerMaxBody)).Decode(responseValue); err != nil {
		return fmt.Errorf("decode signer response: %w", err)
	}
	return nil
}
