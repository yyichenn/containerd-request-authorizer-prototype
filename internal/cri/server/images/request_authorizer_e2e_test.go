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

package images

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	distribution "github.com/distribution/reference"
	"google.golang.org/protobuf/proto"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/containerd/containerd/v2/core/remotes/docker"
)

type testSigningContextRequest struct {
	CredentialContext []byte `json:"credentialContext,omitempty"`
}

type testSigningContextResponse struct {
	ContextID    string `json:"contextId"`
	AccessKeyID  string `json:"accessKeyId"`
	SessionToken string `json:"sessionToken"`
	Date         string `json:"date"`
	Region       string `json:"region"`
	Service      string `json:"service"`
	Terminal     string `json:"terminal"`
}

type testSignMessageRequest struct {
	ContextID string `json:"contextId"`
	Message   string `json:"message"`
}

type testSignMessageResponse struct {
	Signature string `json:"signature"`
}

func TestCRIRequestAuthorizerToLocalRegistry(t *testing.T) {
	credentialContext := []byte("pod-identity-handle")
	signerHandler := http.NewServeMux()
	signerHandler.HandleFunc("/v1/signing-context", func(writer http.ResponseWriter, request *http.Request) {
		var input testSigningContextRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		if !bytes.Equal(input.CredentialContext, credentialContext) {
			http.Error(writer, "unexpected credential context", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(writer).Encode(testSigningContextResponse{
			ContextID:    "test-context",
			AccessKeyID:  "TESTACCESSKEY",
			SessionToken: "test-session-token",
			Date:         "20260824",
			Region:       "us-east-1",
			Service:      "ecr",
			Terminal:     "aws4_request",
		})
	})
	signerHandler.HandleFunc("/v1/sign", func(writer http.ResponseWriter, request *http.Request) {
		var input testSignMessageRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		if input.ContextID != "test-context" {
			http.Error(writer, "unexpected signing context", http.StatusBadRequest)
			return
		}
		if _, err := base64.StdEncoding.DecodeString(input.Message); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(writer).Encode(testSignMessageResponse{
			Signature: base64.StdEncoding.EncodeToString([]byte("test-signature")),
		})
	})

	socketPath := filepath.Join(t.TempDir(), "aws-rfc9421.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	signerServer := &http.Server{Handler: signerHandler}
	go func() {
		_ = signerServer.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = signerServer.Shutdown(context.Background())
	})

	requestSeen := make(chan *http.Request, 1)
	registryServer := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		requestSeen <- request.Clone(request.Context())
		http.Error(writer, "test completed", http.StatusNotFound)
	}))
	defer registryServer.Close()

	registryHost := registryServer.Listener.Addr().String()
	wireAuth := &runtime.AuthConfig{
		RequestAuthorizer: &runtime.RequestAuthorizer{
			Name:              "aws-rfc9421",
			CredentialContext: credentialContext,
		},
	}
	encodedAuth, err := proto.Marshal(wireAuth)
	if err != nil {
		t.Fatal(err)
	}
	var receivedAuth runtime.AuthConfig
	if err := proto.Unmarshal(encodedAuth, &receivedAuth); err != nil {
		t.Fatal(err)
	}
	requestAuthorizer, err := parseRequestAuthorizer(&receivedAuth)
	if err != nil {
		t.Fatal(err)
	}

	socketSigner, err := docker.NewUnixSocketMessageSigner(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	service := &CRIImageService{
		requestAuthorizers: map[string]docker.MessageSigner{
			"aws-rfc9421": socketSigner,
		},
	}
	namedRef, err := distribution.ParseDockerRef(registryHost + "/repository:latest")
	if err != nil {
		t.Fatal(err)
	}
	requestSigning, err := service.requestSigningOptions(namedRef, requestAuthorizer)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := service.registryHosts(context.Background(), nil, requestSigning, nil)(registryHost)
	if err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequest(
		http.MethodGet,
		registryServer.URL+"/v2/repository/manifests/latest",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := hosts[0].Authorizer.Authorize(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	response, err := hosts[0].Client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unexpected registry status %s", response.Status)
	}

	select {
	case signedRequest := <-requestSeen:
		if signedRequest.Header.Get("Signature-Input") == "" {
			t.Fatal("registry request did not contain Signature-Input")
		}
		if signedRequest.Header.Get("Signature") == "" {
			t.Fatal("registry request did not contain Signature")
		}
		if signedRequest.Header.Get("X-Amz-Security-Token") != "test-session-token" {
			t.Fatal("registry request did not contain the expected session token")
		}
	case <-time.After(time.Second):
		t.Fatal("local registry did not receive the signed request")
	}
}
