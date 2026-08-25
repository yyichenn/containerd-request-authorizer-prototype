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
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixSocketMessageSignerRoundTrip(t *testing.T) {
	credentialContext := []byte("pod-identity-handle")
	signedMessages := make(chan []byte, 1)
	handler := http.NewServeMux()
	handler.HandleFunc(rfc9421SignerContextPath, func(writer http.ResponseWriter, request *http.Request) {
		var input signingContextRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		if !bytes.Equal(input.CredentialContext, credentialContext) {
			http.Error(writer, "unexpected credential context", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(writer).Encode(signingContextResponse{
			ContextID:    "test-context",
			AccessKeyID:  testAccessKey,
			SessionToken: testSessionToken,
			Date:         "20260824",
			Region:       testRegion,
			Service:      awsSigningService,
			Terminal:     awsSigningTerminal,
		})
	})
	handler.HandleFunc(rfc9421SignerSignPath, func(writer http.ResponseWriter, request *http.Request) {
		var input signMessageRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		if input.ContextID != "test-context" {
			http.Error(writer, "unexpected signing context", http.StatusBadRequest)
			return
		}
		message, err := base64.StdEncoding.DecodeString(input.Message)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		signedMessages <- message
		_ = json.NewEncoder(writer).Encode(signMessageResponse{
			Signature: base64.StdEncoding.EncodeToString([]byte("test-signature")),
		})
	})

	socketPath := filepath.Join(t.TempDir(), "signer.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Shutdown(context.Background())
	})

	socketSigner, err := NewUnixSocketMessageSigner(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	signingContext, err := socketSigner.NewSigningContext(
		context.Background(),
		time.Now().UTC(),
		credentialContext,
	)
	if err != nil {
		t.Fatal(err)
	}
	if signingContext.AccessKeyID() != testAccessKey {
		t.Fatalf("unexpected access key ID %q", signingContext.AccessKeyID())
	}
	if signingContext.SessionToken() != testSessionToken {
		t.Fatalf("unexpected session token %q", signingContext.SessionToken())
	}

	message := []byte("request signature base")
	signature, err := socketSigner.Sign(context.Background(), signingContext, message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signature, []byte("test-signature")) {
		t.Fatalf("unexpected signature %q", signature)
	}
	select {
	case signedMessage := <-signedMessages:
		if !bytes.Equal(signedMessage, message) {
			t.Fatalf("signer received an unexpected message %q", signedMessage)
		}
	case <-time.After(time.Second):
		t.Fatal("signer did not receive the message")
	}
}

func TestUnixSocketMessageSignerRejectsUnknownContextType(t *testing.T) {
	signer, err := NewUnixSocketMessageSigner(filepath.Join(t.TempDir(), "missing.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(context.Background(), &staticSigningContext{}, []byte("message")); err == nil {
		t.Fatal("expected signing context type validation to fail")
	}
}
