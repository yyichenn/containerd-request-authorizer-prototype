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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/containerd/containerd/v2/pkg/dialer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func main() {
	var (
		address           = flag.String("address", "", "containerd CRI Unix socket")
		image             = flag.String("image", "", "image reference to pull")
		timeout           = flag.Duration("timeout", 30*time.Second, "PullImage timeout")
		requestAuthorizer = flag.String(
			"request-authorizer",
			"",
			"request authorizer plugin selected for this pull",
		)
		credentialContext = flag.String(
			"credential-context",
			"",
			"opaque credential context passed to the request authorizer",
		)
	)
	flag.Parse()
	if *address == "" || *image == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *credentialContext != "" && *requestAuthorizer == "" {
		fmt.Fprintln(os.Stderr, "--credential-context requires --request-authorizer")
		os.Exit(2)
	}

	var auth *runtimeapi.AuthConfig
	if *requestAuthorizer != "" {
		auth = &runtimeapi.AuthConfig{
			RequestAuthorizer: &runtimeapi.RequestAuthorizer{
				Name:              *requestAuthorizer,
				CredentialContext: []byte(*credentialContext),
			},
		}
	}

	connection, err := grpc.NewClient(
		dialer.DialAddress(*address),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer.ContextDialer),
	)
	exitOnError("connect to containerd CRI", err)
	defer connection.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	response, err := runtimeapi.NewImageServiceClient(connection).PullImage(
		ctx,
		&runtimeapi.PullImageRequest{
			Image: &runtimeapi.ImageSpec{
				Image:              *image,
				UserSpecifiedImage: *image,
			},
			Auth: auth,
		},
	)
	exitOnError("CRI PullImage", err)
	fmt.Printf("ImageRef: %s\n", response.ImageRef)
}

func exitOnError(action string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", action, err)
		os.Exit(1)
	}
}
