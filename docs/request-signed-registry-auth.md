# Request-signed registry authentication prototype

This experimental branch adds pull-only request authentication to containerd's
registry path. For explicitly selected hosts, containerd signs each `GET` and
`HEAD` request using an external Unix-socket authorizer instead of sending
Basic or Bearer credentials.

The initial profile uses RFC 9421 HTTP Message Signatures with AWS temporary
credentials. The companion
[`containerd-aws-rfc9421-authorizer`](https://github.com/yyichenn/containerd-aws-rfc9421-authorizer)
repository implements AWS credential discovery and signing. Containerd does
not load or retain the AWS secret access key.

This code is a feasibility prototype, not a proposed stable API.

## Node-wide activation

Set an exact host allowlist and signer socket in the containerd process:

```bash
CONTAINERD_REGISTRY_RFC9421_HOSTS=123456789012.dkr.ecr.us-east-1.amazonaws.com
CONTAINERD_REGISTRY_RFC9421_SIGNER_SOCKET=/run/containerd/aws-rfc9421-authorizer.sock
```

`CONTAINERD_REGISTRY_RFC9421_HOSTS` is comma-separated. Hosts outside the
allowlist retain containerd's existing Docker Basic/Bearer authorizer.
Containerd removes authorization and signature headers when a request
redirects to another host.

The equivalent library configuration is:

```go
config.HostOptions{
	RequestSigning: &config.RequestSigningOptions{
		Hosts:        []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com"},
		SignerSocket: "/run/containerd/aws-rfc9421-authorizer.sock",
	},
}
```

Node-wide selection does not change CRI. Kubelet continues to call the existing
`PullImage` method:

```text
kubelet
  -> CRI ImageService.PullImage
  -> containerd registry resolver
  -> node-local authorizer over a protected Unix socket
  -> request-signed registry call
```

## Per-pull selection

The prototype also registers a configured endpoint as a
`request-authorizer` proxy plugin:

```toml
[proxy_plugins."aws-rfc9421"]
  type = "request-authorizer"
  address = "/run/containerd/aws-rfc9421-authorizer.sock"
```

Its experimental CRI `AuthConfig` fields select the plugin by exact name and
can carry an opaque credential context:

```protobuf
message RequestAuthorizer {
    string name = 1;
    bytes credential_context = 2;
}
```

The runtime does not interpret the credential context. The selected
authorizer can use it as an identity or credential handle. Registry passwords
and tokens are rejected when a request authorizer is selected.

The proxy plugin is an external service, not a dynamically loaded Go plugin.
Production per-pull selection would require an upstream kubelet
credential-provider response and CRI API that populate these fields.

`cmd/rfc9421-cri-pull` is a focused test client for the experimental CRI
fields. It contains no credential or signing logic.

## Local verification

The integration test exercises this path:

```text
CRI AuthConfig serialization
  -> exact request-authorizer lookup
  -> Unix-socket protocol with opaque credential context
  -> RFC 9421 header construction
  -> loopback registry request
```

The loopback registry returns `404` after recording `Signature`,
`Signature-Input`, and `X-Amz-Security-Token`. This verifies plugin selection,
context propagation, per-request signing, and registry transmission. It does
not verify registry-side authentication, image download, or Kubernetes
integration.

## Current scope

- `GET` and `HEAD` registry requests only.
- Exact host selection and fail-closed signing errors.
- RFC 9421 signature input with an AWS4-derived HMAC signature.
- Node-wide selection through environment configuration.
- Per-pull selection through experimental CRI fields.
- Local-pull path only; the transfer-service path fails closed.
- No push or streaming-body digest profile.
- No shared server-side nonce cache; a captured request may be replayed during
  its five-minute validity window.
- Manually managed authorizer process and Unix-socket permissions.

## Client coverage

This branch covers clients whose registry operations execute through the
modified containerd resolver. Kubelet can use node-wide selection without a
client change. Per-pull selection requires kubelet and CRI changes.

Clients that embed containerd's resolver must adopt the changed library and
preserve the request authorizer in their own configuration. Clients with
independent registry implementations need equivalent integration. A
containerd authorizer plugin is therefore one implementation, not a universal
OCI-client deployment mechanism.
