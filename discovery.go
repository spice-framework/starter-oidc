package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
)

const maxProviderResponseBytes = 1 << 20

// Discover constructs a resource server from an issuer's OIDC metadata.
// This is the only constructor that performs network I/O. The caller-owned
// client must have a positive timeout.
func Discover(
	ctx context.Context,
	client *http.Client,
	options Options,
	observers ...Observer,
) (*ResourceServer, error) {
	if ctx == nil {
		return nil, errors.New("discover OIDC resource server: context is nil")
	}
	boundedClient, err := boundedHTTPClient(client)
	if err != nil {
		return nil, err
	}
	normalized, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	if observerErr := validateObservers(observers); observerErr != nil {
		return nil, observerErr
	}
	clientContext := coreoidc.ClientContext(ctx, boundedClient)
	provider, err := coreoidc.NewProvider(clientContext, normalized.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	verifier := provider.VerifierContext(clientContext, &coreoidc.Config{
		ClientID:             normalized.Audience,
		SupportedSigningAlgs: normalized.SupportedSigningAlgs,
	})
	return newResourceServer(verifier, normalized, observers), nil
}

type boundedTransport struct {
	next http.RoundTripper
}

func (transport *boundedTransport) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	if request.URL.Scheme != "https" {
		return nil, errors.New("OIDC provider request must use HTTPS")
	}
	response, err := transport.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.Body == nil {
		return nil, errors.New("OIDC provider response body is nil")
	}
	response.Body = http.MaxBytesReader(nil, response.Body, maxProviderResponseBytes)
	return response, nil
}

func boundedHTTPClient(client *http.Client) (*http.Client, error) {
	if client == nil {
		return nil, errors.New("discover OIDC resource server: HTTP client is nil")
	}
	if client.Timeout <= 0 {
		return nil, errors.New("discover OIDC resource server: HTTP client timeout must be positive")
	}
	next := client.Transport
	if next == nil {
		next = http.DefaultTransport
	} else if nilInterface(next) {
		return nil, errors.New("discover OIDC resource server: HTTP transport is nil")
	}
	bounded := *client
	bounded.Transport = &boundedTransport{next: next}
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &bounded, nil
}
