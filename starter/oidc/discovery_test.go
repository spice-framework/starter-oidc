package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDiscoverVerifiesWithBoundedCallerClient(t *testing.T) {
	t.Parallel()
	key := newSigningKey(t)
	var issuer string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			writeDiscoveryJSON(t, writer, map[string]any{
				"issuer":                                issuer,
				"jwks_uri":                              issuer + "/keys",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			writeDiscoveryJSON(t, writer, testJWKSet(key.N, key.E))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer upstream.Close()
	issuer = upstream.URL
	client := upstream.Client()
	client.Timeout = time.Second
	server, err := Discover(context.Background(), client, Options{
		Issuer:   issuer,
		Audience: testAudience,
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	principal, err := server.Authenticate(
		context.Background(),
		signedToken(t, key, tokenClaims(map[string]any{"iss": issuer})),
	)
	if err != nil || principal.Subject() != "subject-1" {
		t.Fatalf("Authenticate(discovered) = %#v, %v", principal, err)
	}
}

func TestDiscoverRejectsUnsafeTransportAndMetadata(t *testing.T) {
	t.Parallel()
	options := testOptions()
	if _, err := Discover(nilContext(), &http.Client{Timeout: time.Second}, options); err == nil {
		t.Fatal("Discover(nil context) error = nil")
	}
	if _, err := Discover(context.Background(), nil, options); err == nil {
		t.Fatal("Discover(nil client) error = nil")
	}
	if _, err := Discover(context.Background(), &http.Client{}, options); err == nil {
		t.Fatal("Discover(unbounded client) error = nil")
	}
	var typedNil *testTransport
	if _, err := Discover(context.Background(), &http.Client{
		Timeout:   time.Second,
		Transport: typedNil,
	}, options); err == nil {
		t.Fatal("Discover(typed nil transport) error = nil")
	}
	assertDiscoveryFailure(t, func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, testIssuer, http.StatusFound)
	})
	assertDiscoveryFailure(t, func(writer http.ResponseWriter, _ *http.Request) {
		if _, err := io.WriteString(
			writer,
			strings.Repeat("x", maxProviderResponseBytes+1),
		); err != nil {
			t.Errorf("WriteString() error = %v", err)
		}
	})
}

func TestDiscoverHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Discover(ctx, &http.Client{Timeout: time.Second}, testOptions()); err == nil {
		t.Fatal("Discover(canceled context) error = nil")
	}
}

func TestDiscoverRejectsNonHTTPSKeyEndpoint(t *testing.T) {
	t.Parallel()
	key := newSigningKey(t)
	var issuer string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		_ *http.Request,
	) {
		writeDiscoveryJSON(t, writer, map[string]any{
			"issuer":                                issuer,
			"jwks_uri":                              "http://keys.example/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer upstream.Close()
	issuer = upstream.URL
	client := upstream.Client()
	client.Timeout = time.Second
	server, err := Discover(context.Background(), client, Options{
		Issuer:   issuer,
		Audience: testAudience,
	})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	_, err = server.Authenticate(
		context.Background(),
		signedToken(t, key, tokenClaims(map[string]any{"iss": issuer})),
	)
	authenticationErr, ok := errors.AsType[*AuthenticationError](err)
	if !ok || authenticationErr.Reason != ReasonInvalid {
		t.Fatalf("Authenticate(non-HTTPS keys) error = %#v", err)
	}
}

type testTransport struct{}

func (*testTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected request")
}

func assertDiscoveryFailure(
	t *testing.T,
	handler func(http.ResponseWriter, *http.Request),
) {
	t.Helper()
	upstream := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer upstream.Close()
	client := upstream.Client()
	client.Timeout = time.Second
	if _, err := Discover(context.Background(), client, Options{
		Issuer:   upstream.URL,
		Audience: testAudience,
	}); err == nil {
		t.Fatal("Discover() error = nil")
	}
}

func testJWKSet(modulus *big.Int, exponent int) map[string]any {
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": "test-key",
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(modulus.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(
				big.NewInt(int64(exponent)).Bytes(),
			),
		}},
	}
}

func writeDiscoveryJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("Encode() error = %v", err)
	}
}
