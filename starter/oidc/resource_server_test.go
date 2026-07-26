package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/StevenBuglione/spice/security"
	"github.com/StevenBuglione/spice/web"
)

const (
	testIssuer   = "https://issuer.example"
	testAudience = "spice-api"
)

func TestResourceServerAuthenticatesVerifiedClaims(t *testing.T) {
	t.Parallel()
	key := newSigningKey(t)
	var decisions []Decision
	server := newTestResourceServer(t, key, Options{
		Issuer:   testIssuer,
		Audience: testAudience,
	}, func(_ context.Context, decision Decision) {
		decisions = append(decisions, decision)
	})
	rawToken := signedToken(t, key, tokenClaims(map[string]any{
		"roles": []string{"user", "admin", "admin"},
		"scope": "orders:read orders:write",
	}))
	principal, err := server.Authenticate(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if principal.Subject() != "subject-1" ||
		principal.Issuer() != testIssuer ||
		!slices.Equal(principal.Roles(), []string{"admin", "user"}) ||
		!slices.Equal(principal.Scopes(), []string{"orders:read", "orders:write"}) {
		t.Fatalf("principal = %#v", principal)
	}
	if len(decisions) != 1 ||
		!decisions[0].Allowed ||
		decisions[0].Reason != ReasonAllowed ||
		decisions[0].Duration < 0 {
		t.Fatalf("decisions = %#v", decisions)
	}
}

func TestResourceServerRejectsTokensSafely(t *testing.T) {
	t.Parallel()
	key := newSigningKey(t)
	var decisions []Decision
	server := newTestResourceServer(t, key, Options{
		Issuer:        testIssuer,
		Audience:      testAudience,
		MaxTokenBytes: 1024,
	}, func(_ context.Context, decision Decision) {
		decisions = append(decisions, decision)
	})
	tests := []struct {
		name   string
		token  string
		reason Reason
	}{
		{name: "missing", reason: ReasonMissing},
		{name: "whitespace", token: "not a token", reason: ReasonMalformed},
		{name: "oversized", token: strings.Repeat("x", 1025), reason: ReasonMalformed},
		{
			name: "wrong audience",
			token: signedToken(t, key, tokenClaims(map[string]any{
				"aud": "another-api",
			})),
			reason: ReasonInvalid,
		},
		{
			name:   "ID token type",
			token:  signedTokenWithType(t, key, tokenClaims(nil), "JWT"),
			reason: ReasonInvalid,
		},
		{
			name: "expired",
			token: signedToken(t, key, tokenClaims(map[string]any{
				"exp": time.Now().Add(-time.Minute).Unix(),
			})),
			reason: ReasonInvalid,
		},
		{
			name: "invalid claims",
			token: signedToken(t, key, tokenClaims(map[string]any{
				"roles": 42,
			})),
			reason: ReasonClaims,
		},
	}
	for _, test := range tests {
		_, err := server.Authenticate(context.Background(), test.token)
		authenticationErr, ok := errors.AsType[*AuthenticationError](err)
		if !ok ||
			authenticationErr.Reason != test.reason ||
			err.Error() != "authentication failed" ||
			authenticationErr.Problem().Status != http.StatusUnauthorized {
			t.Fatalf("%s: Authenticate() error = %#v", test.name, err)
		}
		if test.token != "" && strings.Contains(err.Error(), test.token) {
			t.Fatalf("%s: Authenticate() leaked the token", test.name)
		}
	}
	if len(decisions) != len(tests) {
		t.Fatalf("len(decisions) = %d, want %d", len(decisions), len(tests))
	}
	for index, test := range tests {
		if decisions[index].Allowed || decisions[index].Reason != test.reason {
			t.Fatalf("decisions[%d] = %#v", index, decisions[index])
		}
	}
}

func TestMiddlewareAuthenticatesBearerRequests(t *testing.T) {
	t.Parallel()
	key := newSigningKey(t)
	server := newTestResourceServer(t, key, testOptions())
	middleware, err := server.Middleware(nil)
	if err != nil {
		t.Fatalf("Middleware() error = %v", err)
	}
	handler, err := web.Chain(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		principal, ok := security.PrincipalFromContext(request.Context())
		if !ok || principal.Subject() != "subject-1" {
			t.Fatalf("PrincipalFromContext() = %#v, %v", principal, ok)
		}
		writer.WriteHeader(http.StatusNoContent)
	}), middleware)
	if err != nil {
		t.Fatalf("web.Chain() error = %v", err)
	}
	rawToken := signedToken(t, key, tokenClaims(nil))
	request := httptest.NewRequest(http.MethodGet, "/orders", nil)
	request.Header.Set("Authorization", "bearer "+rawToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("authenticated status = %d", response.Code)
	}

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/orders", nil))
	if missing.Code != http.StatusUnauthorized ||
		missing.Header().Get("WWW-Authenticate") != "Bearer" ||
		missing.Header().Get("Content-Type") != "application/problem+json" ||
		strings.Contains(missing.Body.String(), "missing") {
		t.Fatalf("missing response = %d %s", missing.Code, missing.Body.String())
	}

	duplicateRequest := httptest.NewRequest(http.MethodGet, "/orders", nil)
	duplicateRequest.Header.Add("Authorization", "Bearer "+rawToken)
	duplicateRequest.Header.Add("Authorization", "Bearer "+rawToken)
	duplicate := httptest.NewRecorder()
	handler.ServeHTTP(duplicate, duplicateRequest)
	if duplicate.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate status = %d", duplicate.Code)
	}
	if duplicate.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatalf("duplicate challenge = %q", duplicate.Header().Get("WWW-Authenticate"))
	}
	if middleware(nil) != nil {
		t.Fatal("Middleware(nil) returned a handler")
	}
}

func TestOptionalMiddlewareAuthenticatesOnlyPresentedCredentials(t *testing.T) {
	t.Parallel()
	key := newSigningKey(t)
	var decisions []Decision
	server := newTestResourceServer(
		t,
		key,
		testOptions(),
		func(_ context.Context, decision Decision) {
			decisions = append(decisions, decision)
		},
	)
	middleware, err := server.OptionalMiddleware(nil)
	if err != nil {
		t.Fatalf("OptionalMiddleware() error = %v", err)
	}
	var authenticated []bool
	handler := middleware(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		_, found := security.PrincipalFromContext(request.Context())
		authenticated = append(authenticated, found)
		writer.WriteHeader(http.StatusNoContent)
	}))

	anonymous := httptest.NewRecorder()
	handler.ServeHTTP(
		anonymous,
		httptest.NewRequest(http.MethodGet, "/public", nil),
	)
	if anonymous.Code != http.StatusNoContent {
		t.Fatalf("anonymous status = %d", anonymous.Code)
	}

	rawToken := signedToken(t, key, tokenClaims(nil))
	verifiedRequest := httptest.NewRequest(http.MethodGet, "/protected", nil)
	verifiedRequest.Header.Set("Authorization", "Bearer "+rawToken)
	verified := httptest.NewRecorder()
	handler.ServeHTTP(verified, verifiedRequest)
	if verified.Code != http.StatusNoContent {
		t.Fatalf("verified status = %d", verified.Code)
	}

	malformedRequest := httptest.NewRequest(http.MethodGet, "/public", nil)
	malformedRequest.Header.Set("Authorization", "Basic secret")
	malformed := httptest.NewRecorder()
	handler.ServeHTTP(malformed, malformedRequest)
	if malformed.Code != http.StatusUnauthorized ||
		malformed.Header().Get("WWW-Authenticate") !=
			`Bearer error="invalid_token"` {
		t.Fatalf(
			"malformed response = %d challenge=%q",
			malformed.Code,
			malformed.Header().Get("WWW-Authenticate"),
		)
	}
	if !slices.Equal(authenticated, []bool{false, true}) {
		t.Fatalf("authenticated calls = %v", authenticated)
	}
	if len(decisions) != 2 ||
		!decisions[0].Allowed ||
		decisions[0].Reason != ReasonAllowed ||
		decisions[1].Allowed ||
		decisions[1].Reason != ReasonMalformed {
		t.Fatalf("decisions = %#v", decisions)
	}
	if middleware(nil) != nil {
		t.Fatal("OptionalMiddleware(nil) returned a handler")
	}
}

func TestMiddlewareReportsWriteFailure(t *testing.T) {
	t.Parallel()
	server := newTestResourceServer(t, newSigningKey(t), testOptions())
	var writeErr error
	middleware, err := server.Middleware(func(_ context.Context, err error) {
		writeErr = err
	})
	if err != nil {
		t.Fatalf("Middleware() error = %v", err)
	}
	handler := middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("authenticated handler called")
	}))
	handler.ServeHTTP(
		&failedResponseWriter{header: make(http.Header)},
		httptest.NewRequest(http.MethodGet, "/", nil),
	)
	if writeErr == nil {
		t.Fatal("response write failure was not reported")
	}
}

func TestResourceServerValidation(t *testing.T) {
	t.Parallel()
	keySet := &coreoidc.StaticKeySet{}
	options := testOptions()
	tests := []Options{
		{},
		{Issuer: "http://issuer.example", Audience: testAudience},
		{Issuer: testIssuer + "?tenant=1", Audience: testAudience},
		{Issuer: testIssuer, Audience: " api"},
		{Issuer: testIssuer, Audience: testAudience, RolesClaim: " roles"},
		{Issuer: testIssuer, Audience: testAudience, ScopesClaim: "scope "},
		{Issuer: testIssuer, Audience: testAudience, MaxTokenBytes: -1},
		{Issuer: testIssuer, Audience: testAudience, MaxTokenBytes: maxTokenBytes + 1},
		{Issuer: testIssuer, Audience: testAudience, SupportedSigningAlgs: []string{""}},
		{Issuer: testIssuer, Audience: testAudience, SupportedSigningAlgs: []string{"none"}},
	}
	for index, invalid := range tests {
		if _, err := NewResourceServer(keySet, invalid); err == nil {
			t.Fatalf("NewResourceServer(case %d) error = nil", index)
		}
	}
	var typedNil *coreoidc.StaticKeySet
	if _, err := NewResourceServer(typedNil, options); err == nil {
		t.Fatal("NewResourceServer(typed nil key set) error = nil")
	}
	if _, err := NewResourceServer(keySet, options, nil); err == nil {
		t.Fatal("NewResourceServer(nil observer) error = nil")
	}
	if _, err := (*ResourceServer)(nil).Authenticate(context.Background(), "token"); err == nil {
		t.Fatal("nil Authenticate() error = nil")
	}
	server := newTestResourceServer(t, newSigningKey(t), options)
	if _, err := server.Authenticate(nilContext(), "token"); err == nil {
		t.Fatal("Authenticate(nil context) error = nil")
	}
	if _, err := (*ResourceServer)(nil).Middleware(nil); err == nil {
		t.Fatal("nil Middleware() error = nil")
	}
	if _, err := (*ResourceServer)(nil).OptionalMiddleware(nil); err == nil {
		t.Fatal("nil OptionalMiddleware() error = nil")
	}
	if authenticationReason(errors.New("other")) != ReasonInvalid {
		t.Fatal("authenticationReason(other) changed")
	}
}

type failedResponseWriter struct {
	header http.Header
}

func (writer *failedResponseWriter) Header() http.Header {
	return writer.header
}

func (*failedResponseWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (*failedResponseWriter) WriteHeader(int) {}

func newSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return key
}

func newTestResourceServer(
	t *testing.T,
	key *rsa.PrivateKey,
	options Options,
	observers ...Observer,
) *ResourceServer {
	t.Helper()
	keySet := &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	server, err := NewResourceServer(keySet, options, observers...)
	if err != nil {
		t.Fatalf("NewResourceServer() error = %v", err)
	}
	return server
}

func testOptions() Options {
	return Options{Issuer: testIssuer, Audience: testAudience}
}

func tokenClaims(overrides map[string]any) map[string]any {
	claims := map[string]any{
		"iss": testIssuer,
		"sub": "subject-1",
		"aud": testAudience,
		"exp": time.Now().Add(time.Minute).Unix(),
		"iat": time.Now().Add(-time.Second).Unix(),
	}
	maps.Copy(claims, overrides)
	return claims
}

func signedToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	return signedTokenWithType(t, key, claims, "at+jwt")
}

func signedTokenWithType(
	t *testing.T,
	key *rsa.PrivateKey,
	claims map[string]any,
	tokenType string,
) string {
	t.Helper()
	headerJSON, err := json.Marshal(map[string]string{
		"alg": "RS256",
		"kid": "test-key",
		"typ": tokenType,
	})
	if err != nil {
		t.Fatalf("json.Marshal(header) error = %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("json.Marshal(claims) error = %v", err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func nilContext() context.Context {
	return nil
}
