// Package oidc provides an opt-in OpenID Connect JWT resource-server adapter.
// It verifies tokens before creating Spice security principals.
package oidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/StevenBuglione/spice/security"
	"github.com/StevenBuglione/spice/web"
)

const (
	defaultRolesClaim  = "roles"
	defaultScopesClaim = "scope"
	defaultTokenBytes  = 16 << 10
	maxTokenBytes      = 1 << 20
)

// Options defines exact issuer, audience, claim, algorithm, and token-size
// boundaries. Issuer and audience must match the resource server's tokens.
type Options struct {
	Issuer               string
	Audience             string
	RolesClaim           string
	ScopesClaim          string
	SupportedSigningAlgs []string
	MaxTokenBytes        int
}

// Reason is a bounded authentication result class.
type Reason string

const (
	// ReasonAllowed identifies a verified token and constructed principal.
	ReasonAllowed Reason = "allowed"
	// ReasonMissing identifies a request without bearer credentials.
	ReasonMissing Reason = "missing"
	// ReasonMalformed identifies invalid bearer syntax or an oversized token.
	ReasonMalformed Reason = "malformed"
	// ReasonInvalid identifies failed signature, issuer, audience, or time checks.
	ReasonInvalid Reason = "invalid"
	// ReasonClaims identifies invalid identity, role, or scope claims.
	ReasonClaims Reason = "claims"
)

// Decision contains no token, subject, or claim data.
type Decision struct {
	Allowed  bool
	Reason   Reason
	Duration time.Duration
}

// Observer receives completed authentication decisions synchronously.
type Observer func(context.Context, Decision)

// ResourceServer verifies JWTs and creates immutable Spice principals.
type ResourceServer struct {
	verifier      *coreoidc.IDTokenVerifier
	rolesClaim    string
	scopesClaim   string
	maxTokenBytes int
	observers     []Observer
}

// NewResourceServer constructs an offline resource server around a caller-owned
// key set. Signature, issuer, audience, and expiry checks cannot be disabled.
func NewResourceServer(
	keySet coreoidc.KeySet,
	options Options,
	observers ...Observer,
) (*ResourceServer, error) {
	normalized, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	if nilInterface(keySet) {
		return nil, errors.New("construct OIDC resource server: key set is nil")
	}
	if err := validateObservers(observers); err != nil {
		return nil, err
	}
	verifier := coreoidc.NewVerifier(normalized.Issuer, keySet, &coreoidc.Config{
		ClientID:             normalized.Audience,
		SupportedSigningAlgs: normalized.SupportedSigningAlgs,
	})
	return newResourceServer(verifier, normalized, observers), nil
}

// Authenticate verifies one raw JWT and constructs its immutable principal.
func (server *ResourceServer) Authenticate(
	ctx context.Context,
	rawToken string,
) (security.Principal, error) {
	if ctx == nil {
		return security.Principal{}, errors.New("authenticate OIDC token: context is nil")
	}
	if server == nil || server.verifier == nil {
		return security.Principal{}, errors.New("authenticate OIDC token: resource server is nil")
	}
	started := time.Now()
	reason := ReasonInvalid
	defer func() {
		server.observe(ctx, Decision{
			Allowed:  reason == ReasonAllowed,
			Reason:   reason,
			Duration: time.Since(started),
		})
	}()
	if rawToken == "" {
		reason = ReasonMissing
		return security.Principal{}, authenticationError(reason)
	}
	if len(rawToken) > server.maxTokenBytes || strings.ContainsAny(rawToken, " \t\r\n") {
		reason = ReasonMalformed
		return security.Principal{}, authenticationError(reason)
	}
	if !validAccessTokenType(rawToken) {
		return security.Principal{}, authenticationError(reason)
	}
	token, err := server.verifier.Verify(ctx, rawToken)
	if err != nil {
		return security.Principal{}, authenticationError(reason)
	}
	var claims map[string]json.RawMessage
	if claimsErr := token.Claims(&claims); claimsErr != nil {
		reason = ReasonClaims
		return security.Principal{}, authenticationError(reason)
	}
	roles, err := decodeStringClaim(claims[server.rolesClaim], false)
	if err != nil {
		reason = ReasonClaims
		return security.Principal{}, authenticationError(reason)
	}
	scopes, err := decodeStringClaim(claims[server.scopesClaim], true)
	if err != nil {
		reason = ReasonClaims
		return security.Principal{}, authenticationError(reason)
	}
	principal, err := security.NewPrincipal(token.Subject, token.Issuer, roles, scopes)
	if err != nil {
		reason = ReasonClaims
		return security.Principal{}, authenticationError(reason)
	}
	reason = ReasonAllowed
	return principal, nil
}

// Middleware constructs bearer authentication middleware.
func (server *ResourceServer) Middleware(
	onWriteFailure security.WriteFailure,
) (web.Middleware, error) {
	if server == nil || server.verifier == nil {
		return nil, errors.New("construct OIDC middleware: resource server is nil")
	}
	return func(next http.Handler) http.Handler {
		if next == nil {
			return nil
		}
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			rawToken, reason := bearerToken(request.Header.Values("Authorization"))
			if reason != ReasonAllowed {
				server.observeDeniedRequest(request.Context(), reason)
				writeAuthenticationError(writer, request, reason, onWriteFailure)
				return
			}
			principal, err := server.Authenticate(request.Context(), rawToken)
			if err != nil {
				writeAuthenticationError(writer, request, authenticationReason(err), onWriteFailure)
				return
			}
			ctx, err := security.WithPrincipal(request.Context(), principal)
			if err != nil {
				writeAuthenticationError(writer, request, ReasonClaims, onWriteFailure)
				return
			}
			next.ServeHTTP(writer, request.WithContext(ctx))
		})
	}, nil
}

// AuthenticationError is a safe unauthenticated failure.
type AuthenticationError struct {
	Reason Reason
}

// Error returns no token, claim, or upstream verifier data.
func (*AuthenticationError) Error() string {
	return "authentication failed"
}

// Problem returns a safe RFC 9457 HTTP 401 response.
func (*AuthenticationError) Problem() web.Problem {
	return web.Problem{
		Type:   "https://spice.dev/problems/unauthenticated",
		Title:  "Authentication required",
		Status: http.StatusUnauthorized,
	}
}

func newResourceServer(
	verifier *coreoidc.IDTokenVerifier,
	options Options,
	observers []Observer,
) *ResourceServer {
	return &ResourceServer{
		verifier:      verifier,
		rolesClaim:    options.RolesClaim,
		scopesClaim:   options.ScopesClaim,
		maxTokenBytes: options.MaxTokenBytes,
		observers:     append([]Observer(nil), observers...),
	}
}

func normalizeOptions(options Options) (Options, error) {
	if err := validateIdentityOptions(options); err != nil {
		return Options{}, err
	}
	if err := normalizeClaimOptions(&options); err != nil {
		return Options{}, err
	}
	if err := normalizeTokenLimit(&options); err != nil {
		return Options{}, err
	}
	if err := normalizeAlgorithms(&options); err != nil {
		return Options{}, err
	}
	return options, nil
}

func validateIdentityOptions(options Options) error {
	issuerURL, err := url.Parse(options.Issuer)
	if err != nil ||
		issuerURL.Scheme != "https" ||
		issuerURL.Host == "" ||
		issuerURL.User != nil ||
		issuerURL.RawQuery != "" ||
		issuerURL.Fragment != "" {
		return errors.New("construct OIDC resource server: issuer must be an HTTPS URL")
	}
	if options.Audience == "" || strings.TrimSpace(options.Audience) != options.Audience {
		return errors.New("construct OIDC resource server: audience is required")
	}
	return nil
}

func normalizeClaimOptions(options *Options) error {
	if options.RolesClaim == "" {
		options.RolesClaim = defaultRolesClaim
	}
	if options.ScopesClaim == "" {
		options.ScopesClaim = defaultScopesClaim
	}
	if strings.TrimSpace(options.RolesClaim) != options.RolesClaim ||
		strings.TrimSpace(options.ScopesClaim) != options.ScopesClaim {
		return errors.New("construct OIDC resource server: claim names must have no surrounding space")
	}
	return nil
}

func normalizeTokenLimit(options *Options) error {
	if options.MaxTokenBytes == 0 {
		options.MaxTokenBytes = defaultTokenBytes
	}
	if options.MaxTokenBytes < 0 || options.MaxTokenBytes > maxTokenBytes {
		return fmt.Errorf(
			"construct OIDC resource server: maximum token bytes must be between 1 and %d",
			maxTokenBytes,
		)
	}
	return nil
}

func normalizeAlgorithms(options *Options) error {
	options.SupportedSigningAlgs = append([]string(nil), options.SupportedSigningAlgs...)
	for index, algorithm := range options.SupportedSigningAlgs {
		if !supportedAlgorithm(algorithm) {
			return fmt.Errorf(
				"construct OIDC resource server: signing algorithm %d is invalid",
				index,
			)
		}
	}
	slices.Sort(options.SupportedSigningAlgs)
	options.SupportedSigningAlgs = slices.Compact(options.SupportedSigningAlgs)
	return nil
}

func supportedAlgorithm(algorithm string) bool {
	switch algorithm {
	case coreoidc.RS256, coreoidc.RS384, coreoidc.RS512,
		coreoidc.ES256, coreoidc.ES384, coreoidc.ES512,
		coreoidc.PS256, coreoidc.PS384, coreoidc.PS512,
		coreoidc.EdDSA:
		return true
	default:
		return false
	}
}

func validateObservers(observers []Observer) error {
	for index, observer := range observers {
		if observer == nil {
			return fmt.Errorf("construct OIDC resource server: observer %d is nil", index)
		}
	}
	return nil
}

func decodeStringClaim(raw json.RawMessage, split bool) ([]string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var values []string
	if raw[0] == '[' {
		if err := json.Unmarshal(raw, &values); err != nil {
			return nil, err
		}
		return values, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if split {
		return strings.Fields(value), nil
	}
	return []string{value}, nil
}

func validAccessTokenType(rawToken string) bool {
	encodedHeader, _, found := strings.Cut(rawToken, ".")
	if !found {
		return false
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(encodedHeader)
	if err != nil {
		return false
	}
	var header struct {
		Type string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return false
	}
	return strings.EqualFold(header.Type, "at+jwt") ||
		strings.EqualFold(header.Type, "application/at+jwt")
}

func bearerToken(values []string) (string, Reason) {
	if len(values) == 0 {
		return "", ReasonMissing
	}
	if len(values) != 1 || values[0] != strings.TrimSpace(values[0]) {
		return "", ReasonMalformed
	}
	scheme, token, found := strings.Cut(values[0], " ")
	if !found ||
		!strings.EqualFold(scheme, "Bearer") ||
		token == "" ||
		strings.ContainsAny(token, " \t\r\n") {
		return "", ReasonMalformed
	}
	return token, ReasonAllowed
}

func (server *ResourceServer) observe(ctx context.Context, decision Decision) {
	for _, observer := range server.observers {
		observer(ctx, decision)
	}
}

func (server *ResourceServer) observeDeniedRequest(ctx context.Context, reason Reason) {
	server.observe(ctx, Decision{Reason: reason})
}

func writeAuthenticationError(
	writer http.ResponseWriter,
	request *http.Request,
	reason Reason,
	onWriteFailure security.WriteFailure,
) {
	challenge := "Bearer"
	if reason != ReasonMissing {
		challenge += ` error="invalid_token"`
	}
	writer.Header().Set("WWW-Authenticate", challenge)
	if err := web.WriteError(writer, request, authenticationError(reason), nil); err != nil &&
		onWriteFailure != nil {
		onWriteFailure(request.Context(), err)
	}
}

func authenticationError(reason Reason) *AuthenticationError {
	return &AuthenticationError{Reason: reason}
}

func authenticationReason(err error) Reason {
	authenticationErr, ok := errors.AsType[*AuthenticationError](err)
	if !ok {
		return ReasonInvalid
	}
	return authenticationErr.Reason
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return (reflected.Kind() == reflect.Interface || reflected.Kind() == reflect.Pointer) &&
		reflected.IsNil()
}
