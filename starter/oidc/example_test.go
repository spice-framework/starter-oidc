package oidc_test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"

	spiceoidc "github.com/spice-framework/spice/starter/oidc"
)

func ExampleNewResourceServer() {
	var trustedPublicKey *rsa.PublicKey
	keySet := &coreoidc.StaticKeySet{
		PublicKeys: []crypto.PublicKey{trustedPublicKey},
	}
	server, err := spiceoidc.NewResourceServer(keySet, spiceoidc.Options{
		Issuer:   "https://issuer.example",
		Audience: "orders-api",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	_, err = server.Authenticate(context.Background(), "verified.jwt.value")
	fmt.Println(err != nil)
	// Output:
	// true
}
