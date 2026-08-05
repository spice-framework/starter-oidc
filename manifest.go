package oidc

import spicestarter "github.com/spice-framework/spice/annotation/sdk/starter"

// Manifest returns OIDC resource-server compatibility and review metadata.
func Manifest() spicestarter.Manifest {
	return spicestarter.Must(spicestarter.Spec{
		Schema:    spicestarter.Schema,
		ID:        "github.com/spice-framework/starter-oidc",
		Version:   "0.1.0-dev",
		Module:    "github.com/spice-framework/starter-oidc",
		SpiceAPI:  spicestarter.APIVersion,
		MinimumGo: "1.26",
		License:   "Apache-2.0",
		Review:    "docs/dependency-review.md",
		Activation: spicestarter.Activation{
			Mode: spicestarter.ActivationExplicitConstructor,
			EntryPoints: []spicestarter.EntryPoint{
				{
					Package: "github.com/spice-framework/starter-oidc",
					Symbol:  "Discover",
				},
				{
					Package: "github.com/spice-framework/starter-oidc",
					Symbol:  "NewResourceServer",
				},
			},
		},
		Capabilities: []string{"security.oidc-resource-server"},
		Dependencies: []spicestarter.Dependency{
			{
				Module:  "github.com/coreos/go-oidc/v3",
				Version: "v3.20.0",
				License: "Apache-2.0",
			},
		},
	})
}
