package oidc

import (
	"slices"
	"testing"

	spicestarter "github.com/spice-framework/spice/annotation/sdk/starter"
)

func TestManifestDeclaresStandaloneReviewedStarter(t *testing.T) {
	t.Parallel()

	manifest := Manifest()
	spec := manifest.Spec()
	if spec.Schema != spicestarter.Schema ||
		spec.ID != "github.com/spice-framework/starter-oidc" ||
		spec.Module != "github.com/spice-framework/starter-oidc" ||
		spec.Version != "0.1.0-dev" ||
		spec.SpiceAPI != spicestarter.APIVersion ||
		spec.MinimumGo != "1.26" ||
		spec.License != "Apache-2.0" ||
		spec.Review != "docs/dependency-review.md" ||
		spec.Activation.Mode != spicestarter.ActivationExplicitConstructor {
		t.Fatalf("Manifest() = %#v", spec)
	}
	wantCapabilities := []string{"security.oidc-resource-server"}
	if !slices.Equal(spec.Capabilities, wantCapabilities) {
		t.Fatalf("capabilities = %v, want %v", spec.Capabilities, wantCapabilities)
	}
	wantEntryPoints := []spicestarter.EntryPoint{
		{Package: "github.com/spice-framework/starter-oidc", Symbol: "Discover"},
		{Package: "github.com/spice-framework/starter-oidc", Symbol: "NewResourceServer"},
	}
	if !slices.Equal(spec.Activation.EntryPoints, wantEntryPoints) {
		t.Fatalf("entrypoints = %#v, want %#v", spec.Activation.EntryPoints, wantEntryPoints)
	}
	if len(spec.Dependencies) != 1 ||
		spec.Dependencies[0] != (spicestarter.Dependency{
			Module:  "github.com/coreos/go-oidc/v3",
			Version: "v3.20.0",
			License: "Apache-2.0",
		}) {
		t.Fatalf("dependencies = %#v", spec.Dependencies)
	}
	if err := manifest.Compatible(spicestarter.APIVersion, "go1.26.5"); err != nil {
		t.Fatalf("Compatible() error = %v", err)
	}
	if err := manifest.Compatible("spice.starter/v2", "go1.26.5"); err == nil {
		t.Fatal("Compatible(mismatched Spice API) error = nil")
	}
	if err := manifest.Compatible(spicestarter.APIVersion, "go1.25.9"); err == nil {
		t.Fatal("Compatible(unsupported Go) error = nil")
	}
}
