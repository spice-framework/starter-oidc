package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
)

const (
	developmentModule  = "github.com/spice-framework/development"
	developmentTool    = developmentModule + "/cmd/spice-dev"
	developmentVersion = "v0.0.0-20260806121906-963bb6676069"
	toolchainModule    = "github.com/spice-framework/toolchain"
	toolchainTool      = toolchainModule + "/cmd/spice-library-release-verify"
	toolchainVersion   = "v0.0.0-20260806054457-a83d9b58034c"
	rehearsalVersion   = "v0.0.0-rehearsal"
)

func requireReleaseTool(ctx context.Context, root string) error {
	content, err := capture(ctx, root, nil, "go", "mod", "edit", "-json")
	if err != nil {
		return fmt.Errorf("read release tool authorization: %w", err)
	}
	return validateReleaseToolAuthorization([]byte(content))
}

func validateReleaseToolAuthorization(content []byte) error {
	var metadata struct {
		Require []struct {
			Path    string
			Version string
		}
		Tool []struct {
			Path string
		}
	}
	if err := json.Unmarshal(content, &metadata); err != nil {
		return fmt.Errorf("decode release tool authorization: %w", err)
	}
	authorizations := [...]struct {
		module  string
		tool    string
		version string
	}{
		{module: developmentModule, tool: developmentTool, version: developmentVersion},
		{module: toolchainModule, tool: toolchainTool, version: toolchainVersion},
	}
	for _, authorization := range authorizations {
		toolCount := 0
		for _, tool := range metadata.Tool {
			if tool.Path == authorization.tool {
				toolCount++
			}
		}
		if toolCount != 1 {
			return fmt.Errorf(
				"go.mod must authorize exactly one %s tool declaration; found %d",
				authorization.tool,
				toolCount,
			)
		}
		required := false
		for _, requirement := range metadata.Require {
			if requirement.Path != authorization.module {
				continue
			}
			required = true
			if requirement.Version != authorization.version {
				return fmt.Errorf(
					"go.mod selects release tool %s; require exactly %s",
					requirement.Version,
					authorization.version,
				)
			}
		}
		if !required {
			return fmt.Errorf(
				"go.mod must require %s at exactly %s",
				authorization.module,
				authorization.version,
			)
		}
	}
	return nil
}

func releaseParity(ctx context.Context, root string) error {
	parent, err := os.MkdirTemp("", "starter-oidc-release-rehearsal-*")
	if err != nil {
		return fmt.Errorf("create release rehearsal root: %w", err)
	}
	defer removeTree(parent)

	offlineVendor := map[string]string{"GOFLAGS": "-mod=vendor"}
	resolved, err := capture(ctx, root, offlineVendor, "go", "tool", "-n", developmentTool)
	if err != nil {
		return fmt.Errorf("resolve authorized central release tool: %w", err)
	}
	if strings.TrimSpace(resolved) == "" {
		return errors.New("resolve authorized central release tool: empty executable path")
	}

	plan, err := capture(
		ctx,
		root,
		offlineVendor,
		"go",
		"tool",
		developmentTool,
		"library-release",
		"plan",
		"--root="+root,
		"--repo=starter-oidc",
		"--version="+rehearsalVersion,
		"--rehearsal",
	)
	if err != nil {
		return fmt.Errorf("plan central release rehearsal: %w", err)
	}
	planFile := filepath.Join(parent, "plan.json")
	if writeErr := os.WriteFile(planFile, []byte(plan+"\n"), 0o600); writeErr != nil {
		return fmt.Errorf("write central release rehearsal plan: %w", writeErr)
	}

	centralOutputs := []string{
		filepath.Join(parent, "central-first"),
		filepath.Join(parent, "central-second"),
	}
	for _, outputDir := range centralOutputs {
		if runErr := command(
			ctx,
			root,
			offlineVendor,
			"go",
			"tool",
			developmentTool,
			"library-release",
			"render",
			"--root="+root,
			"--plan="+planFile,
			"--output="+outputDir,
		); runErr != nil {
			return fmt.Errorf("render central release rehearsal: %w", runErr)
		}
	}

	retainedOutputs := []string{
		filepath.Join(parent, "retained-first"),
		filepath.Join(parent, "retained-second"),
	}
	for _, outputDir := range retainedOutputs {
		if runErr := command(
			ctx,
			root,
			offlineVendor,
			"go",
			"run",
			"./cmd/starter-oidc-release",
			"-rehearsal",
			"-version="+rehearsalVersion,
			"-output="+outputDir,
		); runErr != nil {
			return fmt.Errorf("render retained release rehearsal: %w", runErr)
		}
	}

	central, err := deterministicReleaseArtifacts("central", centralOutputs)
	if err != nil {
		return err
	}
	retained, err := deterministicReleaseArtifacts("retained", retainedOutputs)
	if err != nil {
		return err
	}
	return validateReleaseParity(centralOutputs[0], central, retainedOutputs[0], retained)
}

func deterministicReleaseArtifacts(
	name string,
	outputs []string,
) (map[string][sha256.Size]byte, error) {
	first, err := treeDigests(outputs[0])
	if err != nil {
		return nil, err
	}
	second, err := treeDigests(outputs[1])
	if err != nil {
		return nil, err
	}
	if !maps.Equal(first, second) {
		return nil, fmt.Errorf("identical %s release rehearsals produced different artifacts", name)
	}
	return first, nil
}

func validateReleaseParity(
	centralRoot string,
	central map[string][sha256.Size]byte,
	retainedRoot string,
	retained map[string][sha256.Size]byte,
) error {
	base := "starter-oidc_" + strings.TrimPrefix(rehearsalVersion, "v")
	archive := base + "_source.tar.gz"
	sbom := base + "_sbom.spdx.json"
	expected := []string{"checksums.txt", sbom, archive}
	for name, artifacts := range map[string]map[string][sha256.Size]byte{
		"central":  central,
		"retained": retained,
	} {
		actual := slices.Sorted(maps.Keys(artifacts))
		if !slices.Equal(actual, expected) {
			return fmt.Errorf(
				"%s release rehearsal artifacts %v do not match %v; signatures are forbidden",
				name,
				actual,
				expected,
			)
		}
	}
	if central[archive] != retained[archive] {
		return errors.New("central and retained source archives are not byte-identical")
	}
	if err := validateReleaseChecksums(centralRoot, central, sbom, archive); err != nil {
		return fmt.Errorf("central release rehearsal: %w", err)
	}
	if err := validateReleaseChecksums(retainedRoot, retained, sbom, archive); err != nil {
		return fmt.Errorf("retained release rehearsal: %w", err)
	}
	centralSBOM, err := readReleaseArtifact(centralRoot, sbom)
	if err != nil {
		return err
	}
	retainedSBOM, err := readReleaseArtifact(retainedRoot, sbom)
	if err != nil {
		return err
	}
	return validateReleaseSBOMParity(centralSBOM, retainedSBOM)
}

func validateReleaseChecksums(
	root string,
	artifacts map[string][sha256.Size]byte,
	names ...string,
) error {
	content, err := readReleaseArtifact(root, "checksums.txt")
	if err != nil {
		return err
	}
	if len(content) == 0 || content[len(content)-1] != '\n' {
		return errors.New("checksums.txt must end with one newline")
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	orderedNames := slices.Clone(names)
	slices.Sort(orderedNames)
	if len(lines) != len(orderedNames) {
		return fmt.Errorf("checksums.txt has %d lines; require %d", len(lines), len(orderedNames))
	}
	for index, name := range orderedNames {
		want := fmt.Sprintf("%x", artifacts[name])
		wantLine := want + "  " + name
		if lines[index] != wantLine {
			return fmt.Errorf("checksums.txt line %d is %q; require canonical %q", index+1, lines[index], wantLine)
		}
	}
	return nil
}

type releaseSBOM struct {
	SPDXVersion       string           `json:"spdxVersion"`
	DataLicense       string           `json:"dataLicense"`
	SPDXID            string           `json:"SPDXID"`
	Name              string           `json:"name"`
	DocumentNamespace string           `json:"documentNamespace"`
	CreationInfo      sbomCreationInfo `json:"creationInfo"`
	Packages          []map[string]any `json:"packages"`
	Relationships     []map[string]any `json:"relationships"`
}

type sbomCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

func validateReleaseSBOMParity(centralContent, retainedContent []byte) error {
	central, err := decodeReleaseSBOM(centralContent)
	if err != nil {
		return fmt.Errorf("decode central release SBOM: %w", err)
	}
	retained, err := decodeReleaseSBOM(retainedContent)
	if err != nil {
		return fmt.Errorf("decode retained release SBOM: %w", err)
	}
	baseNamespace := "https://github.com/spice-framework/starter-oidc/releases/" +
		rehearsalVersion + "/spdx/"
	if central.Name != "starter-oidc "+rehearsalVersion ||
		!validSBOMNamespace(central.DocumentNamespace, baseNamespace+"v1/") ||
		!slices.Equal(central.CreationInfo.Creators, []string{
			"Organization: Spice Framework",
			"Tool: github.com/spice-framework/development/cmd/spice-dev library-release renderer/v1",
		}) {
		return errors.New("central release SBOM provenance does not match renderer/v1")
	}
	if retained.Name != "Spice OIDC starter "+rehearsalVersion ||
		!validSBOMNamespace(retained.DocumentNamespace, baseNamespace) ||
		strings.HasPrefix(retained.DocumentNamespace, baseNamespace+"v1/") ||
		!slices.Equal(retained.CreationInfo.Creators, []string{
			"Organization: Spice Authors",
			"Tool: github.com/spice-framework/starter-oidc/cmd/starter-oidc-release",
		}) {
		return errors.New("retained release SBOM provenance does not match the starter builder")
	}
	if central.DocumentNamespace == retained.DocumentNamespace {
		return errors.New("central and retained SBOM namespaces must identify their distinct builders")
	}
	central.Name = retained.Name
	central.DocumentNamespace = retained.DocumentNamespace
	central.CreationInfo.Creators = slices.Clone(retained.CreationInfo.Creators)
	if !reflect.DeepEqual(central, retained) {
		return errors.New("central and retained SBOMs differ outside documented provenance fields")
	}
	return nil
}

func decodeReleaseSBOM(content []byte) (releaseSBOM, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var result releaseSBOM
	if err := decoder.Decode(&result); err != nil {
		return releaseSBOM{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return releaseSBOM{}, errors.New("release SBOM has trailing JSON values")
		}
		return releaseSBOM{}, err
	}
	return result, nil
}

func validSBOMNamespace(value, prefix string) bool {
	digest, found := strings.CutPrefix(value, prefix)
	if !found || len(digest) != sha256.Size*2 {
		return false
	}
	for _, character := range digest {
		decimal := character >= '0' && character <= '9'
		hex := character >= 'a' && character <= 'f'
		if !decimal && !hex {
			return false
		}
	}
	return true
}

func readReleaseArtifact(rootPath, name string) (_ []byte, resultErr error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open release artifact root: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	content, err := root.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("read release artifact %q: %w", name, err)
	}
	return content, nil
}
