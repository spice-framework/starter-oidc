package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateReleaseToolAuthorization(t *testing.T) {
	t.Parallel()
	valid := fmt.Sprintf(
		`{"Require":[{"Path":%q,"Version":%q},{"Path":%q,"Version":%q}],"Tool":[{"Path":%q},{"Path":%q}]}`,
		developmentModule,
		developmentVersion,
		toolchainModule,
		toolchainVersion,
		developmentTool,
		toolchainTool,
	)
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{name: "exact authorization", content: valid},
		{name: "missing tool", content: `{"Require":[]}`, wantErr: "exactly one"},
		{
			name: "wrong version",
			content: fmt.Sprintf(
				`{"Require":[{"Path":%q,"Version":"v0.0.0-wrong"}],"Tool":[{"Path":%q}]}`,
				developmentModule,
				developmentTool,
			),
			wantErr: "require exactly " + developmentVersion,
		},
		{
			name: "missing requirement",
			content: fmt.Sprintf(
				`{"Require":[],"Tool":[{"Path":%q}]}`,
				developmentTool,
			),
			wantErr: "must require " + developmentModule,
		},
		{
			name: "missing verifier tool",
			content: fmt.Sprintf(
				`{"Require":[{"Path":%q,"Version":%q},{"Path":%q,"Version":%q}],"Tool":[{"Path":%q}]}`,
				developmentModule, developmentVersion, toolchainModule, toolchainVersion, developmentTool,
			),
			wantErr: toolchainTool,
		},
		{
			name: "wrong verifier version",
			content: fmt.Sprintf(
				`{"Require":[{"Path":%q,"Version":%q},{"Path":%q,"Version":"v0.0.0-wrong"}],"Tool":[{"Path":%q},{"Path":%q}]}`,
				developmentModule, developmentVersion, toolchainModule, developmentTool, toolchainTool,
			),
			wantErr: "require exactly " + toolchainVersion,
		},
		{name: "malformed metadata", content: `{`, wantErr: "decode release tool authorization"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateReleaseToolAuthorization([]byte(test.content))
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validateReleaseToolAuthorization() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateReleaseToolAuthorization() error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestDeterministicReleaseArtifactsRejectsDrift(t *testing.T) {
	t.Parallel()
	first := t.TempDir()
	second := t.TempDir()
	writeTestFile(t, first, "artifact", "first")
	writeTestFile(t, second, "artifact", "second")
	_, err := deterministicReleaseArtifacts("fixture", []string{first, second})
	if err == nil || !strings.Contains(err.Error(), "different artifacts") {
		t.Fatalf("deterministicReleaseArtifacts() error = %v, want drift diagnostic", err)
	}
}

func TestValidateReleaseSBOMParity(t *testing.T) {
	t.Parallel()
	central, retained := releaseSBOMFixtures()
	tests := []struct {
		name    string
		mutate  func(*releaseSBOM, *releaseSBOM)
		wantErr string
	}{
		{name: "documented provenance differences"},
		{
			name: "package drift",
			mutate: func(_ *releaseSBOM, retained *releaseSBOM) {
				retained.Packages[0]["versionInfo"] = "v9.9.9"
			},
			wantErr: "outside documented provenance fields",
		},
		{
			name: "wrong central provenance",
			mutate: func(central *releaseSBOM, _ *releaseSBOM) {
				central.CreationInfo.Creators[0] = "Organization: Unknown"
			},
			wantErr: "central release SBOM provenance",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			centralCopy := cloneReleaseSBOM(t, central)
			retainedCopy := cloneReleaseSBOM(t, retained)
			if test.mutate != nil {
				test.mutate(&centralCopy, &retainedCopy)
			}
			err := validateReleaseSBOMParity(
				marshalReleaseSBOM(t, centralCopy),
				marshalReleaseSBOM(t, retainedCopy),
			)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validateReleaseSBOMParity() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateReleaseSBOMParity() error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestValidateReleaseParity(t *testing.T) {
	t.Parallel()
	centralRoot, central := writeReleaseFixture(t, true)
	retainedRoot, retained := writeReleaseFixture(t, false)
	if err := validateReleaseParity(centralRoot, central, retainedRoot, retained); err != nil {
		t.Fatalf("validateReleaseParity() error = %v", err)
	}

	t.Run("rejects signatures", func(t *testing.T) {
		t.Parallel()
		signed := cloneArtifactDigests(central)
		signed["artifact.sig"] = sha256.Sum256([]byte("signature"))
		err := validateReleaseParity(centralRoot, signed, retainedRoot, retained)
		if err == nil || !strings.Contains(err.Error(), "signatures are forbidden") {
			t.Fatalf("validateReleaseParity() error = %v, want signature diagnostic", err)
		}
	})

	t.Run("rejects archive drift", func(t *testing.T) {
		t.Parallel()
		drifted := cloneArtifactDigests(retained)
		drifted[releaseArchiveName()] = sha256.Sum256([]byte("different-source-archive"))
		err := validateReleaseParity(centralRoot, central, retainedRoot, drifted)
		if err == nil || !strings.Contains(err.Error(), "source archives are not byte-identical") {
			t.Fatalf("validateReleaseParity() error = %v, want archive diagnostic", err)
		}
	})

	t.Run("rejects checksum mismatch", func(t *testing.T) {
		t.Parallel()
		corruptRoot := t.TempDir()
		for name := range central {
			content, err := os.ReadFile(filepath.Join(centralRoot, name))
			if err != nil {
				t.Fatalf("read fixture %s: %v", name, err)
			}
			if name == "checksums.txt" {
				content = []byte(strings.Repeat("0", sha256.Size*2) + "  " + releaseSBOMName() + "\n" +
					strings.Repeat("0", sha256.Size*2) + "  " + releaseArchiveName() + "\n")
			}
			writeTestBytes(t, corruptRoot, name, content)
		}
		corrupt, err := treeDigests(corruptRoot)
		if err != nil {
			t.Fatalf("digest corrupt fixture: %v", err)
		}
		err = validateReleaseParity(corruptRoot, corrupt, retainedRoot, retained)
		if err == nil || !strings.Contains(err.Error(), "require canonical") {
			t.Fatalf("validateReleaseParity() error = %v, want checksum diagnostic", err)
		}
	})

	t.Run("rejects noncanonical checksum spacing", func(t *testing.T) {
		t.Parallel()
		corruptRoot := t.TempDir()
		for name := range central {
			content, err := os.ReadFile(filepath.Join(centralRoot, name))
			if err != nil {
				t.Fatalf("read fixture %s: %v", name, err)
			}
			if name == "checksums.txt" {
				content = []byte(strings.ReplaceAll(string(content), "  ", " "))
			}
			writeTestBytes(t, corruptRoot, name, content)
		}
		corrupt, err := treeDigests(corruptRoot)
		if err != nil {
			t.Fatalf("digest corrupt fixture: %v", err)
		}
		err = validateReleaseParity(corruptRoot, corrupt, retainedRoot, retained)
		if err == nil || !strings.Contains(err.Error(), "require canonical") {
			t.Fatalf("validateReleaseParity() error = %v, want canonical checksum diagnostic", err)
		}
	})
}

func releaseSBOMFixtures() (releaseSBOM, releaseSBOM) {
	common := releaseSBOM{
		SPDXVersion:  "SPDX-2.3",
		DataLicense:  "CC0-1.0",
		SPDXID:       "SPDXRef-DOCUMENT",
		CreationInfo: sbomCreationInfo{Created: "2026-01-01T00:00:00Z"},
		Packages: []map[string]any{{
			"SPDXID":      "SPDXRef-Package",
			"name":        "starter-oidc",
			"versionInfo": rehearsalVersion,
		}},
		Relationships: []map[string]any{{
			"spdxElementId":      "SPDXRef-DOCUMENT",
			"relationshipType":   "DESCRIBES",
			"relatedSpdxElement": "SPDXRef-Package",
		}},
	}
	central := common
	central.Name = "starter-oidc " + rehearsalVersion
	central.DocumentNamespace = releaseNamespace("v1/", 'a')
	central.CreationInfo.Creators = []string{
		"Organization: Spice Framework",
		"Tool: github.com/spice-framework/development/cmd/spice-dev library-release renderer/v1",
	}
	retained := cloneReleaseSBOMValue(common)
	retained.Name = "Spice OIDC starter " + rehearsalVersion
	retained.DocumentNamespace = releaseNamespace("", 'b')
	retained.CreationInfo.Creators = []string{
		"Organization: Spice Authors",
		"Tool: github.com/spice-framework/starter-oidc/cmd/starter-oidc-release",
	}
	return central, retained
}

func writeReleaseFixture(t *testing.T, central bool) (string, map[string][sha256.Size]byte) {
	t.Helper()
	root := t.TempDir()
	centralSBOM, retainedSBOM := releaseSBOMFixtures()
	sbom := retainedSBOM
	if central {
		sbom = centralSBOM
	}
	archive := []byte("identical-source-archive")
	sbomContent := marshalReleaseSBOM(t, sbom)
	writeTestBytes(t, root, releaseArchiveName(), archive)
	writeTestBytes(t, root, releaseSBOMName(), sbomContent)
	checksums := fmt.Sprintf(
		"%x  %s\n%x  %s\n",
		sha256.Sum256(sbomContent),
		releaseSBOMName(),
		sha256.Sum256(archive),
		releaseArchiveName(),
	)
	writeTestFile(t, root, "checksums.txt", checksums)
	digests, err := treeDigests(root)
	if err != nil {
		t.Fatalf("digest release fixture: %v", err)
	}
	return root, digests
}

func releaseArchiveName() string {
	return "starter-oidc_" + strings.TrimPrefix(rehearsalVersion, "v") + "_source.tar.gz"
}

func releaseSBOMName() string {
	return "starter-oidc_" + strings.TrimPrefix(rehearsalVersion, "v") + "_sbom.spdx.json"
}

func releaseNamespace(extra string, digit rune) string {
	return "https://github.com/spice-framework/starter-oidc/releases/" + rehearsalVersion +
		"/spdx/" + extra + strings.Repeat(string(digit), sha256.Size*2)
}

func cloneReleaseSBOM(t *testing.T, value releaseSBOM) releaseSBOM {
	t.Helper()
	content := marshalReleaseSBOM(t, value)
	cloned, err := decodeReleaseSBOM(content)
	if err != nil {
		t.Fatalf("clone SBOM: %v", err)
	}
	return cloned
}

func cloneReleaseSBOMValue(value releaseSBOM) releaseSBOM {
	content, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var cloned releaseSBOM
	if err := json.Unmarshal(content, &cloned); err != nil {
		panic(err)
	}
	return cloned
}

func marshalReleaseSBOM(t *testing.T, value releaseSBOM) []byte {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal SBOM: %v", err)
	}
	return content
}

func cloneArtifactDigests(value map[string][sha256.Size]byte) map[string][sha256.Size]byte {
	return maps.Clone(value)
}

func writeTestFile(t *testing.T, root, name, content string) {
	t.Helper()
	writeTestBytes(t, root, name, []byte(content))
}

func writeTestBytes(t *testing.T, root, name string, content []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), content, 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
}
