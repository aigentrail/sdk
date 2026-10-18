package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReleaseMetadataRejectsMismatchedTagsAndManifests(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	versions, err := readVersions(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"", "refs/pull/24/merge", "refs/heads/main", "refs/tags/v" + versions.Python, "refs/tags/js-v" + versions.JavaScript, "refs/tags/go/v" + versions.Go} {
		if err := checkMetadata(root, versions, ref); err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
	}
	for _, ref := range []string{"refs/tags/v0.0.0", "refs/tags/js-v0.0.0", "refs/tags/go/v0.0.0", "refs/tags/v" + versions.Python + "-unreviewed"} {
		if err := checkMetadata(root, versions, ref); err == nil {
			t.Fatalf("accepted mismatched tag %s", ref)
		}
	}
	for _, runtime := range []string{"python", "javascript"} {
		changed := versions
		if runtime == "python" {
			changed.Python = "0.99.0"
		} else {
			changed.JavaScript = "0.99.0"
		}
		if err := checkMetadata(root, changed, ""); err == nil {
			t.Fatalf("accepted mismatched %s manifest", runtime)
		}
	}
}

func TestReleaseMetadataRejectsStaleLocks(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	versions, err := readVersions(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"python/uv.lock", "js/gentrail-ai/package-lock.json"} {
		t.Run(path, func(t *testing.T) {
			stage := t.TempDir()
			for _, directory := range []string{"python", "js/gentrail-ai"} {
				if err := os.MkdirAll(filepath.Join(stage, directory), 0755); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"python/pyproject.toml", "python/uv.lock", "js/gentrail-ai/package.json", "js/gentrail-ai/package-lock.json"} {
				raw, err := os.ReadFile(filepath.Join(root, name))
				if err != nil {
					t.Fatal(err)
				}
				if name == path {
					raw = []byte(`{"name":"@gentrail/ai","version":"` + versions.JavaScript + `","packages":{"":{"version":"0.0.0"}}}`)
				}
				if err := os.WriteFile(filepath.Join(stage, name), raw, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := checkMetadata(stage, versions, ""); err == nil {
				t.Fatal("accepted stale lock")
			}
		})
	}
}
