package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func main() {
	if err := checkRelease(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type releaseVersions struct {
	Python     string `json:"python"`
	JavaScript string `json:"javascript"`
	Go         string `json:"go"`
}

func checkRelease() (result error) {
	if len(os.Args) != 2 {
		return errors.New("usage: go run scripts/releasecheck/main.go metadata|python|javascript|go")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	versions, err := readVersions(root)
	if err != nil {
		return err
	}
	if err := checkMetadata(root, versions, os.Getenv("GITHUB_REF")); err != nil {
		return err
	}
	if os.Args[1] == "metadata" {
		return nil
	}
	if os.Args[1] != "python" && os.Args[1] != "javascript" && os.Args[1] != "go" {
		return fmt.Errorf("unknown target %q", os.Args[1])
	}
	stage, err := os.MkdirTemp("", "gentrail-release-*")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(stage)) }()
	if err := os.CopyFS(filepath.Join(stage, "spec"), os.DirFS(filepath.Join(root, "spec"))); err != nil {
		return err
	}
	output := filepath.Join(root, "dist", "release", os.Args[1])
	if err := os.MkdirAll(output, 0755); err != nil {
		return err
	}
	switch os.Args[1] {
	case "python":
		return checkPython(root, stage, output, versions.Python)
	case "javascript":
		return checkJavaScript(root, stage, output, versions.JavaScript)
	case "go":
		return checkGo(root, stage, output, versions.Go)
	default:
		return fmt.Errorf("unknown target %q", os.Args[1])
	}
}

func readVersions(root string) (releaseVersions, error) {
	var versions releaseVersions
	raw, err := os.ReadFile(filepath.Join(root, "release.json"))
	if err != nil {
		return versions, err
	}
	if err := json.Unmarshal(raw, &versions); err != nil {
		return versions, err
	}
	for _, version := range []string{versions.Python, versions.JavaScript, versions.Go} {
		if !regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`).MatchString(version) {
			return versions, fmt.Errorf("invalid release version %q", version)
		}
	}
	return versions, nil
}

func checkMetadata(root string, versions releaseVersions, ref string) error {
	for _, path := range []string{"python/pyproject.toml", "python/uv.lock"} {
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			return err
		}
		pattern := `(?m)^name = "gentrail"\nversion = "` + regexp.QuoteMeta(versions.Python) + `"$`
		if !regexp.MustCompile(pattern).Match(raw) {
			return fmt.Errorf("%s differs from release.json", path)
		}
	}
	for _, path := range []string{"js/gentrail-ai/package.json", "js/gentrail-ai/package-lock.json"} {
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			return err
		}
		var manifest struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Packages map[string]struct {
				Version string `json:"version"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(raw, &manifest); err != nil {
			return err
		}
		if manifest.Name != "@gentrail/ai" || manifest.Version != versions.JavaScript {
			return fmt.Errorf("%s differs from release.json", path)
		}
		if path == "js/gentrail-ai/package-lock.json" && manifest.Packages[""].Version != versions.JavaScript {
			return errors.New("npm lock root differs from release.json")
		}
	}
	if strings.HasPrefix(ref, "refs/tags/") {
		tag := strings.TrimPrefix(ref, "refs/tags/")
		if tag != "v"+versions.Python && tag != "js-v"+versions.JavaScript && tag != "go/v"+versions.Go {
			return fmt.Errorf("release tag %q differs from release.json", tag)
		}
	}
	return nil
}

func run(directory string, environment []string, name string, arguments ...string) error {
	_, err := command(directory, environment, false, name, arguments...)
	return err
}

func command(directory string, environment []string, capture bool, name string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, arguments...)
	cmd.Dir = directory
	cmd.Env = append(os.Environ(), environment...)
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = 5 * time.Second
	if capture {
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("%s %v: %w", name, arguments, err)
		}
		return output, nil
	}
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %v: %w", name, arguments, err)
	}
	return nil, nil
}

func oneMatch(pattern string) (string, error) {
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return "", err
	}
	if len(paths) != 1 {
		return "", fmt.Errorf("expected one artifact matching %s, found %d", pattern, len(paths))
	}
	return paths[0], nil
}

func checkPython(root, stage, output, version string) error {
	if err := run(root, nil, "uv", "build", "--project", "python", "--out-dir", output); err != nil {
		return err
	}
	sdist, err := oneMatch(filepath.Join(output, "gentrail-"+version+".tar.gz"))
	if err != nil {
		return err
	}
	if err := run(root, nil, "uv", "build", sdist, "--wheel", "--out-dir", output+"-rebuilt"); err != nil {
		return err
	}
	for index, directory := range []string{output, output + "-rebuilt"} {
		wheel, err := oneMatch(filepath.Join(directory, "gentrail-"+version+"-*.whl"))
		if err != nil {
			return err
		}
		consumer := filepath.Join(stage, fmt.Sprintf("consumer%d", index))
		if err := checkPythonWheel(root, stage, consumer, wheel, version); err != nil {
			return err
		}
	}
	return nil
}

func checkPythonWheel(root, stage, consumer, wheel, version string) error {
	python := filepath.Join(consumer, ".venv", "bin", "python")
	if err := run(root, nil, "uv", "venv", "--python", "python3", filepath.Dir(filepath.Dir(python))); err != nil {
		return err
	}
	if err := run(root, nil, "uv", "pip", "install", "--python", python, wheel, "httpx"); err != nil {
		return err
	}
	installed, err := command(consumer, nil, true, python, "-I", filepath.Join(root, "scripts", "releasecheck", "smoke.py"), version)
	if err != nil {
		return err
	}
	fixture := filepath.Join(consumer, "python")
	if err := os.CopyFS(filepath.Join(fixture, "tests"), os.DirFS(filepath.Join(root, "python", "tests"))); err != nil {
		return err
	}
	if err := os.Symlink(strings.TrimSpace(string(installed)), filepath.Join(fixture, "gentrail")); err != nil {
		return err
	}
	if err := os.Symlink(filepath.Join(stage, "spec"), filepath.Join(consumer, "spec")); err != nil {
		return err
	}
	tests, err := filepath.Glob(filepath.Join(fixture, "tests", "test_*.py"))
	if err != nil {
		return err
	}
	if len(tests) == 0 {
		return errors.New("no Python package tests")
	}
	for _, test := range tests {
		if err := run(consumer, []string{"PYTHONPATH="}, python, test); err != nil {
			return err
		}
	}
	return nil
}

func checkJavaScript(root, stage, output, version string) error {
	packageRoot := filepath.Join(root, "js", "gentrail-ai")
	if err := run(packageRoot, nil, "npm", "ci"); err != nil {
		return err
	}
	if err := run(packageRoot, nil, "npm", "pack", "--pack-destination", output); err != nil {
		return err
	}
	archive := filepath.Join(output, "gentrail-ai-"+version+".tgz")
	consumer := filepath.Join(stage, "js", "gentrail-ai")
	if err := os.MkdirAll(consumer, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(consumer, "package.json"), []byte(`{"private":true,"type":"module"}`), 0644); err != nil {
		return err
	}
	if err := run(consumer, nil, "npm", "install", "--no-audit", "--no-fund", archive); err != nil {
		return err
	}
	smoke, err := os.ReadFile(filepath.Join(root, "scripts", "releasecheck", "smoke.mjs"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(consumer, "smoke.mjs"), smoke, 0644); err != nil {
		return err
	}
	if err := run(consumer, nil, "node", "smoke.mjs"); err != nil {
		return err
	}
	installed := filepath.Join(consumer, "node_modules", "@gentrail", "ai")
	if err := os.CopyFS(filepath.Join(consumer, "dist", "test"), os.DirFS(filepath.Join(packageRoot, "dist", "test"))); err != nil {
		return err
	}
	if err := os.Symlink(filepath.Join(installed, "dist", "src"), filepath.Join(consumer, "dist", "src")); err != nil {
		return err
	}
	if err := os.Symlink(filepath.Join(installed, "data"), filepath.Join(consumer, "data")); err != nil {
		return err
	}
	tests, err := filepath.Glob(filepath.Join(consumer, "dist", "test", "*.test.js"))
	if err != nil {
		return err
	}
	if len(tests) == 0 {
		return errors.New("no JavaScript package tests")
	}
	return run(consumer, nil, "node", append([]string{"--test"}, tests...)...)
}

func checkGo(root, stage, output, version string) error {
	const module = "github.com/aigentrail/sdk/go"
	version = "v" + version
	proxy := filepath.Join(stage, "proxy", filepath.FromSlash(module), "@v")
	if err := os.MkdirAll(proxy, 0755); err != nil {
		return err
	}
	archive := filepath.Join(output, "gentrail-go-"+version+".zip")
	if err := writeGoArchive(root, archive, module+"@"+version+"/"); err != nil {
		return err
	}
	archiveBytes, err := os.ReadFile(archive)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(proxy, version+".zip"), archiveBytes, 0644); err != nil {
		return err
	}
	mod, err := os.ReadFile(filepath.Join(root, "go", "go.mod"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(proxy, version+".mod"), mod, 0644); err != nil {
		return err
	}
	commitTime, err := command(root, nil, true, "git", "show", "-s", "--format=%cI", "HEAD")
	if err != nil {
		return err
	}
	info, err := json.Marshal(struct {
		Version string
		Time    string
	}{version, strings.TrimSpace(string(commitTime))})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(proxy, version+".info"), info, 0644); err != nil {
		return err
	}
	environment := []string{"GOPROXY=file://" + filepath.Join(stage, "proxy"), "GOSUMDB=off", "GOMODCACHE=" + filepath.Join(stage, "modules"), "GOFLAGS=-modcacherw"}
	raw, err := command(stage, environment, true, "go", "mod", "download", "-json", module+"@"+version)
	if err != nil {
		return err
	}
	var downloaded struct{ Dir string }
	if err := json.Unmarshal(raw, &downloaded); err != nil {
		return err
	}
	if downloaded.Dir == "" {
		return errors.New("Go module download returned no directory")
	}
	consumer := filepath.Join(stage, "go")
	if err := os.CopyFS(consumer, os.DirFS(downloaded.Dir)); err != nil {
		return err
	}
	if err := run(consumer, nil, "go", "vet", "./..."); err != nil {
		return err
	}
	return run(consumer, nil, "go", "test", "./...")
}

func writeGoArchive(root, path, prefix string) (result error) {
	raw, err := command(root, nil, true, "git", "ls-files", "-z", "go")
	if err != nil {
		return err
	}
	files := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
	files = append(files, "LICENSE")
	if len(raw) == 0 || len(files) > 2048 {
		return errors.New("Go module file count outside release bounds")
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	writer := zip.NewWriter(file)
	defer func() { result = errors.Join(result, writer.Close()) }()
	for _, name := range files {
		content, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return err
		}
		if len(content) > 16<<20 {
			return fmt.Errorf("module file too large: %s", name)
		}
		entry, err := writer.Create(prefix + strings.TrimPrefix(name, "go/"))
		if err != nil {
			return err
		}
		if _, err := entry.Write(content); err != nil {
			return err
		}
	}
	return nil
}
