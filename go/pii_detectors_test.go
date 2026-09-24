package gentrail

import (
	"strings"
	"testing"
)

func TestPIIFindingReportsOriginalOffsetsAcrossNormalization(t *testing.T) {
	ssn := "１２３‑４５‑６７８９"
	field := "zero​width ssn " + ssn + " end"

	findings := piiFindings(field)

	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one SSN", findings)
	}
	got := field[findings[0].originalStart:findings[0].originalEnd]
	if got != ssn {
		t.Errorf("finding covers %q, want %q", got, ssn)
	}
	if findings[0].class != piiClassSSN {
		t.Errorf("class = %s, want %s", findings[0].class, piiClassSSN)
	}
}

func TestSecretFindingCoversOnlyTheSecretGroup(t *testing.T) {
	token := "ghp_R8x2mQ9vL4kT7nB1cZ5wY3pH6jD0fG2sA9eK"
	field := "export GITHUB_TOKEN=" + token

	for _, finding := range piiFindings(field) {
		if finding.detector != "gitleaks:github-pat" {
			continue
		}
		if got := field[finding.originalStart:finding.originalEnd]; got != token {
			t.Errorf("github-pat finding covers %q, want %q", got, token)
		}
		return
	}
	t.Fatalf("no github-pat finding in %q", field)
}

func TestVendoredGitleaksRulesCompile(t *testing.T) {
	ruleSet, err := compileSecretRules(gitleaksRulesJSON)
	if err != nil {
		t.Fatalf("compile vendored rules: %v", err)
	}
	if len(ruleSet.rules) < 200 {
		t.Errorf("compiled %d rules, want the full gitleaks default set", len(ruleSet.rules))
	}
	if len(ruleSet.globalAllowlist.regexes) == 0 {
		t.Error("global allowlist has no regexes")
	}
}

func TestCompileSecretRulesRejectsMalformedRules(t *testing.T) {
	cases := map[string]string{
		"no rules":             `{"rules": []}`,
		"missing keywords":     `{"rules": [{"id": "r", "regex": "x", "keywords": []}]}`,
		"invalid regex":        `{"rules": [{"id": "r", "regex": "(", "keywords": ["x"]}]}`,
		"secret group too big": `{"rules": [{"id": "r", "regex": "(x)", "secret_group": 2, "keywords": ["x"]}]}`,
		"one byte keyword":     `{"rules": [{"id": "r", "regex": "x", "keywords": ["x"]}]}`,
		"unknown regex target": `{"rules": [{"id": "r", "regex": "x", "keywords": ["x"], "allowlists": [{"regex_target": "path"}]}]}`,
	}
	for name, raw := range cases {
		if _, err := compileSecretRules([]byte(raw)); err == nil {
			t.Errorf("%s: compiled without error", name)
		}
	}
}

func FuzzPIIFindingsStayInsideTheirField(f *testing.F) {
	for _, seed := range []string{"", "ssn 123-45-6789", "１​‑", "api_key = \"q8Zr4TmN2vX7pL1kW9sB\"", "\xff\xfe"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, field string) {
		for _, finding := range piiFindings(field) {
			if finding.originalStart < 0 || finding.originalEnd > len(field) || finding.originalStart >= finding.originalEnd {
				t.Fatalf("finding %+v outside field of %d bytes", finding, len(field))
			}
		}
	})
}

func BenchmarkRedactPIITypicalToolResult(b *testing.B) {
	field := strings.Repeat("customer record: name Jane Doe, order 4411 shipped to warehouse 12, status ok. ", 128)
	b.SetBytes(int64(len(field)))
	for b.Loop() {
		redactPII(field)
	}
}

func TestVendoredIBANRegistryLoads(t *testing.T) {
	lengths, err := parseIBANRegistry(ibanRegistryJSON)
	if err != nil {
		t.Fatalf("parse vendored registry: %v", err)
	}
	if len(lengths) < 80 {
		t.Errorf("registry has %d countries, want the full SWIFT list", len(lengths))
	}
	for country, want := range map[string]int{"DE": 22, "GB": 22, "NO": 15, "LC": 32} {
		if lengths[country] != want {
			t.Errorf("length for %s = %d, want %d", country, lengths[country], want)
		}
	}
}

func TestParseIBANRegistryRejectsMalformedRegistries(t *testing.T) {
	cases := map[string]string{
		"not json":             `{`,
		"no countries":         `{"length_by_country": {}}`,
		"three letter country": `{"length_by_country": {"DEU": 22}}`,
		"length too short":     `{"length_by_country": {"DE": 14}}`,
		"length too long":      `{"length_by_country": {"DE": 35}}`,
	}
	for name, raw := range cases {
		if _, err := parseIBANRegistry([]byte(raw)); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

func FuzzRedactPIILeavesNothingDetectable(f *testing.F) {
	for _, seed := range []string{"ssn 123-45-6789", "a@b.com 4111111111111111", "phone 555-123-4567", "api_key = \"q8Zr4TmN2vX7pL1kW9sB\"", "0@0.AA+00000000+00000000+00000000+00000000"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, field string) {
		redacted := redactPII(field)
		if leftover := piiFindings(redacted); len(leftover) > 0 {
			t.Fatalf("redactPII(%q) = %q still has %+v", field, redacted, leftover)
		}
	})
}
