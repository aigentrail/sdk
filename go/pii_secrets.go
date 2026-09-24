package gentrail

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
)

//go:embed gitleaks_rules.json
var gitleaksRulesJSON []byte

type gitleaksAllowlistJSON struct {
	RegexTarget string   `json:"regex_target"`
	Regexes     []string `json:"regexes"`
	Stopwords   []string `json:"stopwords"`
}

type gitleaksRulesFile struct {
	GlobalAllowlist *gitleaksAllowlistJSON `json:"global_allowlist"`
	Rules           []struct {
		ID          string                  `json:"id"`
		Regex       string                  `json:"regex"`
		SecretGroup int                     `json:"secret_group"`
		Entropy     float64                 `json:"entropy"`
		Keywords    []string                `json:"keywords"`
		Allowlists  []gitleaksAllowlistJSON `json:"allowlists"`
	} `json:"rules"`
}

type secretAllowlistTarget int

const (
	secretAllowlistTargetSecret secretAllowlistTarget = iota
	secretAllowlistTargetMatch
	secretAllowlistTargetLine
)

type secretAllowlist struct {
	target    secretAllowlistTarget
	regexes   []*regexp.Regexp
	stopwords []string
}

type secretRule struct {
	id          string
	class       string
	regex       *regexp.Regexp
	secretGroup int
	entropyMin  float64
	keywords    []string
	allowlists  []secretAllowlist
}

type secretRuleSet struct {
	rules           []secretRule
	globalAllowlist secretAllowlist
	keywords        keywordIndex
}

var compiledSecretRules = sync.OnceValue(func() secretRuleSet {
	ruleSet, err := compileSecretRules(gitleaksRulesJSON)
	if err != nil {
		panic("gentrail: vendored gitleaks rules: " + err.Error())
	}
	return ruleSet
})

func compileSecretRules(raw []byte) (secretRuleSet, error) {
	var file gitleaksRulesFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return secretRuleSet{}, err
	}
	if len(file.Rules) == 0 {
		return secretRuleSet{}, fmt.Errorf("no rules")
	}
	var ruleSet secretRuleSet
	if file.GlobalAllowlist != nil {
		global, err := compileSecretAllowlist(*file.GlobalAllowlist)
		if err != nil {
			return secretRuleSet{}, fmt.Errorf("global allowlist: %w", err)
		}
		ruleSet.globalAllowlist = global
	}
	seenKeywords := map[string]bool{}
	var uniqueKeywords []string
	for _, source := range file.Rules {
		if len(source.Keywords) == 0 {
			return secretRuleSet{}, fmt.Errorf("rule %s has no keywords to prefilter on", source.ID)
		}
		regex, err := regexp.Compile(source.Regex)
		if err != nil {
			return secretRuleSet{}, fmt.Errorf("rule %s: %w", source.ID, err)
		}
		if source.SecretGroup > regex.NumSubexp() {
			return secretRuleSet{}, fmt.Errorf("rule %s: secret group %d out of range", source.ID, source.SecretGroup)
		}
		rule := secretRule{
			id: source.ID, class: secretClassForGitleaksRule(source.ID), regex: regex,
			secretGroup: source.SecretGroup, entropyMin: source.Entropy, keywords: source.Keywords,
		}
		for _, allowlistSource := range source.Allowlists {
			allowlist, err := compileSecretAllowlist(allowlistSource)
			if err != nil {
				return secretRuleSet{}, fmt.Errorf("rule %s allowlist: %w", source.ID, err)
			}
			rule.allowlists = append(rule.allowlists, allowlist)
		}
		for _, keyword := range source.Keywords {
			if !seenKeywords[keyword] {
				seenKeywords[keyword] = true
				uniqueKeywords = append(uniqueKeywords, keyword)
			}
		}
		ruleSet.rules = append(ruleSet.rules, rule)
	}
	index, err := newKeywordIndex(uniqueKeywords)
	if err != nil {
		return secretRuleSet{}, err
	}
	ruleSet.keywords = index
	return ruleSet, nil
}

func secretClassForGitleaksRule(id string) string {
	if id == "aws-access-token" {
		return piiClassAWSKey
	}
	return piiClassSecret
}

func compileSecretAllowlist(source gitleaksAllowlistJSON) (secretAllowlist, error) {
	allowlist := secretAllowlist{stopwords: source.Stopwords}
	switch source.RegexTarget {
	case "", "secret":
		allowlist.target = secretAllowlistTargetSecret
	case "match":
		allowlist.target = secretAllowlistTargetMatch
	case "line":
		allowlist.target = secretAllowlistTargetLine
	default:
		return secretAllowlist{}, fmt.Errorf("unknown regex target %q", source.RegexTarget)
	}
	for _, pattern := range source.Regexes {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return secretAllowlist{}, err
		}
		allowlist.regexes = append(allowlist.regexes, regex)
	}
	return allowlist, nil
}

func secretFindings(text normalizedText) []piiFinding {
	ruleSet := compiledSecretRules()
	presentKeywords := ruleSet.keywords.present(text.lower)
	if len(presentKeywords) == 0 {
		return nil
	}
	var findings []piiFinding
	for _, rule := range ruleSet.rules {
		if !anyKeywordPresent(rule.keywords, presentKeywords) {
			continue
		}
		for _, m := range rule.regex.FindAllStringSubmatchIndex(text.text, -1) {
			start, end := secretSpan(m, rule.secretGroup)
			if start >= end || secretRejected(text.text, m[0], m[1], start, end, rule, ruleSet.globalAllowlist) {
				continue
			}
			findings = append(findings, text.finding(rule.class, start, end, "gitleaks:"+rule.id))
		}
	}
	return findings
}

func anyKeywordPresent(keywords []string, present map[string]bool) bool {
	for _, keyword := range keywords {
		if present[keyword] {
			return true
		}
	}
	return false
}

func secretSpan(submatches []int, secretGroup int) (start, end int) {
	if secretGroup > 0 {
		return submatches[2*secretGroup], submatches[2*secretGroup+1]
	}
	for group := 1; 2*group+1 < len(submatches); group++ {
		if submatches[2*group] >= 0 && submatches[2*group+1] > submatches[2*group] {
			return submatches[2*group], submatches[2*group+1]
		}
	}
	return submatches[0], submatches[1]
}

func secretRejected(text string, matchStart, matchEnd, secretStart, secretEnd int, rule secretRule, global secretAllowlist) bool {
	secret := text[secretStart:secretEnd]
	if rule.entropyMin > 0 && shannonEntropy(secret) <= rule.entropyMin {
		return true
	}
	targets := map[secretAllowlistTarget]string{
		secretAllowlistTargetSecret: secret,
		secretAllowlistTargetMatch:  text[matchStart:matchEnd],
		secretAllowlistTargetLine:   lineAround(text, matchStart, matchEnd),
	}
	if global.allows(targets) {
		return true
	}
	for _, allowlist := range rule.allowlists {
		if allowlist.allows(targets) {
			return true
		}
	}
	return false
}

func (a secretAllowlist) allows(targets map[secretAllowlistTarget]string) bool {
	for _, regex := range a.regexes {
		if regex.MatchString(targets[a.target]) {
			return true
		}
	}
	lowerSecret := strings.ToLower(targets[secretAllowlistTargetSecret])
	for _, stopword := range a.stopwords {
		if strings.Contains(lowerSecret, stopword) {
			return true
		}
	}
	return false
}

func lineAround(text string, start, end int) string {
	lineStart := strings.LastIndexByte(text[:start], '\n') + 1
	lineEnd := strings.IndexByte(text[end:], '\n')
	if lineEnd < 0 {
		return text[lineStart:]
	}
	return text[lineStart : end+lineEnd]
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	entropy := 0.0
	length := float64(len(s))
	for _, count := range counts {
		frequency := float64(count) / length
		entropy -= frequency * math.Log2(frequency)
	}
	return entropy
}

type keywordIndex struct {
	bigramHasKeyword *[1 << 16]bool
	keywordsByBigram map[uint16][]string
}

func newKeywordIndex(keywords []string) (keywordIndex, error) {
	index := keywordIndex{bigramHasKeyword: new([1 << 16]bool), keywordsByBigram: map[uint16][]string{}}
	for _, keyword := range keywords {
		if len(keyword) < 2 {
			return keywordIndex{}, fmt.Errorf("keyword %q is shorter than the two-byte index", keyword)
		}
		bigram := uint16(keyword[0])<<8 | uint16(keyword[1])
		index.bigramHasKeyword[bigram] = true
		index.keywordsByBigram[bigram] = append(index.keywordsByBigram[bigram], keyword)
	}
	return index, nil
}

func (index keywordIndex) present(lower string) map[string]bool {
	found := map[string]bool{}
	for i := 0; i+1 < len(lower); i++ {
		bigram := uint16(lower[i])<<8 | uint16(lower[i+1])
		if !index.bigramHasKeyword[bigram] {
			continue
		}
		for _, keyword := range index.keywordsByBigram[bigram] {
			if strings.HasPrefix(lower[i:], keyword) {
				found[keyword] = true
			}
		}
	}
	return found
}
