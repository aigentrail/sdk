package gentrail

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

var (
	ssnDashedRe          = regexp.MustCompile(`\d{3}-\d{2}-\d{4}`)
	ssnUndelimitedRe     = regexp.MustCompile(`\d{3} \d{2} \d{4}|\d{9}`)
	ssnContextWords      = []string{"ssn", "social security", "ss#", "ss #"}
	digitRunRe           = regexp.MustCompile(`\d(?:[ -]?\d)*`)
	phoneInternationalRe = regexp.MustCompile(`\+\d[\d ().-]{6,22}\d`)
	phoneNationalRe      = regexp.MustCompile(`\(?\d{3}\)?[ .-]?\d{3}[ .-]\d{4}`)
	phoneContextWords    = []string{"phone", "tel", "call", "mobile", "cell", "fax", "sms", "whatsapp", "text me", "contact"}
)

func ssnFindings(text normalizedText) []piiFinding {
	var findings []piiFinding
	for _, m := range findAllInWindows(ssnDashedRe, text.text, text.numericSpans) {
		if !isolatedToken(text, m[0], m[1]) || !validSSN(strings.ReplaceAll(text.text[m[0]:m[1]], "-", "")) {
			continue
		}
		findings = append(findings, text.finding(piiClassSSN, m[0], m[1], "ssn_dashed"))
	}
	for _, m := range findAllInWindows(ssnUndelimitedRe, text.text, text.numericSpans) {
		if !isolatedToken(text, m[0], m[1]) || !text.contextBefore(m[0], ssnContextWords) {
			continue
		}
		if !validSSN(strings.ReplaceAll(text.text[m[0]:m[1]], " ", "")) {
			continue
		}
		findings = append(findings, text.finding(piiClassSSN, m[0], m[1], "ssn_with_context"))
	}
	return findings
}

func isolatedToken(text normalizedText, start, end int) bool {
	before, after := start-1, end
	if text.alphanumericAt(before) || text.alphanumericAt(after) {
		return false
	}
	return !(before >= 0 && text.text[before] == '-') && !(after < len(text.text) && text.text[after] == '-')
}

func validSSN(digits string) bool {
	if len(digits) != 9 {
		panic("gentrail: validSSN needs exactly nine digits")
	}
	area, group, serial := digits[:3], digits[3:5], digits[5:]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	return group != "00" && serial != "0000"
}

func creditCardFindings(text normalizedText) []piiFinding {
	var findings []piiFinding
	for _, run := range findAllInWindows(digitRunRe, text.text, text.numericSpans) {
		groups := digitGroups(text.text, run[0], run[1])
		for first := 0; first < len(groups); first++ {
			last, found := longestCardSpan(text.text, groups, first)
			if !found {
				continue
			}
			findings = append(findings, text.finding(piiClassCreditCard, groups[first][0], groups[last][1], "credit_card_luhn"))
			first = last
		}
	}
	return findings
}

func digitGroups(text string, start, end int) [][2]int {
	var groups [][2]int
	groupStart := start
	for i := start; i < end; i++ {
		if text[i] == ' ' || text[i] == '-' {
			groups = append(groups, [2]int{groupStart, i})
			groupStart = i + 1
		}
	}
	return append(groups, [2]int{groupStart, end})
}

func longestCardSpan(text string, groups [][2]int, first int) (last int, found bool) {
	const cardDigitsMin, cardDigitsMax = 13, 19
	var digits strings.Builder
	for i := first; i < len(groups); i++ {
		digits.WriteString(text[groups[i][0]:groups[i][1]])
		if digits.Len() > cardDigitsMax {
			break
		}
		if digits.Len() >= cardDigitsMin && validCardNumber(digits.String()) {
			last, found = i, true
		}
	}
	return last, found
}

func validCardNumber(digits string) bool {
	if digits[0] < '2' || digits[0] > '6' {
		return false
	}
	if strings.Count(digits, digits[:1]) == len(digits) {
		return false
	}
	return luhnValid(digits)
}

func luhnValid(s string) bool {
	digits := make([]int, 0, len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

//go:embed iban_registry.json
var ibanRegistryJSON []byte

var ibanLengthByCountry = sync.OnceValue(func() map[string]int {
	lengths, err := parseIBANRegistry(ibanRegistryJSON)
	if err != nil {
		panic("gentrail: vendored iban registry: " + err.Error())
	}
	return lengths
})

func parseIBANRegistry(raw []byte) (map[string]int, error) {
	var registry struct {
		LengthByCountry map[string]int `json:"length_by_country"`
	}
	if err := json.Unmarshal(raw, &registry); err != nil {
		return nil, err
	}
	if len(registry.LengthByCountry) == 0 {
		return nil, fmt.Errorf("no countries")
	}
	for country, length := range registry.LengthByCountry {
		if len(country) != 2 || length < 15 || length > 34 {
			return nil, fmt.Errorf("implausible entry %q with length %d", country, length)
		}
	}
	return registry.LengthByCountry, nil
}

func ibanFindings(text normalizedText) []piiFinding {
	var findings []piiFinding
	for _, start := range ibanCandidateStarts(text.text) {
		length, known := ibanLengthByCountry()[text.text[start:start+2]]
		if !known || text.alphanumericAt(start-1) {
			continue
		}
		compact, end := collectIBAN(text.text, start, length)
		if len(compact) != length || text.alphanumericAt(end) || !ibanChecksumValid(compact) {
			continue
		}
		findings = append(findings, text.finding(piiClassIBAN, start, end, "iban_mod97"))
	}
	return findings
}

func ibanCandidateStarts(text string) []int {
	var starts []int
	for i := 0; i+3 < len(text); i++ {
		countryCode := text[i] >= 'A' && text[i] <= 'Z' && text[i+1] >= 'A' && text[i+1] <= 'Z'
		checkDigits := text[i+2] >= '0' && text[i+2] <= '9' && text[i+3] >= '0' && text[i+3] <= '9'
		if countryCode && checkDigits {
			starts = append(starts, i)
		}
	}
	return starts
}

func collectIBAN(text string, start, length int) (compact string, end int) {
	var builder strings.Builder
	end = start
	for i := start; i < len(text) && builder.Len() < length; i++ {
		b := text[i]
		isUpperAlphanumeric := (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z')
		if isUpperAlphanumeric {
			builder.WriteByte(b)
			end = i + 1
			continue
		}
		if b != ' ' || i == start || text[i-1] == ' ' {
			break
		}
	}
	return builder.String(), end
}

func ibanChecksumValid(compact string) bool {
	rearranged := compact[4:] + compact[:4]
	remainder := 0
	for i := 0; i < len(rearranged); i++ {
		b := rearranged[i]
		switch {
		case b >= '0' && b <= '9':
			remainder = (remainder*10 + int(b-'0')) % 97
		case b >= 'A' && b <= 'Z':
			remainder = (remainder*100 + int(b-'A') + 10) % 97
		default:
			return false
		}
	}
	return remainder == 1
}

func phoneFindings(text normalizedText) []piiFinding {
	var findings []piiFinding
	for _, m := range findAllInWindows(phoneInternationalRe, text.text, text.numericSpans) {
		digitCount := countDigits(text.text[m[0]:m[1]])
		if text.alphanumericAt(m[0]-1) || text.digitAt(m[1]) || digitCount < 8 || digitCount > 15 {
			continue
		}
		findings = append(findings, text.finding(piiClassPhone, m[0], m[1], "phone_international"))
	}
	for _, m := range findAllInWindows(phoneNationalRe, text.text, text.numericSpans) {
		if !isolatedToken(text, m[0], m[1]) || !text.contextBefore(m[0], phoneContextWords) {
			continue
		}
		findings = append(findings, text.finding(piiClassPhone, m[0], m[1], "phone_national_with_context"))
	}
	return findings
}

func countDigits(s string) int {
	count := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			count++
		}
	}
	return count
}

func findNumericSpans(text string) [][2]int {
	const digitsMin, separatorsInARowMax = 8, 2
	var windows [][2]int
	start, digits, separatorsInARow, lastDigitEnd := -1, 0, 0, 0
	for i := 0; i <= len(text); i++ {
		if i < len(text) && text[i] >= '0' && text[i] <= '9' {
			if start < 0 {
				start = i
				if i > 0 && (text[i-1] == '+' || text[i-1] == '(') {
					start = i - 1
				}
			}
			digits++
			separatorsInARow = 0
			lastDigitEnd = i + 1
			continue
		}
		if i < len(text) && start >= 0 && separatorsInARow < separatorsInARowMax && strings.IndexByte(" -.()", text[i]) >= 0 {
			separatorsInARow++
			continue
		}
		if start >= 0 && digits >= digitsMin {
			windows = append(windows, [2]int{start, lastDigitEnd})
		}
		start, digits, separatorsInARow = -1, 0, 0
	}
	return windows
}

func findAllInWindows(re *regexp.Regexp, text string, windows [][2]int) [][2]int {
	var matches [][2]int
	for _, window := range windows {
		for _, m := range re.FindAllStringIndex(text[window[0]:window[1]], -1) {
			matches = append(matches, [2]int{window[0] + m[0], window[0] + m[1]})
		}
	}
	return matches
}
