package gentrail

import (
	"regexp"
	"sort"
	"strings"
)

const (
	piiClassAWSKey     = "AWS_KEY"
	piiClassCreditCard = "CREDIT_CARD"
	piiClassEmail      = "EMAIL"
	piiClassIBAN       = "IBAN"
	piiClassPhone      = "PHONE"
	piiClassSecret     = "SECRET"
	piiClassSSN        = "SSN"
)

var placeholderRe = regexp.MustCompile(`\[(?:` + strings.Join([]string{
	piiClassAWSKey, piiClassCreditCard, piiClassEmail, piiClassIBAN, piiClassPhone, piiClassSecret, piiClassSSN,
}, "|") + `)\]`)

type piiFinding struct {
	class         string
	originalStart int
	originalEnd   int
	detector      string
}

var piiDetectors = []func(normalizedText) []piiFinding{
	emailFindings,
	ssnFindings,
	creditCardFindings,
	ibanFindings,
	phoneFindings,
	secretFindings,
}

func redactPII(field string) string {
	const redactionPassesMax = 4
	redacted := field
	for range redactionPassesMax {
		next := redactPIIOnce(redacted)
		if next == redacted {
			return redacted
		}
		redacted = next
	}
	return redacted
}

func redactPIIOnce(field string) string {
	findings := piiFindings(field)
	if len(findings) == 0 {
		return field
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].originalStart != findings[j].originalStart {
			return findings[i].originalStart < findings[j].originalStart
		}
		return findings[i].originalEnd > findings[j].originalEnd
	})
	var redacted strings.Builder
	written := 0
	for _, finding := range findings {
		if finding.originalStart < written {
			written = max(written, finding.originalEnd)
			continue
		}
		redacted.WriteString(field[written:finding.originalStart])
		redacted.WriteString("[" + finding.class + "]")
		written = finding.originalEnd
	}
	redacted.WriteString(field[written:])
	return redacted.String()
}

func piiFindings(field string) []piiFinding {
	if field == "" {
		return nil
	}
	text := normalizeForPII(field)
	var findings []piiFinding
	for _, detect := range piiDetectors {
		findings = append(findings, detect(text)...)
	}
	for _, finding := range findings {
		assertPIIFindingInBounds(finding, len(field))
	}
	return findings
}

func assertPIIFindingInBounds(finding piiFinding, fieldLength int) {
	if finding.originalStart < 0 || finding.originalEnd > fieldLength {
		panic("gentrail: pii finding outside its field")
	}
	if finding.originalStart >= finding.originalEnd {
		panic("gentrail: empty pii finding")
	}
}

var emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

var fileExtensionsThatAreNotTLDs = map[string]bool{
	"bmp": true, "css": true, "csv": true, "gif": true, "htm": true, "html": true, "ico": true, "jpeg": true,
	"jpg": true, "js": true, "json": true, "jsx": true, "md": true, "pdf": true, "png": true, "py": true,
	"svg": true, "tif": true, "tiff": true, "toml": true, "ts": true, "tsx": true, "txt": true, "webp": true,
	"xml": true, "yaml": true, "yml": true,
}

func emailFindings(text normalizedText) []piiFinding {
	var findings []piiFinding
	for _, m := range findAllInWindows(emailRe, text.lower, emailWindows(text.lower)) {
		topLevelDomain := text.lower[strings.LastIndexByte(text.lower[m[0]:m[1]], '.')+m[0]+1 : m[1]]
		if fileExtensionsThatAreNotTLDs[topLevelDomain] {
			continue
		}
		findings = append(findings, text.finding(piiClassEmail, m[0], m[1], "email"))
	}
	return findings
}

func emailWindows(lower string) [][2]int {
	var windows [][2]int
	windowEnd := 0
	for at := strings.IndexByte(lower, '@'); at >= 0; {
		if at >= windowEnd {
			start := at
			for start > 0 && isEmailByte(lower[start-1]) {
				start--
			}
			windowEnd = at + 1
			for windowEnd < len(lower) && isEmailByte(lower[windowEnd]) {
				windowEnd++
			}
			windows = append(windows, [2]int{start, windowEnd})
		}
		next := strings.IndexByte(lower[at+1:], '@')
		if next < 0 {
			break
		}
		at += 1 + next
	}
	return windows
}

func isEmailByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || strings.IndexByte("._%+-", b) >= 0
}
