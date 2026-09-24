package gentrail

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

type normalizedText struct {
	text         string
	lower        string
	numericSpans [][2]int
	originOfByte []int
}

func normalizeForPII(original string) normalizedText {
	var builder strings.Builder
	builder.Grow(len(original))
	originOfByte := make([]int, 0, len(original)+1)
	for offset, r := range original {
		if r < utf8.RuneSelf {
			builder.WriteByte(byte(r))
			originOfByte = append(originOfByte, offset)
			continue
		}
		replacement := foldRuneForPII(r)
		builder.WriteString(replacement)
		for range len(replacement) {
			originOfByte = append(originOfByte, offset)
		}
	}
	originOfByte = append(originOfByte, len(original))
	text := builder.String()
	if len(originOfByte) != len(text)+1 {
		panic("gentrail: pii normalization lost its offset map")
	}
	return normalizedText{text: text, lower: asciiLower(text), numericSpans: findNumericSpans(text), originOfByte: originOfByte}
}

func foldRuneForPII(r rune) string {
	switch {
	case r == 0x00AD, r == 0x200B, r == 0x200C, r == 0x200D, r == 0x2060, r == 0xFEFF:
		return ""
	case r >= 0x2010 && r <= 0x2015, r == 0x2212, r == 0xFE58, r == 0xFE63, r == 0xFF0D:
		return "-"
	case unicode.Is(unicode.Zs, r):
		return " "
	}
	return norm.NFKC.String(string(r))
}

func asciiLower(s string) string {
	lowered := []byte(s)
	for i, b := range lowered {
		if b >= 'A' && b <= 'Z' {
			lowered[i] = b + ('a' - 'A')
		}
	}
	return string(lowered)
}

func (t normalizedText) finding(class string, start, end int, detector string) piiFinding {
	if start < 0 || end > len(t.text) || start >= end {
		panic("gentrail: pii span outside normalized text")
	}
	originalStart := t.originOfByte[start]
	lastOriginInSpan := t.originOfByte[end-1]
	originalEnd := t.originOfByte[end]
	for next := end + 1; originalEnd <= lastOriginInSpan; next++ {
		originalEnd = t.originOfByte[next]
	}
	return piiFinding{class: class, originalStart: originalStart, originalEnd: originalEnd, detector: detector}
}

func (t normalizedText) digitAt(i int) bool {
	return i >= 0 && i < len(t.text) && t.text[i] >= '0' && t.text[i] <= '9'
}

func (t normalizedText) alphanumericAt(i int) bool {
	if i < 0 || i >= len(t.text) {
		return false
	}
	b := t.lower[i]
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z')
}

func (t normalizedText) contextBefore(start int, words []string) bool {
	const contextWindowBytes = 40
	window := t.lower[max(0, start-contextWindowBytes):start]
	for _, word := range words {
		if strings.Contains(window, word) {
			return true
		}
	}
	return false
}
