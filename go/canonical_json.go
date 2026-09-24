package gentrail

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const canonicalJSONDepthMax = 512

// CanonicalJSON serializes value as RFC 8785 (JCS) canonical JSON, so a sealed
// journal hashes identically in every Gentrail SDK: object keys sorted by
// UTF-16 code units, no insignificant whitespace, minimal string escaping, and
// ECMAScript number formatting. It accepts nil, bool, string, every Go integer
// kind, float32, float64, json.Number, []any, and map[string]any. NaN,
// infinities, invalid UTF-8, nesting deeper than 512, and any other type are
// errors.
func CanonicalJSON(value any) (string, error) {
	var out strings.Builder
	var stack []canonicalContainer
	if err := writeCanonicalValue(&out, &stack, value); err != nil {
		return "", err
	}
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		if top.nextIndex == top.length() {
			out.WriteByte(top.closingByte())
			stack = stack[:len(stack)-1]
			continue
		}
		if top.nextIndex > 0 {
			out.WriteByte(',')
		}
		element := top.writeKeyAndTakeElement(&out)
		if err := writeCanonicalValue(&out, &stack, element); err != nil {
			return "", err
		}
	}
	return out.String(), nil
}

type canonicalContainer struct {
	isObject   bool
	array      []any
	object     map[string]any
	sortedKeys []string
	nextIndex  int
}

func (c *canonicalContainer) length() int {
	if c.isObject {
		return len(c.sortedKeys)
	}
	return len(c.array)
}

func (c *canonicalContainer) closingByte() byte {
	if c.isObject {
		return '}'
	}
	return ']'
}

func (c *canonicalContainer) writeKeyAndTakeElement(out *strings.Builder) any {
	index := c.nextIndex
	c.nextIndex++
	if !c.isObject {
		return c.array[index]
	}
	key := c.sortedKeys[index]
	writeCanonicalString(out, key)
	out.WriteByte(':')
	return c.object[key]
}

func writeCanonicalValue(out *strings.Builder, stack *[]canonicalContainer, value any) error {
	switch v := value.(type) {
	case []any:
		return pushCanonicalContainer(out, stack, canonicalContainer{array: v}, '[')
	case map[string]any:
		sortedKeys, err := keysInUTF16Order(v)
		if err != nil {
			return err
		}
		return pushCanonicalContainer(out, stack, canonicalContainer{isObject: true, object: v, sortedKeys: sortedKeys}, '{')
	case string:
		if !utf8.ValidString(v) {
			return fmt.Errorf("gentrail: canonical JSON string %q is not valid UTF-8", v)
		}
		writeCanonicalString(out, v)
		return nil
	default:
		scalar, err := canonicalScalar(value)
		if err != nil {
			return err
		}
		out.WriteString(scalar)
		return nil
	}
}

func pushCanonicalContainer(out *strings.Builder, stack *[]canonicalContainer, container canonicalContainer, openingByte byte) error {
	if len(*stack) >= canonicalJSONDepthMax {
		return fmt.Errorf("gentrail: canonical JSON nesting exceeds %d levels", canonicalJSONDepthMax)
	}
	out.WriteByte(openingByte)
	*stack = append(*stack, container)
	return nil
}

func keysInUTF16Order(object map[string]any) ([]string, error) {
	type keyWithUnits struct {
		key   string
		units []uint16
	}
	keyed := make([]keyWithUnits, 0, len(object))
	for key := range object {
		if !utf8.ValidString(key) {
			return nil, fmt.Errorf("gentrail: canonical JSON key %q is not valid UTF-8", key)
		}
		keyed = append(keyed, keyWithUnits{key: key, units: utf16.Encode([]rune(key))})
	}
	slices.SortFunc(keyed, func(a, b keyWithUnits) int { return slices.Compare(a.units, b.units) })
	sortedKeys := make([]string, len(keyed))
	for i, entry := range keyed {
		sortedKeys[i] = entry.key
	}
	return sortedKeys, nil
}

func canonicalScalar(value any) (string, error) {
	if integer, ok := canonicalInteger(value); ok {
		return integer, nil
	}
	switch v := value.(type) {
	case nil:
		return "null", nil
	case bool:
		return strconv.FormatBool(v), nil
	case float64:
		return ecmascriptNumber(v)
	case float32:
		return ecmascriptNumber(float64(v))
	case json.Number:
		return canonicalJSONNumber(v)
	default:
		return "", fmt.Errorf("gentrail: %T is not canonical JSON", value)
	}
}

func canonicalInteger(value any) (string, bool) {
	switch v := value.(type) {
	case int:
		return strconv.FormatInt(int64(v), 10), true
	case int8:
		return strconv.FormatInt(int64(v), 10), true
	case int16:
		return strconv.FormatInt(int64(v), 10), true
	case int32:
		return strconv.FormatInt(int64(v), 10), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case uint:
		return strconv.FormatUint(uint64(v), 10), true
	case uint8:
		return strconv.FormatUint(uint64(v), 10), true
	case uint16:
		return strconv.FormatUint(uint64(v), 10), true
	case uint32:
		return strconv.FormatUint(uint64(v), 10), true
	case uint64:
		return strconv.FormatUint(v, 10), true
	default:
		return "", false
	}
}

// canonicalJSONNumber keeps integer literals exact, as the Python SDK does for
// ints, instead of rounding them through float64.
func canonicalJSONNumber(number json.Number) (string, error) {
	text := string(number)
	if !strings.ContainsAny(text, ".eE") {
		integer, ok := new(big.Int).SetString(text, 10)
		if !ok {
			return "", fmt.Errorf("gentrail: canonical JSON number %q is not an integer", text)
		}
		return integer.String(), nil
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return "", fmt.Errorf("gentrail: canonical JSON number %q: %w", text, err)
	}
	return ecmascriptNumber(f)
}

func writeCanonicalString(out *strings.Builder, s string) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

func ecmascriptNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("gentrail: canonical JSON has no NaN or Infinity, got %v", f)
	}
	if f == 0 {
		return "0", nil
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	scientific := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, exponentText, found := strings.Cut(scientific, "e")
	if !found {
		panic("gentrail: strconv 'e' format produced no exponent: " + scientific)
	}
	exponent, err := strconv.Atoi(exponentText)
	if err != nil {
		panic("gentrail: strconv 'e' format produced a bad exponent: " + scientific)
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	return sign + placeDecimalPoint(digits, exponent+1), nil
}

func placeDecimalPoint(digits string, point int) string {
	count := len(digits)
	if count == 0 {
		panic("gentrail: placeDecimalPoint needs at least one digit")
	}
	if count <= point && point <= 21 {
		return digits + strings.Repeat("0", point-count)
	}
	if 0 < point && point <= 21 {
		return digits[:point] + "." + digits[point:]
	}
	if -6 < point && point <= 0 {
		return "0." + strings.Repeat("0", -point) + digits
	}
	exponent := point - 1
	mantissa := digits[:1]
	if count > 1 {
		mantissa += "." + digits[1:]
	}
	if exponent > 0 {
		return mantissa + "e+" + strconv.Itoa(exponent)
	}
	return mantissa + "e-" + strconv.Itoa(-exponent)
}
