package gentrail

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestCanonicalJSONFormatsNumbersLikeECMAScript(t *testing.T) {
	cases := []struct {
		number float64
		want   string
	}{
		{1.5e-7, "1.5e-7"},
		{1e21, "1e+21"},
		{1e20, "100000000000000000000"},
		{123.456, "123.456"},
		{0.0001, "0.0001"},
		{1e-7, "1e-7"},
		{1e-6, "0.000001"},
		{-0.5, "-0.5"},
		{5e-324, "5e-324"},
		{1.7976931348623157e308, "1.7976931348623157e+308"},
		{2.0, "2"},
		{sumOfPointOneAndPointTwo(), "0.30000000000000004"},
		{0, "0"},
		{math.Copysign(0, -1), "0"},
		{-1e21, "-1e+21"},
		{123456789012345680000, "123456789012345680000"},
	}
	for _, c := range cases {
		got, err := CanonicalJSON(c.number)
		if err != nil {
			t.Errorf("%v: %v", c.number, err)
			continue
		}
		if got != c.want {
			t.Errorf("CanonicalJSON(%v) = %q, want %q", c.number, got, c.want)
		}
	}
}

func TestCanonicalJSONRejectsNonFiniteNumbers(t *testing.T) {
	for _, number := range []any{math.NaN(), math.Inf(1), math.Inf(-1), float32(math.Inf(1)), json.Number("1e400")} {
		if got, err := CanonicalJSON(number); err == nil {
			t.Errorf("CanonicalJSON(%v) = %q, want error", number, got)
		}
	}
}

func TestCanonicalJSONFormatsIntegerKindsExactly(t *testing.T) {
	cases := []struct {
		value any
		want  string
	}{
		{int(-7), "-7"},
		{int8(-128), "-128"},
		{int16(32767), "32767"},
		{int32(-2147483648), "-2147483648"},
		{int64(math.MaxInt64), "9223372036854775807"},
		{uint(7), "7"},
		{uint8(255), "255"},
		{uint16(65535), "65535"},
		{uint32(4294967295), "4294967295"},
		{uint64(math.MaxUint64), "18446744073709551615"},
		{json.Number("4411"), "4411"},
		{json.Number("-0"), "0"},
		{json.Number("123456789012345678901234567890"), "123456789012345678901234567890"},
		{json.Number("19.99"), "19.99"},
		{json.Number("1.0"), "1"},
		{json.Number("1E+21"), "1e+21"},
		{float32(0.5), "0.5"},
	}
	for _, c := range cases {
		got, err := CanonicalJSON(c.value)
		if err != nil {
			t.Errorf("%T(%v): %v", c.value, c.value, err)
			continue
		}
		if got != c.want {
			t.Errorf("CanonicalJSON(%T(%v)) = %q, want %q", c.value, c.value, got, c.want)
		}
	}
}

func TestCanonicalJSONEscapesStringsMinimally(t *testing.T) {
	cases := []struct{ in, want string }{
		{`say "hi" \ bye`, `"say \"hi\" \\ bye"`},
		{"\b\f\n\r\t", `"\b\f\n\r\t"`},
		{"\x00\x01\x1f", `"\u0000\u0001\u001f"`},
		{"<a>&amp;\u2028\u2029\x7f", "\"<a>&amp;\u2028\u2029\x7f\""},
		{"Été \U0001F600", "\"Été \U0001F600\""},
	}
	for _, c := range cases {
		got, err := CanonicalJSON(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("CanonicalJSON(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestCanonicalJSONSortsKeysByUTF16CodeUnits(t *testing.T) {
	object := map[string]any{"\uffff": 2, "\U0001F600": 1, "b": true, "a": nil, "é": "x", "": []any{}}
	got, err := CanonicalJSON(object)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"\":[],\"a\":null,\"b\":true,\"é\":\"x\",\"\U0001F600\":1,\"\uffff\":2}"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestCanonicalJSONNestsContainersWithoutWhitespace(t *testing.T) {
	value := map[string]any{
		"list":   []any{1, []any{}, map[string]any{}, []any{map[string]any{"z": false, "y": []any{nil}}}},
		"nested": map[string]any{"b": map[string]any{"k": -0.5}, "a": "first"},
	}
	got, err := CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"list":[1,[],{},[{"y":[null],"z":false}]],"nested":{"a":"first","b":{"k":-0.5}}}`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestCanonicalJSONRejectsUnsupportedValues(t *testing.T) {
	for _, value := range []any{
		struct{}{},
		[]string{"a"},
		map[string]string{"a": "b"},
		"\xff",
		map[string]any{"\xff": 1},
		[]any{1, make(chan int)},
	} {
		if got, err := CanonicalJSON(value); err == nil {
			t.Errorf("CanonicalJSON(%#v) = %q, want error", value, got)
		}
	}
}

func TestCanonicalJSONBoundsNestingDepth(t *testing.T) {
	var deepest any = "leaf"
	for range canonicalJSONDepthMax {
		deepest = []any{deepest}
	}
	got, err := CanonicalJSON(deepest)
	if err != nil {
		t.Fatalf("depth %d: %v", canonicalJSONDepthMax, err)
	}
	if want := strings.Repeat("[", canonicalJSONDepthMax) + `"leaf"` + strings.Repeat("]", canonicalJSONDepthMax); got != want {
		t.Errorf("depth %d serialized wrong", canonicalJSONDepthMax)
	}
	if _, err := CanonicalJSON([]any{deepest}); err == nil {
		t.Errorf("depth %d: want error", canonicalJSONDepthMax+1)
	}
}

func sumOfPointOneAndPointTwo() float64 {
	pointOne, pointTwo := 0.1, 0.2
	return pointOne + pointTwo
}
