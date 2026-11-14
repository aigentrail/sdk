package canonicaljson

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIntegerNormalizationPreservesDigitsWithoutBigIntegerArithmetic(t *testing.T) {
	for input, expected := range map[string]string{"9007199254740993": "9007199254740993", "-0": "0", "+00012": "12", "-00012": "-12"} {
		actual, err := Encode(json.Number(input))
		if err != nil || actual != expected {
			t.Fatal("integer normalization changed", input, actual, err)
		}
	}
	large := "1" + strings.Repeat("7", 200000)
	if actual, err := Encode(json.Number(large)); err != nil || actual != large {
		t.Fatal("bounded large integer lost its digits", err)
	}
	for _, invalid := range []string{"", "-", "1-2", "0x10"} {
		if _, err := Encode(json.Number(invalid)); err == nil {
			t.Fatal("invalid integer accepted", invalid)
		}
	}
}
