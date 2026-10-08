package gentrail

import "github.com/aigentrail/sdk/go/canonicaljson"

// CanonicalJSON serializes value as RFC 8785 (JCS) canonical JSON, so a sealed
// journal hashes identically in every Gentrail SDK: object keys sorted by
// UTF-16 code units, no insignificant whitespace, minimal string escaping, and
// ECMAScript number formatting. It accepts nil, bool, string, every Go integer
// kind, float32, float64, json.Number, []any, and map[string]any. NaN,
// infinities, invalid UTF-8, nesting deeper than 512, and any other type are
// errors.
func CanonicalJSON(value any) (string, error) {
	return canonicaljson.Encode(value)
}
