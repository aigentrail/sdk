package gentrail

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"os"
	"slices"
	"sort"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestExportFilterListsMatchSpec(t *testing.T) {
	raw, err := os.ReadFile("../spec/spans.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		ExportFilter struct {
			AttributePrefixes []string `json:"attribute_prefixes"`
			AttributeKeys     []string `json:"attribute_keys"`
		} `json:"export_filter"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(genAISignalAttributePrefixes, spec.ExportFilter.AttributePrefixes) {
		t.Errorf("prefixes %v, spec %v", genAISignalAttributePrefixes, spec.ExportFilter.AttributePrefixes)
	}
	keys := slices.Collect(maps.Keys(genAISignalAttributeKeys))
	sort.Strings(keys)
	specKeys := slices.Clone(spec.ExportFilter.AttributeKeys)
	sort.Strings(specKeys)
	if !slices.Equal(keys, specKeys) {
		t.Errorf("keys %v, spec %v", keys, specKeys)
	}
}

func TestExportFilterMatchesSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../spec/export_filter_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name       string            `json:"name"`
		Attributes map[string]string `json:"attributes"`
		Exported   bool              `json:"exported"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no export filter vectors")
	}
	for _, vector := range vectors {
		attributes := make([]attribute.KeyValue, 0, len(vector.Attributes))
		for key, value := range vector.Attributes {
			attributes = append(attributes, attribute.String(key, value))
		}
		if got := carriesGenAISignal(attributes); got != vector.Exported {
			t.Errorf("%s: exported=%v, want %v", vector.Name, got, vector.Exported)
		}
	}
}

func TestInstrumentNeverShipsNonGenAISpans(t *testing.T) {
	clearGentrailEnv(t)
	srv, requests := newOTLPCollector(t)
	provider := sdktrace.NewTracerProvider()
	defer provider.Shutdown(context.Background())

	processor, err := Instrument(provider, WithAPIKey("sk-test"), WithEndpoint(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	tracer := provider.Tracer("app")
	_, databaseSpan := tracer.Start(context.Background(), "db.query")
	databaseSpan.SetAttributes(attribute.String("db.statement", "SELECT * FROM users WHERE email='jane.doe@example.com'"))
	databaseSpan.End()
	_, chatSpan := tracer.Start(context.Background(), "chat")
	chatSpan.SetAttributes(attribute.String("gen_ai.system", "openai"))
	chatSpan.End()
	if err := processor.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}

	body := receiveOTLPRequest(t, requests).body
	if !bytes.Contains(body, []byte("openai")) {
		t.Error("the gen_ai span was not exported")
	}
	if bytes.Contains(body, []byte("db.statement")) || bytes.Contains(body, []byte("jane.doe@example.com")) {
		t.Error("a database span reached the collector")
	}
}
