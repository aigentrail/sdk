package gentrail

import (
	"context"
	"testing"
)

func TestInitUnconfiguredDegradesToLedgerOnly(t *testing.T) {
	clearGentrailEnv(t)
	g := Init(context.Background())

	if g.Tracer != nil || g.Enforcer != nil {
		t.Errorf("unconfigured Init = tracer %v enforcer %v, want both nil", g.Tracer, g.Enforcer)
	}
	if g.Ledger == nil {
		t.Fatal("Init must always provide a ledger")
	}
	if len(g.Ledger.All()) != 0 {
		t.Error("Init ledger must start empty")
	}
	if err := g.Flush(context.Background()); err != nil {
		t.Errorf("Flush = %v", err)
	}
	if err := g.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown = %v", err)
	}
}

func TestInitConfiguredBuildsTracerAndEnforcer(t *testing.T) {
	clearGentrailEnv(t)
	srv, requests := newOTLPCollector(t)
	t.Setenv("GENTRAIL_API_KEY", "sk-test")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("GENTRAIL_DECIDE_ENDPOINT", srv.URL)
	g := Init(context.Background())

	if g.Tracer == nil || g.Enforcer == nil || g.Ledger == nil {
		t.Fatalf("configured Init = %+v, want tracer, enforcer, and ledger", g)
	}
	g.Tracer.RecordLLMCall(context.Background(), LLMCallParams{AgentID: "a", ModelID: "m"})
	if err := g.Flush(context.Background()); err != nil {
		t.Fatalf("Flush = %v", err)
	}
	if got := receiveOTLPRequest(t, requests).authorization; got != "Bearer sk-test" {
		t.Errorf("authorization = %q", got)
	}
	if err := g.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown = %v", err)
	}
}

func TestNilGentrailHandleIsNoop(t *testing.T) {
	var g *Gentrail
	if err := g.Flush(context.Background()); err != nil {
		t.Errorf("nil Flush = %v", err)
	}
	if err := g.Shutdown(context.Background()); err != nil {
		t.Errorf("nil Shutdown = %v", err)
	}
}
