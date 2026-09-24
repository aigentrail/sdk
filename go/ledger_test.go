package gentrail

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"testing"
	"time"
)

type journalVector struct {
	Name    string `json:"name"`
	Journal struct {
		JournalID     string  `json:"journal_id"`
		AgentID       string  `json:"agent_id"`
		AgentName     string  `json:"agent_name"`
		StartedAt     string  `json:"started_at"`
		CompletedAt   *string `json:"completed_at"`
		UserMessage   string  `json:"user_message"`
		FinalResponse string  `json:"final_response"`
		ModelCalls    []struct {
			ModelID       string           `json:"model_id"`
			PromptPreview string           `json:"prompt_preview"`
			CoTReasoning  string           `json:"cot_reasoning"`
			TokenUsage    map[string]int64 `json:"token_usage"`
			LatencyMS     *float64         `json:"latency_ms"`
		} `json:"model_calls"`
		ToolCalls []struct {
			ToolName   string         `json:"tool_name"`
			ToolArgs   map[string]any `json:"tool_args"`
			Result     *string        `json:"result"`
			DurationMS *float64       `json:"duration_ms"`
		} `json:"tool_calls"`
		TotalTokens int64 `json:"total_tokens"`
		Sealed      bool  `json:"sealed"`
	} `json:"journal"`
	Canonical     string `json:"canonical"`
	IntegrityHash string `json:"integrity_hash"`
}

func loadJournalVectors(t *testing.T) []journalVector {
	t.Helper()
	raw, err := os.ReadFile("../spec/journal_vectors.json")
	if err != nil {
		t.Fatalf("read journal vectors: %v", err)
	}
	var vectors []journalVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("unmarshal journal vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("no journal vectors")
	}
	return vectors
}

func parseVectorTimestamp(t *testing.T, text string) time.Time {
	t.Helper()
	moment, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		t.Fatalf("parse %q: %v", text, err)
	}
	return moment
}

func unsealedJournalFromVector(t *testing.T, vector journalVector) *DecisionJournal {
	t.Helper()
	source := vector.Journal
	journal := &DecisionJournal{
		JournalID:     source.JournalID,
		AgentID:       source.AgentID,
		AgentName:     source.AgentName,
		StartedAt:     parseVectorTimestamp(t, source.StartedAt),
		UserMessage:   source.UserMessage,
		FinalResponse: source.FinalResponse,
		TotalTokens:   source.TotalTokens,
	}
	for _, call := range source.ModelCalls {
		journal.ModelCalls = append(journal.ModelCalls, ModelCallRecord{
			ModelID:       call.ModelID,
			PromptPreview: call.PromptPreview,
			CoTReasoning:  call.CoTReasoning,
			TokenUsage:    call.TokenUsage,
			LatencyMS:     call.LatencyMS,
		})
	}
	for _, call := range source.ToolCalls {
		journal.ToolCalls = append(journal.ToolCalls, ToolCallRecord{
			ToolName:   call.ToolName,
			ToolArgs:   call.ToolArgs,
			Result:     call.Result,
			DurationMS: call.DurationMS,
		})
	}
	return journal
}

func TestSealedJournalsMatchSharedVectors(t *testing.T) {
	for _, vector := range loadJournalVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			if !vector.Journal.Sealed || vector.Journal.CompletedAt == nil {
				t.Fatal("vector journals are expected to be sealed")
			}
			journal := unsealedJournalFromVector(t, vector)
			hash := journal.Seal(parseVectorTimestamp(t, *vector.Journal.CompletedAt))

			document, err := journalCanonicalDocument(journal)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := CanonicalJSON(document)
			if err != nil {
				t.Fatal(err)
			}
			if canonical != vector.Canonical {
				t.Errorf("canonical\n got %s\nwant %s", canonical, vector.Canonical)
			}
			if hash != vector.IntegrityHash {
				t.Errorf("hash = %s, want %s", hash, vector.IntegrityHash)
			}
			if journal.IntegrityHash != hash || !journal.Sealed {
				t.Errorf("journal not stamped: sealed=%v hash=%q", journal.Sealed, journal.IntegrityHash)
			}
		})
	}
}

func TestUnsealedJournalDocumentHasNullCompletedAtAndEmptyMaps(t *testing.T) {
	journal := &DecisionJournal{
		JournalID:  "inv-1",
		StartedAt:  time.Date(2026, 9, 24, 5, 57, 37, 615999999, time.FixedZone("PDT", -7*3600)),
		ModelCalls: []ModelCallRecord{{ModelID: "m"}},
		ToolCalls:  []ToolCallRecord{{ToolName: "t"}},
	}
	document, err := journalCanonicalDocument(journal)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"agent_id":"","agent_name":"","completed_at":null,"final_response":"","journal_id":"inv-1",` +
		`"model_calls":[{"cot_reasoning":"","latency_ms":null,"model_id":"m","prompt_preview":"","token_usage":{}}],` +
		`"sealed":false,"started_at":"2026-09-24T12:57:37.615Z",` +
		`"tool_calls":[{"duration_ms":null,"result":null,"tool_args":{},"tool_name":"t"}],"total_tokens":0,"user_message":""}`
	if canonical != want {
		t.Errorf("canonical\n got %s\nwant %s", canonical, want)
	}
}

func TestSealHashesTypedToolArgsAsTheirJSON(t *testing.T) {
	typed := &DecisionJournal{JournalID: "j", ToolCalls: []ToolCallRecord{{
		ToolName: "t",
		ToolArgs: map[string]any{"ids": []int{1, 2}, "tags": map[string]string{"k": "v"}},
	}}}
	generic := &DecisionJournal{JournalID: "j", ToolCalls: []ToolCallRecord{{
		ToolName: "t",
		ToolArgs: map[string]any{"ids": []any{1, 2}, "tags": map[string]any{"k": "v"}},
	}}}
	sealedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if typed.Seal(sealedAt) != generic.Seal(sealedAt) {
		t.Error("typed and generic tool args with the same JSON must hash identically")
	}
}

func TestSealPanicsOnUnhashableJournal(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Seal must panic on a journal holding a non-JSON value")
		}
	}()
	journal := &DecisionJournal{ToolCalls: []ToolCallRecord{{ToolName: "t", ToolArgs: map[string]any{"c": make(chan int)}}}}
	journal.Seal(time.Now())
}

type steppingClock struct {
	next time.Time
	step time.Duration
}

func (c *steppingClock) now() time.Time {
	moment := c.next
	c.next = c.next.Add(c.step)
	return moment
}

func sequentialJournalIDs() func() string {
	count := 0
	return func() string {
		count++
		return fmt.Sprintf("inv-test-%d", count)
	}
}

type ledgerWithThreeJournals struct {
	ledger               *EvidenceLedger
	first, second, third *DecisionJournal
}

func newLedgerWithThreeJournals() ledgerWithThreeJournals {
	clock := &steppingClock{next: time.Date(2026, 9, 24, 5, 0, 0, 0, time.UTC), step: time.Second}
	ledger := NewEvidenceLedger(clock.now, sequentialJournalIDs())
	return ledgerWithThreeJournals{
		ledger: ledger,
		first:  ledger.Create("agent-a", "A"),
		second: ledger.Create("agent-b", "B"),
		third:  ledger.Create("agent-a", "A"),
	}
}

func TestEvidenceLedgerCreateUsesInjectedClockAndIDs(t *testing.T) {
	fixture := newLedgerWithThreeJournals()
	ids := []string{fixture.first.JournalID, fixture.second.JournalID, fixture.third.JournalID}
	if !slices.Equal(ids, []string{"inv-test-1", "inv-test-2", "inv-test-3"}) {
		t.Errorf("ids = %v", ids)
	}
	if !fixture.first.StartedAt.Equal(time.Date(2026, 9, 24, 5, 0, 0, 0, time.UTC)) {
		t.Errorf("StartedAt = %v, want the clock's first reading", fixture.first.StartedAt)
	}
	if fixture.first.Sealed || fixture.first.CompletedAt != nil || fixture.first.IntegrityHash != "" {
		t.Errorf("new journal = %+v, want unsealed", fixture.first)
	}
}

func TestEvidenceLedgerLookups(t *testing.T) {
	fixture := newLedgerWithThreeJournals()
	if got, ok := fixture.ledger.Get("inv-test-2"); !ok || got != fixture.second {
		t.Errorf("Get(inv-test-2) = %v, %v", got, ok)
	}
	if _, ok := fixture.ledger.Get("missing"); ok {
		t.Error("Get(missing) reported found")
	}
	if all := fixture.ledger.All(); !slices.Equal(all, []*DecisionJournal{fixture.first, fixture.second, fixture.third}) {
		t.Errorf("All() not in creation order: %v", all)
	}
	if byAgent := fixture.ledger.ByAgent("agent-a"); !slices.Equal(byAgent, []*DecisionJournal{fixture.first, fixture.third}) {
		t.Errorf("ByAgent(agent-a) = %v", byAgent)
	}
	if byAgent := fixture.ledger.ByAgent("nobody"); len(byAgent) != 0 {
		t.Errorf("ByAgent(nobody) = %v, want empty", byAgent)
	}
}

func TestEvidenceLedgerSealStampsJournalAtClockTime(t *testing.T) {
	fixture := newLedgerWithThreeJournals()
	hash, ok := fixture.ledger.Seal("inv-test-2")
	if !ok || hash == "" {
		t.Fatalf("Seal(inv-test-2) = %q, %v", hash, ok)
	}
	if !fixture.second.Sealed || fixture.second.IntegrityHash != hash {
		t.Errorf("sealed journal not stamped: %+v", fixture.second)
	}
	wantCompleted := time.Date(2026, 9, 24, 5, 0, 3, 0, time.UTC)
	if fixture.second.CompletedAt == nil || !fixture.second.CompletedAt.Equal(wantCompleted) {
		t.Errorf("CompletedAt = %v, want %v", fixture.second.CompletedAt, wantCompleted)
	}
	if recomputed, err := journalIntegrityHash(fixture.second); err != nil || recomputed != hash {
		t.Errorf("recomputed hash = %q (%v), want %q", recomputed, err, hash)
	}
	if _, ok := fixture.ledger.Seal("missing"); ok {
		t.Error("Seal(missing) reported found")
	}
}

func TestEvidenceLedgerClearRemovesEveryJournal(t *testing.T) {
	fixture := newLedgerWithThreeJournals()
	fixture.ledger.Clear()
	if all := fixture.ledger.All(); len(all) != 0 {
		t.Errorf("All() after Clear = %v", all)
	}
	if _, ok := fixture.ledger.Get("inv-test-1"); ok {
		t.Error("Get after Clear reported found")
	}
	if got := fixture.ledger.Create("agent-a", "A").JournalID; got != "inv-test-4" {
		t.Errorf("Create after Clear id = %q, want the generator to continue", got)
	}
}

func TestEvidenceLedgerDefaultJournalIDFormat(t *testing.T) {
	fixed := time.Date(2026, 9, 24, 23, 30, 0, 0, time.FixedZone("UTC-5", -5*3600))
	ledger := NewEvidenceLedger(func() time.Time { return fixed }, nil)
	pattern := regexp.MustCompile(`^inv-2026-0925-[0-9a-f]{6}$`)
	first := ledger.Create("a", "A")
	second := ledger.Create("a", "A")
	for _, id := range []string{first.JournalID, second.JournalID} {
		if !pattern.MatchString(id) {
			t.Errorf("journal id %q does not match %s", id, pattern)
		}
	}
	if first.JournalID == second.JournalID {
		t.Error("default ids collided")
	}
}

func TestEvidenceLedgerRetriesTakenJournalIDs(t *testing.T) {
	ids := []string{"dup", "dup", "fresh"}
	ledger := NewEvidenceLedger(nil, func() string {
		id := ids[0]
		ids = ids[1:]
		return id
	})
	ledger.Create("a", "A")
	if got := ledger.Create("a", "A").JournalID; got != "fresh" {
		t.Errorf("second journal id = %q, want the generator's next unused id", got)
	}
}

func TestEvidenceLedgerPanicsWhenIDGeneratorNeverYieldsAFreshID(t *testing.T) {
	ledger := NewEvidenceLedger(nil, func() string { return "constant" })
	ledger.Create("a", "A")
	defer func() {
		if recover() == nil {
			t.Error("Create must panic when every generated id is taken")
		}
	}()
	ledger.Create("a", "A")
}
