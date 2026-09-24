package gentrail

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const (
	journalTimestampLayout = "2006-01-02T15:04:05.000Z"
	journalIDAttemptsMax   = 16
)

// ModelCallRecord is one LLM call captured in a DecisionJournal. A nil
// LatencyMS means the latency was not measured.
type ModelCallRecord struct {
	ModelID       string
	PromptPreview string
	CoTReasoning  string
	TokenUsage    map[string]int64
	LatencyMS     *float64
}

// ToolCallRecord is one tool invocation captured in a DecisionJournal. A nil
// Result or DurationMS means the value was not captured.
type ToolCallRecord struct {
	ToolName   string
	ToolArgs   map[string]any
	Result     *string
	DurationMS *float64
}

// DecisionJournal is the evidence package for one agent invocation. Seal
// stamps it with an RFC 8785 integrity hash that every Gentrail SDK computes
// identically for the same journal.
type DecisionJournal struct {
	JournalID     string
	AgentID       string
	AgentName     string
	StartedAt     time.Time
	CompletedAt   *time.Time
	UserMessage   string
	FinalResponse string
	ModelCalls    []ModelCallRecord
	ToolCalls     []ToolCallRecord
	TotalTokens   int64
	Sealed        bool
	IntegrityHash string
}

// Seal marks the journal completed at now and returns its integrity hash: the
// sha256 hex of the canonical JSON of the journal's canonical document.
// ToolArgs values are hashed as their encoding/json form. It panics when the
// journal holds a value JSON cannot represent (NaN, infinity, a channel), since
// a journal that cannot be hashed cannot serve as evidence.
func (j *DecisionJournal) Seal(now time.Time) string {
	completedAt := now
	j.CompletedAt = &completedAt
	j.Sealed = true
	hash, err := journalIntegrityHash(j)
	if err != nil {
		panic(fmt.Sprintf("gentrail: seal journal %q: %v", j.JournalID, err))
	}
	j.IntegrityHash = hash
	return hash
}

func journalIntegrityHash(j *DecisionJournal) (string, error) {
	document, err := journalCanonicalDocument(j)
	if err != nil {
		return "", err
	}
	canonical, err := CanonicalJSON(document)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:]), nil
}

func journalCanonicalDocument(j *DecisionJournal) (map[string]any, error) {
	var completedAt any
	if j.CompletedAt != nil {
		completedAt = formatJournalTimestamp(*j.CompletedAt)
	}
	modelCalls := make([]any, len(j.ModelCalls))
	for i, call := range j.ModelCalls {
		modelCalls[i] = modelCallCanonicalDocument(call)
	}
	toolCalls := make([]any, len(j.ToolCalls))
	for i, call := range j.ToolCalls {
		document, err := toolCallCanonicalDocument(call)
		if err != nil {
			return nil, err
		}
		toolCalls[i] = document
	}
	return map[string]any{
		"journal_id":     j.JournalID,
		"agent_id":       j.AgentID,
		"agent_name":     j.AgentName,
		"started_at":     formatJournalTimestamp(j.StartedAt),
		"completed_at":   completedAt,
		"user_message":   j.UserMessage,
		"final_response": j.FinalResponse,
		"model_calls":    modelCalls,
		"tool_calls":     toolCalls,
		"total_tokens":   j.TotalTokens,
		"sealed":         j.Sealed,
	}, nil
}

func modelCallCanonicalDocument(call ModelCallRecord) map[string]any {
	tokenUsage := make(map[string]any, len(call.TokenUsage))
	for kind, count := range call.TokenUsage {
		tokenUsage[kind] = count
	}
	return map[string]any{
		"model_id":       call.ModelID,
		"prompt_preview": call.PromptPreview,
		"cot_reasoning":  call.CoTReasoning,
		"token_usage":    tokenUsage,
		"latency_ms":     optionalFloat(call.LatencyMS),
	}
}

func toolCallCanonicalDocument(call ToolCallRecord) (map[string]any, error) {
	toolArgs, err := toolArgsAsJSONValue(call.ToolArgs)
	if err != nil {
		return nil, fmt.Errorf("gentrail: tool %q args: %w", call.ToolName, err)
	}
	var result any
	if call.Result != nil {
		result = *call.Result
	}
	return map[string]any{
		"tool_name":   call.ToolName,
		"tool_args":   toolArgs,
		"result":      result,
		"duration_ms": optionalFloat(call.DurationMS),
	}, nil
}

// toolArgsAsJSONValue round-trips through encoding/json so args holding
// structs, typed slices, or typed maps hash as the JSON a Python caller would
// have sent, with numbers kept exact as json.Number.
func toolArgsAsJSONValue(toolArgs map[string]any) (any, error) {
	if toolArgs == nil {
		return map[string]any{}, nil
	}
	encoded, err := json.Marshal(toolArgs)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func optionalFloat(value *float64) any {
	if value == nil {
		return nil
	}
	return *value
}

func formatJournalTimestamp(moment time.Time) string {
	return moment.UTC().Format(journalTimestampLayout)
}

// EvidenceLedger holds the decision journals of one process, safe for
// concurrent use. Journals it returns are shared, not copied.
type EvidenceLedger struct {
	mutex        sync.Mutex
	now          func() time.Time
	newJournalID func() string
	journals     map[string]*DecisionJournal
	order        []string
}

// NewEvidenceLedger builds an empty ledger. A nil now uses time.Now; a nil
// newJournalID generates "inv-YYYY-MMDD-xxxxxx" ids from now and crypto/rand.
func NewEvidenceLedger(now func() time.Time, newJournalID func() string) *EvidenceLedger {
	if now == nil {
		now = time.Now
	}
	if newJournalID == nil {
		newJournalID = func() string { return randomLedgerJournalID(now()) }
	}
	return &EvidenceLedger{
		now:          now,
		newJournalID: newJournalID,
		journals:     map[string]*DecisionJournal{},
	}
}

func randomLedgerJournalID(now time.Time) string {
	var suffix [3]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		panic("gentrail: crypto/rand failed: " + err.Error())
	}
	return "inv-" + now.UTC().Format("2006-0102") + "-" + hex.EncodeToString(suffix[:])
}

// Create starts a new unsealed journal for the agent and records it. It
// panics if the id generator keeps returning ids already in the ledger.
func (l *EvidenceLedger) Create(agentID, agentName string) *DecisionJournal {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	journal := &DecisionJournal{
		JournalID: l.unusedJournalID(),
		AgentID:   agentID,
		AgentName: agentName,
		StartedAt: l.now(),
	}
	l.journals[journal.JournalID] = journal
	l.order = append(l.order, journal.JournalID)
	return journal
}

func (l *EvidenceLedger) unusedJournalID() string {
	for range journalIDAttemptsMax {
		id := l.newJournalID()
		if _, taken := l.journals[id]; !taken {
			return id
		}
	}
	panic(fmt.Sprintf("gentrail: journal id generator returned %d ids already in the ledger", journalIDAttemptsMax))
}

// Get returns the journal with the given id.
func (l *EvidenceLedger) Get(journalID string) (*DecisionJournal, bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	journal, ok := l.journals[journalID]
	return journal, ok
}

// All returns every journal in creation order.
func (l *EvidenceLedger) All() []*DecisionJournal {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	all := make([]*DecisionJournal, 0, len(l.order))
	for _, id := range l.order {
		all = append(all, l.journals[id])
	}
	return all
}

// ByAgent returns the agent's journals in creation order.
func (l *EvidenceLedger) ByAgent(agentID string) []*DecisionJournal {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	var matching []*DecisionJournal
	for _, id := range l.order {
		if journal := l.journals[id]; journal.AgentID == agentID {
			matching = append(matching, journal)
		}
	}
	return matching
}

// Seal seals the journal with the given id at the ledger's current time and
// returns its integrity hash; ok is false when no such journal exists.
func (l *EvidenceLedger) Seal(journalID string) (hash string, ok bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	journal, ok := l.journals[journalID]
	if !ok {
		return "", false
	}
	return journal.Seal(l.now()), true
}

// Clear removes every journal.
func (l *EvidenceLedger) Clear() {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.journals = map[string]*DecisionJournal{}
	l.order = nil
}
