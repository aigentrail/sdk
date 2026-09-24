import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalJson,
  DecisionJournal,
  EvidenceLedger,
  journalCanonicalDocument,
} from "../src/index.js";
import { readSpecJson } from "./support.js";

interface VectorModelCall {
  model_id: string;
  prompt_preview: string;
  cot_reasoning: string;
  token_usage: Record<string, number>;
  latency_ms: number | null;
}

interface VectorToolCall {
  tool_name: string;
  tool_args: Record<string, unknown>;
  result: string | null;
  duration_ms: number | null;
}

interface JournalVector {
  name: string;
  journal: {
    journal_id: string;
    agent_id: string;
    agent_name: string;
    started_at: string;
    completed_at: string;
    user_message: string;
    final_response: string;
    model_calls: VectorModelCall[];
    tool_calls: VectorToolCall[];
    total_tokens: number;
    sealed: boolean;
  };
  canonical: string;
  integrity_hash: string;
}

function journalFromVector(vector: JournalVector): DecisionJournal {
  const source = vector.journal;
  const journal = new DecisionJournal({
    journalId: source.journal_id,
    agentId: source.agent_id,
    agentName: source.agent_name,
    startedAt: new Date(source.started_at),
  });
  journal.userMessage = source.user_message;
  journal.finalResponse = source.final_response;
  journal.totalTokens = source.total_tokens;
  journal.modelCalls = source.model_calls.map((call) => ({
    modelId: call.model_id,
    promptPreview: call.prompt_preview,
    cotReasoning: call.cot_reasoning,
    tokenUsage: call.token_usage,
    latencyMs: call.latency_ms,
  }));
  journal.toolCalls = source.tool_calls.map((call) => ({
    toolName: call.tool_name,
    toolArgs: call.tool_args,
    result: call.result,
    durationMs: call.duration_ms,
  }));
  return journal;
}

test("sealed journals match the shared canonical form and hash", () => {
  const vectors = readSpecJson("journal_vectors.json") as JournalVector[];
  assert.ok(vectors.length > 0, "no journal vectors");
  for (const vector of vectors) {
    const journal = journalFromVector(vector);
    const hash = journal.seal(new Date(vector.journal.completed_at));
    assert.equal(journal.sealed, vector.journal.sealed, vector.name);
    assert.equal(canonicalJson(journalCanonicalDocument(journal)), vector.canonical, vector.name);
    assert.equal(hash, vector.integrity_hash, vector.name);
    assert.equal(journal.integrityHash, vector.integrity_hash, vector.name);
  }
});

test("the ledger creates, finds, seals, and clears journals with an injected clock and ids", () => {
  const now = new Date("2026-09-24T05:57:37.615Z");
  let issued = 0;
  const ledger = new EvidenceLedger({
    clock: () => now,
    generateJournalId: () => `inv-test-${(issued += 1)}`,
  });
  const billing = ledger.create("agent-billing", "Billing Agent");
  const support = ledger.create("agent-support", "Support Agent");
  assert.equal(billing.journalId, "inv-test-1");
  assert.equal(billing.startedAt, now);
  assert.equal(ledger.get("inv-test-2"), support);
  assert.equal(ledger.get("missing"), null);
  assert.deepEqual(ledger.all(), [billing, support]);
  assert.deepEqual(ledger.byAgent("agent-support"), [support]);
  const hash = ledger.seal("inv-test-1");
  assert.match(hash ?? "", /^[0-9a-f]{64}$/);
  assert.equal(billing.sealed, true);
  assert.equal(billing.completedAt, now);
  assert.equal(ledger.seal("missing"), null);
  ledger.clear();
  assert.deepEqual(ledger.all(), []);
});

test("default journal ids carry the UTC date and six hex characters", () => {
  const ledger = new EvidenceLedger({ clock: () => new Date("2026-01-02T23:59:59.000-05:00") });
  assert.match(ledger.create("a", "A").journalId, /^inv-2026-0103-[0-9a-f]{6}$/);
});
