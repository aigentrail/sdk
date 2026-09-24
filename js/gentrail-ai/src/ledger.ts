import { createHash, randomBytes } from "node:crypto";

import { canonicalJson } from "./canonicalJson.js";

export interface ModelCallRecord {
  modelId: string;
  promptPreview: string;
  cotReasoning: string;
  tokenUsage: Record<string, number>;
  latencyMs: number | null;
}

export interface ToolCallRecord {
  toolName: string;
  toolArgs: Record<string, unknown>;
  result: string | null;
  durationMs: number | null;
}

export interface DecisionJournalInit {
  journalId: string;
  agentId: string;
  agentName: string;
  startedAt: Date;
}

export class DecisionJournal {
  readonly journalId: string;
  readonly agentId: string;
  readonly agentName: string;
  readonly startedAt: Date;
  completedAt: Date | null = null;
  userMessage = "";
  finalResponse = "";
  modelCalls: ModelCallRecord[] = [];
  toolCalls: ToolCallRecord[] = [];
  totalTokens = 0;
  sealed = false;
  integrityHash: string | null = null;

  constructor(init: DecisionJournalInit) {
    if (init.journalId === "") {
      throw new Error("a decision journal needs a journal id");
    }
    if (Number.isNaN(init.startedAt.getTime())) {
      throw new Error("a decision journal needs a valid start time");
    }
    this.journalId = init.journalId;
    this.agentId = init.agentId;
    this.agentName = init.agentName;
    this.startedAt = init.startedAt;
  }

  seal(now: Date = new Date()): string {
    this.completedAt = now;
    this.sealed = true;
    this.integrityHash = journalIntegrityHash(this);
    return this.integrityHash;
  }
}

export function journalCanonicalDocument(journal: DecisionJournal): Record<string, unknown> {
  return {
    journal_id: journal.journalId,
    agent_id: journal.agentId,
    agent_name: journal.agentName,
    started_at: journal.startedAt.toISOString(),
    completed_at: journal.completedAt === null ? null : journal.completedAt.toISOString(),
    user_message: journal.userMessage,
    final_response: journal.finalResponse,
    model_calls: journal.modelCalls.map((call) => ({
      model_id: call.modelId,
      prompt_preview: call.promptPreview,
      cot_reasoning: call.cotReasoning,
      token_usage: { ...call.tokenUsage },
      latency_ms: call.latencyMs,
    })),
    tool_calls: journal.toolCalls.map((call) => ({
      tool_name: call.toolName,
      tool_args: call.toolArgs,
      result: call.result,
      duration_ms: call.durationMs,
    })),
    total_tokens: journal.totalTokens,
    sealed: journal.sealed,
  };
}

export function journalIntegrityHash(journal: DecisionJournal): string {
  const canonical = canonicalJson(journalCanonicalDocument(journal));
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

export type Clock = () => Date;

export type JournalIdGenerator = (now: Date) => string;

export interface EvidenceLedgerOptions {
  clock?: Clock;
  generateJournalId?: JournalIdGenerator;
}

export function defaultJournalId(now: Date): string {
  const year = now.getUTCFullYear().toString().padStart(4, "0");
  const month = (now.getUTCMonth() + 1).toString().padStart(2, "0");
  const day = now.getUTCDate().toString().padStart(2, "0");
  return `inv-${year}-${month}${day}-${randomBytes(3).toString("hex")}`;
}

export class EvidenceLedger {
  private readonly journals = new Map<string, DecisionJournal>();
  private readonly clock: Clock;
  private readonly generateJournalId: JournalIdGenerator;

  constructor(options: EvidenceLedgerOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
    this.generateJournalId = options.generateJournalId ?? defaultJournalId;
  }

  create(agentId: string, agentName: string): DecisionJournal {
    const startedAt = this.clock();
    const journal = new DecisionJournal({
      journalId: this.generateJournalId(startedAt),
      agentId,
      agentName,
      startedAt,
    });
    if (this.journals.has(journal.journalId)) {
      throw new Error(`journal id ${journal.journalId} is already in the ledger`);
    }
    this.journals.set(journal.journalId, journal);
    return journal;
  }

  get(journalId: string): DecisionJournal | null {
    return this.journals.get(journalId) ?? null;
  }

  all(): DecisionJournal[] {
    return [...this.journals.values()];
  }

  byAgent(agentId: string): DecisionJournal[] {
    return this.all().filter((journal) => journal.agentId === agentId);
  }

  seal(journalId: string): string | null {
    const journal = this.journals.get(journalId);
    if (journal === undefined) {
      return null;
    }
    return journal.seal(this.clock());
  }

  clear(): void {
    this.journals.clear();
  }
}
