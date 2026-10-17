export const ADMISSION_PROTOCOL = "quota_v1";
const RESPONSE_SIZE_MAX = 65536;

export class QuotaExhaustedError extends Error {}

interface Reservation {
  request_id: string;
  state: string;
  revision_id: string;
  window_start: number;
  expires_at: number;
  window_end: number;
}

export function sameOriginLink(endpoint: string, link: unknown): string {
  const base = new URL(endpoint);
  if (
    !["http:", "https:"].includes(base.protocol) ||
    base.username ||
    base.password ||
    base.search ||
    base.hash
  ) {
    throw new Error("invalid decision endpoint");
  }
  if (typeof link !== "string" || link === "") {
    throw new Error("missing admission control");
  }
  const target = new URL(link, base);
  if (
    target.origin !== base.origin ||
    target.username ||
    target.password ||
    target.hash
  ) {
    throw new Error("admission control leaves decision origin");
  }
  return target.href;
}

export async function boundedJson(
  response: Response,
  sizeMax: number,
): Promise<unknown> {
  if (!response.body) {
    throw new Error("missing response body");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      size += value.byteLength;
      if (size > sizeMax) {
        throw new Error("response too large");
      }
      chunks.push(value);
    }
    const raw = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      raw.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
}

export class AdmissionClient {
  constructor(
    private readonly endpoint: string,
    private readonly apiKey: string,
    private readonly timeoutMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  async authorize(requestId: string, link: unknown): Promise<void> {
    if (
      !isRecord(link) ||
      !requestId ||
      link.required !== true ||
      link.protocol !== ADMISSION_PROTOCOL
    ) {
      throw new Error("invalid admission resource");
    }
    if (
      typeof link.proposal_hash !== "string" ||
      !/^[a-fA-F0-9]{64}$/.test(link.proposal_hash)
    ) {
      throw new Error("invalid proposal hash");
    }
    const signal = AbortSignal.timeout(9000);
    const reserved = await this.exchange(
      link.reserve_url,
      link.proposal_hash,
      signal,
    );
    if (reserved.outcome === "quota_exhausted") {
      throw new QuotaExhaustedError("tool-call allowance exhausted");
    }
    const expected = this.checkedReceipt(reserved, requestId, "reserved");
    if (
      reserved.execution_authorized !== undefined &&
      reserved.execution_authorized !== false
    ) {
      throw new Error("reservation cannot authorize execution");
    }
    const consumed = await this.exchange(
      reserved.consume_url,
      link.proposal_hash,
      signal,
    );
    const actual = this.checkedReceipt(consumed, requestId, "consumed");
    if (
      consumed.execution_authorized !== true ||
      JSON.stringify(actual) !==
        JSON.stringify({ ...expected, state: "consumed" })
    ) {
      throw new Error("execution was not authorized");
    }
    signal.throwIfAborted();
  }

  private checkedReceipt(
    receipt: Record<string, unknown>,
    requestId: string,
    state: string,
  ): Reservation {
    const reservation = receipt.reservation;
    if (receipt.outcome !== "verified" || !isRecord(reservation)) {
      throw new Error("unverified admission receipt");
    }
    if (
      reservation.request_id !== requestId ||
      reservation.state !== state ||
      typeof reservation.revision_id !== "string" ||
      !reservation.revision_id
    ) {
      throw new Error("admission identity mismatch");
    }
    const { window_start, expires_at, window_end } = reservation;
    if (
      typeof window_start !== "number" ||
      typeof expires_at !== "number" ||
      typeof window_end !== "number"
    ) {
      throw new Error("invalid admission timestamps");
    }
    if (![window_start, expires_at, window_end].every(Number.isSafeInteger)) {
      throw new Error("invalid admission timestamps");
    }
    const now = Math.floor(this.now() / 1000);
    if (
      !(window_start <= now && now < expires_at && expires_at <= window_end)
    ) {
      throw new Error("expired or invalid admission window");
    }
    return {
      request_id: requestId,
      state,
      revision_id: reservation.revision_id,
      window_start,
      expires_at,
      window_end,
    };
  }

  private async exchange(
    link: unknown,
    proposalHash: string,
    deadline: AbortSignal,
  ): Promise<Record<string, unknown>> {
    const target = sameOriginLink(this.endpoint, link);
    deadline.throwIfAborted();
    const response = await fetch(target, {
      method: "POST",
      redirect: "error",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
        "User-Agent": "gentrail-sdk-js",
      },
      body: JSON.stringify({ proposal_hash: proposalHash }),
      signal: AbortSignal.any([
        deadline,
        AbortSignal.timeout(Math.min(this.timeoutMs, 3000)),
      ]),
    });
    if (response.status !== 200) {
      await response.body?.cancel();
      throw new Error(`admission returned ${response.status}`);
    }
    const receipt = await boundedJson(response, RESPONSE_SIZE_MAX);
    if (!isRecord(receipt)) {
      throw new Error("invalid admission response");
    }
    return receipt;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
