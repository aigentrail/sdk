export const ADMISSION_PROTOCOL = "operation_v1";
const RESPONSE_SIZE_MAX = 65536;

export class QuotaExhaustedError extends Error {}
export class AttemptClosedError extends Error {}
export class ConsumptionUncertainError extends Error {}

interface Reservation {
  request_id: string;
  state: string;
  policy_digest: string;
  expires_at: number;
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
    if (
      reserved.outcome === "verified" &&
      reserved.execution_authorized === false
    ) {
      for (const state of ["consumed", "released"]) {
        if (
          isRecord(reserved.reservation) &&
          reserved.reservation.state === state
        ) {
          this.checkedReceipt(reserved, requestId, state);
          throw new AttemptClosedError("attempt already consumed or canceled");
        }
      }
    }
    const expected = this.checkedReceipt(reserved, requestId, "reserved");
    if (reserved.execution_authorized !== false) {
      throw new Error("reservation cannot authorize execution");
    }
    try {
      const consumed = await this.exchange(
        reserved.consume_url,
        link.proposal_hash,
        signal,
      );
      const actual = this.checkedReceipt(consumed, requestId, "consumed");
      const sameReservation =
        actual.request_id === expected.request_id &&
        actual.policy_digest === expected.policy_digest &&
        actual.expires_at <= expected.expires_at;
      if (sameReservation && consumed.execution_authorized === false) {
        throw new AttemptClosedError("attempt already consumed or canceled");
      }
      if (!sameReservation || consumed.execution_authorized !== true) {
        throw new Error("execution was not authorized");
      }
      signal.throwIfAborted();
    } catch (error) {
      if (error instanceof AttemptClosedError) {
        throw error;
      }
      throw new ConsumptionUncertainError(
        "consumption could not be confirmed",
        { cause: error },
      );
    }
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
      typeof reservation.policy_digest !== "string" ||
      !/^[a-fA-F0-9]{64}$/.test(reservation.policy_digest)
    ) {
      throw new Error("admission identity mismatch");
    }
    const expires_at = reservation.expires_at;
    if (typeof expires_at !== "number" || !Number.isSafeInteger(expires_at)) {
      throw new Error("invalid admission expiry");
    }
    const now = Math.floor(this.now() / 1000);
    if (!(now > 0 && now < expires_at && expires_at - now <= 30)) {
      throw new Error("expired or invalid admission lease");
    }
    return {
      request_id: requestId,
      state,
      policy_digest: reservation.policy_digest,
      expires_at,
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
