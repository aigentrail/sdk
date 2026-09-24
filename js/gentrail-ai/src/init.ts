import { PolicyEnforcer } from "./enforcement.js";
import { EvidenceLedger } from "./ledger.js";
import { createGovernanceTracer, type GovernanceTracer } from "./tracer.js";

export interface Gentrail {
  readonly tracer: GovernanceTracer | null;
  readonly enforcer: PolicyEnforcer | null;
  readonly ledger: EvidenceLedger;
  flush(): Promise<void>;
  shutdown(): Promise<void>;
}

export function init(): Gentrail {
  const tracer = tracerFromEnvOrNull();
  const enforcer = enforcerFromEnvOrNull();
  return {
    tracer,
    enforcer,
    ledger: new EvidenceLedger(),
    flush: async () => {
      await tracer?.forceFlush();
    },
    shutdown: async () => {
      await tracer?.shutdown();
    },
  };
}

function tracerFromEnvOrNull(): GovernanceTracer | null {
  try {
    return createGovernanceTracer();
  } catch (err) {
    console.warn(`gentrail: governance tracing disabled (${String(err)})`);
    return null;
  }
}

function enforcerFromEnvOrNull(): PolicyEnforcer | null {
  try {
    return PolicyEnforcer.fromEnv();
  } catch (err) {
    console.warn(`gentrail: inline enforcement disabled (${String(err)})`);
    return null;
  }
}
