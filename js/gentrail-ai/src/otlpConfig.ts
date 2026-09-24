import { readFileSync } from "node:fs";
import type { AgentOptions } from "node:https";

import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import type { SpanExporter } from "@opentelemetry/sdk-trace-base";

export const DEFAULT_OTLP_ENDPOINT = "https://otel.gentrail.ai";
const INSECURE_VALUES = new Set(["true", "1", "yes"]);

export interface OtlpExporterConfig {
  url: string;
  headers?: Record<string, string>;
  httpAgentOptions?: AgentOptions;
}

export function gentrailApiKeyFromEnv(): string {
  const apiKey = (process.env.GENTRAIL_API_KEY ?? "").trim();
  if (apiKey !== "") {
    return apiKey;
  }
  if (process.env.AIGENTRAIL_API_KEY) {
    console.warn(
      "AIGENTRAIL_API_KEY is set but this SDK reads GENTRAIL_API_KEY; governance tracing disabled",
    );
  } else if (process.env.OTEL_EXPORTER_OTLP_ENDPOINT) {
    console.warn(
      "OTEL_EXPORTER_OTLP_ENDPOINT is set but GENTRAIL_API_KEY is not; governance tracing disabled",
    );
  }
  return "";
}

export function redactionEnabledFromEnv(): boolean {
  return (process.env.GENTRAIL_REDACT_PII ?? "").toLowerCase() !== "false";
}

export function otlpTracesUrlFromEnv(): string {
  const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT || DEFAULT_OTLP_ENDPOINT;
  return endpoint.replace(/\/+$/, "") + "/v1/traces";
}

export function otlpAuthHeaders(apiKey: string): Record<string, string> | null {
  if (process.env.OTEL_EXPORTER_OTLP_TRACES_HEADERS || process.env.OTEL_EXPORTER_OTLP_HEADERS) {
    return null;
  }
  return { Authorization: `Bearer ${apiKey}` };
}

export function otlpAgentOptionsFromEnv(): AgentOptions | null {
  const certificatePath = process.env.OTEL_EXPORTER_OTLP_CERTIFICATE ?? "";
  const insecure = INSECURE_VALUES.has(
    (process.env.OTEL_EXPORTER_OTLP_INSECURE ?? "").toLowerCase(),
  );
  if (certificatePath === "" && !insecure) {
    return null;
  }
  const options: AgentOptions = { keepAlive: true };
  if (certificatePath !== "") {
    options.ca = readCertificateAuthority(certificatePath);
  }
  if (insecure) {
    options.rejectUnauthorized = false;
  }
  return options;
}

function readCertificateAuthority(certificatePath: string): Buffer {
  try {
    return readFileSync(certificatePath);
  } catch (err) {
    throw new Error(
      `cannot read OTEL_EXPORTER_OTLP_CERTIFICATE ${certificatePath}: ${String(err)}`,
    );
  }
}

export function otlpExporterConfigFromEnv(apiKey: string): OtlpExporterConfig {
  if (apiKey === "") {
    throw new Error("the Gentrail OTLP exporter needs GENTRAIL_API_KEY");
  }
  const config: OtlpExporterConfig = { url: otlpTracesUrlFromEnv() };
  const headers = otlpAuthHeaders(apiKey);
  if (headers !== null) {
    config.headers = headers;
  }
  const httpAgentOptions = otlpAgentOptionsFromEnv();
  if (httpAgentOptions !== null) {
    config.httpAgentOptions = httpAgentOptions;
  }
  return config;
}

export function buildGentrailOtlpExporter(apiKey: string): SpanExporter {
  return new OTLPTraceExporter(otlpExporterConfigFromEnv(apiKey));
}
