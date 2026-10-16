package gentrail

import (
	"context"
	"errors"

	"github.com/aigentrail/sdk/go/admission"
)

func (e *Enforcer) authorizeAdmission(ctx context.Context, verdict Verdict) (bool, string) {
	if verdict.Admission == nil {
		return true, ""
	}
	if !e.strictAdmission {
		return false, "Strict tool-call quotas require WithStrictAdmission and an agent-bound credential."
	}
	client := admission.Client{DecideEndpoint: e.base + "/api/v1/decide", APIKey: e.apiKey, HTTP: e.client, Now: e.now}
	if err := client.Authorize(ctx, verdict.requestID, *verdict.Admission); err != nil {
		if errors.Is(err, admission.ErrQuotaExhausted) {
			return false, "This agent has used its tool-call allowance for the current quota window."
		}
		return false, "Gentrail could not authorize this tool-call attempt; the call was not run."
	}
	return true, ""
}
