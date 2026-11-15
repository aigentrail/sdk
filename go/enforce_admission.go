package gentrail

import (
	"context"
	"errors"

	"github.com/aigentrail/sdk/go/admission"
)

func (e *Enforcer) authorizeAdmission(ctx context.Context, verdict Verdict) (bool, string) {
	if verdict.Admission == nil {
		return false, "Gentrail did not provide execution admission; the call was not run."
	}
	client := admission.Client{DecideEndpoint: e.base + "/api/v1/decide", APIKey: e.apiKey, HTTP: e.client, Now: e.now}
	if err := client.Authorize(ctx, verdict.requestID, *verdict.Admission); err != nil {
		if errors.Is(err, admission.ErrQuotaExhausted) {
			return false, "This agent has used its tool-call allowance for the current quota window."
		}
		if errors.Is(err, admission.ErrAttemptClosed) {
			return false, "This tool-call attempt is already consumed or canceled. Check its outcome before starting a new attempt."
		}
		if errors.Is(err, admission.ErrConsumptionUncertain) {
			return false, "Gentrail could not confirm execution admission. Do not retry automatically; check this attempt's outcome before starting another."
		}
		return false, "Gentrail could not authorize this tool-call attempt. Review its status before starting another."
	}
	return true, ""
}
