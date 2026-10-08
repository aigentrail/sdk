package gentrail

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"go.opentelemetry.io/otel/attribute"
)

type DecisionReference struct {
	RequestID     string `json:"request_id"`
	InvocationID  string `json:"invocation_id"`
	ProposalHash  string `json:"proposal_hash"`
	ArgumentsHash string `json:"arguments_hash"`
}

func (reference DecisionReference) validate() error {
	if strings.TrimSpace(reference.RequestID) == "" || len(reference.RequestID) > 256 || reference.InvocationID == "" || len(reference.InvocationID) > 256 {
		return errors.New("invalid observation request identity")
	}
	for _, value := range []string{reference.ProposalHash, reference.ArgumentsHash} {
		digest, err := hex.DecodeString(value)
		if err != nil || len(digest) != 32 || value != strings.ToLower(value) {
			return errors.New("invalid observation digest")
		}
	}
	return nil
}

func observationArgumentsHash(raw string) (string, error) {
	if len(raw) > 2*1024*1024 {
		return "", errors.New("observation arguments exceed size limit")
	}
	arguments := map[string]any{}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &arguments); err != nil {
			return "", errors.New("observation arguments must be a JSON object")
		}
	}
	if arguments == nil {
		arguments = map[string]any{}
	}
	encoded, err := CanonicalJSON(arguments)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(digest[:]), nil
}

func observationReferenceAttributes(reference *DecisionReference, arguments string) ([]attribute.KeyValue, error) {
	if reference == nil {
		return nil, nil
	}
	if err := reference.validate(); err != nil {
		return nil, err
	}
	argumentsHash, err := observationArgumentsHash(arguments)
	if err != nil {
		return nil, err
	}
	return []attribute.KeyValue{
		attribute.String("aigentrail.decision.request_id", reference.RequestID),
		attribute.String("aigentrail.decision.invocation_id", reference.InvocationID),
		attribute.String("aigentrail.decision.proposal_hash", reference.ProposalHash),
		attribute.String("aigentrail.decision.arguments_hash", argumentsHash),
	}, nil
}

func (verdict *Verdict) validateObservationReference(request decideRequest) {
	if verdict.Reference == nil {
		return
	}
	if verdict.Outcome != "verified" || verdict.Reference.validate() != nil || verdict.Reference.RequestID != request.RequestID || verdict.Reference.InvocationID != request.InvocationID {
		verdict.Reference = nil
		return
	}
	encoded, err := json.Marshal(request.ToolArgs)
	if err != nil {
		verdict.Reference = nil
		return
	}
	digest, err := observationArgumentsHash(string(encoded))
	if err != nil || digest != verdict.Reference.ArgumentsHash {
		verdict.Reference = nil
	}
}
