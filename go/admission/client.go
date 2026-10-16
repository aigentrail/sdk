package admission

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const Protocol = "quota_v1"

var ErrQuotaExhausted = errors.New("admission: tool-call allowance exhausted")

type Link struct {
	Required     bool   `json:"required"`
	Protocol     string `json:"protocol"`
	ProposalHash string `json:"proposal_hash"`
	ReserveURL   string `json:"reserve_url"`
}

func (link Link) valid() bool {
	digest, err := hex.DecodeString(link.ProposalHash)
	return err == nil && len(digest) == 32 && link.Required && link.Protocol == Protocol
}

type Client struct {
	DecideEndpoint string
	APIKey         string
	HTTP           *http.Client
	Now            func() time.Time
}

func resolveSameOriginLink(base, link string) (string, error) {
	endpoint, err := url.Parse(base)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "https" && endpoint.Scheme != "http") {
		return "", errors.New("admission: invalid decision endpoint")
	}
	if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return "", errors.New("admission: invalid decision endpoint")
	}
	control, err := url.Parse(link)
	if err != nil || link == "" {
		return "", errors.New("admission: invalid control")
	}
	target := endpoint.ResolveReference(control)
	if target.Scheme != endpoint.Scheme || target.Host != endpoint.Host || target.User != nil || target.Fragment != "" {
		return "", errors.New("admission: control leaves decision origin")
	}
	return target.String(), nil
}

type admissionReceipt struct {
	Outcome             string               `json:"outcome"`
	ExecutionAuthorized bool                 `json:"execution_authorized"`
	ConsumeURL          string               `json:"consume_url"`
	Reservation         admissionReservation `json:"reservation"`
}

type admissionReservation struct {
	RequestID   string `json:"request_id"`
	State       string `json:"state"`
	ExpiresAt   int64  `json:"expires_at"`
	WindowStart int64  `json:"window_start"`
	WindowEnd   int64  `json:"window_end"`
	RevisionID  string `json:"revision_id"`
}

func (c Client) Authorize(ctx context.Context, requestID string, link Link) error {
	if c.HTTP == nil || c.Now == nil {
		return errors.New("admission: HTTP client and clock are required")
	}
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()
	if !link.valid() || requestID == "" {
		return errors.New("admission: invalid decision resource")
	}
	reserved, err := c.exchange(ctx, http.MethodPost, link.ReserveURL, link.ProposalHash)
	if err != nil {
		return err
	}
	if reserved.Outcome == "quota_exhausted" {
		return ErrQuotaExhausted
	}
	if !c.validReceipt(reserved, requestID, "reserved") || reserved.ExecutionAuthorized || reserved.ConsumeURL == "" {
		return errors.New("admission: reservation was not verified")
	}
	consumed, err := c.exchange(ctx, http.MethodPost, reserved.ConsumeURL, link.ProposalHash)
	if err != nil {
		return err
	}
	if !c.validReceipt(consumed, requestID, "consumed") || !consumed.ExecutionAuthorized || !sameAdmissionReservation(reserved, consumed) {
		return errors.New("admission: execution was not authorized")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func (c Client) validReceipt(receipt admissionReceipt, requestID, state string) bool {
	reservation := receipt.Reservation
	now := c.Now().Unix()
	return receipt.Outcome == "verified" && reservation.RequestID == requestID && reservation.State == state &&
		reservation.RevisionID != "" && reservation.WindowStart <= now && now < reservation.ExpiresAt &&
		reservation.ExpiresAt <= reservation.WindowEnd
}

func sameAdmissionReservation(reserved, consumed admissionReceipt) bool {
	expected := reserved.Reservation
	expected.State = "consumed"
	return consumed.Reservation == expected
}

func (c Client) exchange(ctx context.Context, method, link, proposalHash string) (admissionReceipt, error) {
	target, err := resolveSameOriginLink(c.DecideEndpoint, link)
	if err != nil {
		return admissionReceipt{}, err
	}
	body, err := json.Marshal(struct {
		ProposalHash string `json:"proposal_hash"`
	}{proposalHash})
	if err != nil {
		return admissionReceipt{}, err
	}
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return admissionReceipt{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.APIKey)
	request.Header.Set("User-Agent", "gentrail-sdk-go")
	client := *c.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return admissionReceipt{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return admissionReceipt{}, fmt.Errorf("admission: HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return admissionReceipt{}, errors.New("admission: response unreadable or too large")
	}
	var receipt admissionReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return admissionReceipt{}, err
	}
	return receipt, nil
}
