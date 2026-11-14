package admission

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestLegacyQuotaVectorsAreRejected(t *testing.T) {
	testAdmissionVectors(t, "admission_vectors.json", true)
}

func TestOperationAdmissionVectors(t *testing.T) {
	testAdmissionVectors(t, "operation_admission_vectors.json", false)
}

func testAdmissionVectors(t *testing.T, filename string, retired bool) {
	t.Helper()
	raw, err := os.ReadFile("../../spec/" + filename)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name     string          `json:"name"`
		Link     Link            `json:"link"`
		Reserved json.RawMessage `json:"reserved"`
		Consumed json.RawMessage `json:"consumed"`
		Allowed  bool            `json:"allowed"`
		Requests uint32          `json:"requests"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no admission vectors")
	}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			var requests atomic.Uint32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				reply := vector.Reserved
				if r.URL.Path == "/consume" {
					reply = vector.Consumed
				}
				if _, err := w.Write(reply); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			client := Client{DecideEndpoint: server.URL + "/api/v1/decide", APIKey: "key", HTTP: server.Client(), Now: func() time.Time { return time.Unix(100, 0) }}
			err := client.Authorize(context.Background(), "call", vector.Link)
			expectedRequests := vector.Requests
			if retired {
				expectedRequests = 0
			}
			if actual := requests.Load(); actual != expectedRequests {
				t.Fatalf("requests=%d want=%d", actual, expectedRequests)
			}
			allowed := vector.Allowed && !retired
			if (err == nil) != allowed {
				t.Fatalf("allowed=%v want=%v error=%v", err == nil, allowed, err)
			}
		})
	}
}
