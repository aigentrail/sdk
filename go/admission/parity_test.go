package admission

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestSharedAdmissionVectors(t *testing.T) {
	raw, err := os.ReadFile("../../spec/admission_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name     string          `json:"name"`
		Link     Link            `json:"link"`
		Reserved json.RawMessage `json:"reserved"`
		Consumed json.RawMessage `json:"consumed"`
		Allowed  bool            `json:"allowed"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no admission vectors")
	}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			if (err == nil) != vector.Allowed {
				t.Fatalf("allowed=%v want=%v error=%v", err == nil, vector.Allowed, err)
			}
		})
	}
}
