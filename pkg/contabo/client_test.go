package contabo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestClientCreateListDelete(t *testing.T) {
	var (
		gotTokenReq bool
		gotCreate   bool
		gotDelete   bool
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("token method = %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		vals, _ := url.ParseQuery(string(body))
		if vals.Get("client_id") != "id" || vals.Get("client_secret") != "secret" || vals.Get("username") != "user" || vals.Get("password") != "pass" || vals.Get("grant_type") != "password" {
			t.Fatalf("unexpected token params: %v", vals)
		}
		gotTokenReq = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token123","token_type":"Bearer","expires_in":3600}`))
	})

	mux.HandleFunc("/v1/dns/zones/example.com/records", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token123" {
			t.Fatalf("missing auth header")
		}

		switch r.Method {
		case http.MethodPost:
			var req CreateRecordRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode create: %v", err)
			}
			if req.Name != "_acme-challenge" || req.Type != "TXT" || req.Data != "value" {
				t.Fatalf("unexpected create request: %+v", req)
			}
			gotCreate = true
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"recordId":42,"name":"_acme-challenge","type":"TXT","data":"value","ttl":120,"prio":0}]}`))
		default:
			t.Fatalf("unexpected method: %s", r.Method)
		}
	})

	mux.HandleFunc("/v1/dns/zones/example.com/records/42", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("delete method = %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer token123" {
			t.Fatalf("missing auth header on delete")
		}
		gotDelete = true
		w.WriteHeader(http.StatusNoContent)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client, err := NewClientWithAuthURL(server.URL, server.URL+"/token", "id", "secret", "user", "pass", 5*time.Second)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	ctx := context.Background()
	if err := client.CreateRecord(ctx, "example.com", CreateRecordRequest{Name: "_acme-challenge", Type: "TXT", Data: "value"}); err != nil {
		t.Fatalf("create record: %v", err)
	}

	records, err := client.ListRecords(ctx, "example.com", "_acme-challenge")
	if err != nil {
		t.Fatalf("list records: %v", err)
	}
	if len(records) != 1 || records[0].RecordID != 42 {
		t.Fatalf("unexpected records: %+v", records)
	}

	if err := client.DeleteRecord(ctx, "example.com", "42"); err != nil {
		t.Fatalf("delete record: %v", err)
	}

	if !gotTokenReq || !gotCreate || !gotDelete {
		t.Fatalf("expected all requests, got token=%v create=%v delete=%v", gotTokenReq, gotCreate, gotDelete)
	}
}

func TestClientListRecordsSearchParam(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token123","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("/v1/dns/zones/example.com/records", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "search=_acme-challenge") {
			t.Fatalf("expected search param, got %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client, err := NewClientWithAuthURL(server.URL, server.URL+"/token", "id", "secret", "user", "pass", 5*time.Second)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if _, err := client.ListRecords(context.Background(), "example.com", "_acme-challenge"); err != nil {
		t.Fatalf("list records: %v", err)
	}
}
