package solver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	v1alpha1 "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

func TestSolverPresentAndCleanUp(t *testing.T) {
	var (
		createdRecordName string
		createdRecordData string
		deletedRecordID   string
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token123","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("/v1/dns/zones/example.com/records", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var payload struct {
				Name string `json:"name"`
				Data string `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			createdRecordName = payload.Name
			createdRecordData = payload.Data
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"recordId":99,"name":"_acme-challenge","type":"TXT","data":"key","ttl":120,"prio":0},{"recordId":100,"name":"_acme-challenge","type":"TXT","data":"other","ttl":120,"prio":0}]}`))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/v1/dns/zones/example.com/records/99", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		deletedRecordID = "99"
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/dns/zones/example.com/records/100", func(w http.ResponseWriter, r *http.Request) {
		// should not be called
		deletedRecordID = "100"
		w.WriteHeader(http.StatusNoContent)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	cfg := Config{
		CredentialsSecretName: "contabo-credentials",
		BaseURL:               server.URL,
		AuthURL:               server.URL + "/token",
	}
	cfgJSON, _ := json.Marshal(cfg)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "contabo-credentials",
			Namespace: "tenant-ns",
		},
		Data: map[string][]byte{
			secretKeyClientID:     []byte("id"),
			secretKeyClientSecret: []byte("secret"),
			secretKeyUsername:     []byte("user"),
			secretKeyPassword:     []byte("pass"),
		},
	}

	challenge := &v1alpha1.ChallengeRequest{
		ResourceNamespace: "tenant-ns",
		ResolvedZone:      "example.com.",
		ResolvedFQDN:      "_acme-challenge.example.com.",
		Key:               "key",
		Config:            &apiextensionsv1.JSON{Raw: cfgJSON},
	}

	s := NewSolver()
	s.client = kubefake.NewSimpleClientset(secret)
	if err := s.Present(challenge); err != nil {
		t.Fatalf("present: %v", err)
	}
	if createdRecordName != "_acme-challenge" || createdRecordData != "key" {
		t.Fatalf("unexpected create record: name=%s data=%s", createdRecordName, createdRecordData)
	}

	if err := s.CleanUp(challenge); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if deletedRecordID != "99" {
		t.Fatalf("expected delete of 99, got %s", deletedRecordID)
	}
}

func TestRelativeRecordNameRoot(t *testing.T) {
	if got := relativeRecordName("example.com.", "example.com."); got != "@" {
		t.Fatalf("expected @, got %s", got)
	}
	if got := relativeRecordName("example.com", "example.com."); got != "@" {
		t.Fatalf("expected @, got %s", got)
	}
}

func TestNormalizeZone(t *testing.T) {
	if got := normalizeZone("example.com."); got != "example.com" {
		t.Fatalf("expected example.com, got %s", got)
	}
}

func TestSolverLoadConfigErrors(t *testing.T) {
	if _, err := loadConfig(nil); err == nil {
		t.Fatalf("expected error for nil config")
	}

	cfgJSON, _ := json.Marshal(Config{})
	if _, err := loadConfig(&apiextensionsv1.JSON{Raw: cfgJSON}); err == nil {
		t.Fatalf("expected error for missing secret name")
	}

	if _, err := loadConfig(&apiextensionsv1.JSON{Raw: []byte("not-json")}); err == nil {
		t.Fatalf("expected error for bad json")
	}
}

func TestSolverTimeoutDefault(t *testing.T) {
	cfg := Config{}
	if cfg.timeout() == 0 {
		t.Fatalf("expected non-zero timeout")
	}
	if cfg.ttl() == 0 {
		t.Fatalf("expected non-zero ttl")
	}
	_ = context.Background()
}

func TestCredentialsFromSecretErrors(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "ns"},
		Data: map[string][]byte{
			secretKeyClientID: []byte("id"),
		},
	}
	if _, err := credentialsFromSecret(secret); err == nil {
		t.Fatalf("expected error for incomplete secret")
	}
}
