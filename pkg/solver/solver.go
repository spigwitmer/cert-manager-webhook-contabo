package solver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cert-manager-webhook-contabo/pkg/contabo"

	v1alpha1 "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const (
	defaultTTL            = 120
	defaultTimeout        = 15 * time.Second
	secretKeyClientID     = "clientId"
	secretKeyClientSecret = "clientSecret"
	secretKeyUsername     = "username"
	secretKeyPassword     = "password"
)

// Solver implements the cert-manager webhook Solver interface.
type Solver struct {
	client kubernetes.Interface
}

type credentials struct {
	clientID     string
	clientSecret string
	username     string
	password     string
}

func NewSolver() *Solver {
	return &Solver{}
}

func (s *Solver) Name() string {
	return "contabo"
}

func (s *Solver) Initialize(restConfig *rest.Config, _ <-chan struct{}) error {
	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize kubernetes client: %w", err)
	}
	s.client = client
	return nil
}

func (s *Solver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout())
	defer cancel()

	creds, err := s.loadCredentials(ctx, ch, cfg)
	if err != nil {
		return err
	}

	client, err := s.newClient(cfg, creds)
	if err != nil {
		return err
	}

	zone := normalizeZone(ch.ResolvedZone)
	recordName := relativeRecordName(ch.ResolvedFQDN, ch.ResolvedZone)

	req := contabo.CreateRecordRequest{
		Name: recordName,
		Type: "TXT",
		TTL:  cfg.ttl(),
		Prio: 0,
		Data: ch.Key,
	}

	klog.Infof("creating TXT record %s in zone %s", recordName, zone)
	return client.CreateRecord(ctx, zone, req)
}

func (s *Solver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout())
	defer cancel()

	creds, err := s.loadCredentials(ctx, ch, cfg)
	if err != nil {
		return err
	}

	client, err := s.newClient(cfg, creds)
	if err != nil {
		return err
	}

	zone := normalizeZone(ch.ResolvedZone)
	recordName := relativeRecordName(ch.ResolvedFQDN, ch.ResolvedZone)

	records, err := client.ListRecords(ctx, zone, recordName)
	if err != nil {
		return err
	}

	for _, record := range records {
		if !isACMERecord(record, recordName, ch.Key) {
			continue
		}
		klog.Infof("deleting TXT record %s (%d) in zone %s", record.Name, record.RecordID, zone)
		if err := client.DeleteRecord(ctx, zone, fmt.Sprint(record.RecordID)); err != nil {
			return err
		}
	}

	return nil
}

func (s *Solver) newClient(cfg *Config, creds *credentials) (*contabo.Client, error) {
	if cfg.AuthURL != "" {
		return contabo.NewClientWithAuthURL(cfg.BaseURL, cfg.AuthURL, creds.clientID, creds.clientSecret, creds.username, creds.password, cfg.timeout())
	}
	return contabo.NewClient(cfg.BaseURL, creds.clientID, creds.clientSecret, creds.username, creds.password, cfg.timeout())
}

func (s *Solver) loadCredentials(ctx context.Context, ch *v1alpha1.ChallengeRequest, cfg *Config) (*credentials, error) {
	if s.client == nil {
		return nil, fmt.Errorf("kubernetes client is not initialized")
	}

	namespace := cfg.CredentialsSecretNamespace
	if namespace == "" {
		namespace = ch.ResourceNamespace
	}
	if namespace == "" {
		return nil, fmt.Errorf("credentialsSecretNamespace is required when challenge resource namespace is empty")
	}

	secret, err := s.client.CoreV1().Secrets(namespace).Get(ctx, cfg.CredentialsSecretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials secret %s/%s: %w", namespace, cfg.CredentialsSecretName, err)
	}

	return credentialsFromSecret(secret)
}

func credentialsFromSecret(secret *corev1.Secret) (*credentials, error) {
	clientID := strings.TrimSpace(string(secret.Data[secretKeyClientID]))
	clientSecret := strings.TrimSpace(string(secret.Data[secretKeyClientSecret]))
	username := strings.TrimSpace(string(secret.Data[secretKeyUsername]))
	password := strings.TrimSpace(string(secret.Data[secretKeyPassword]))

	if clientID == "" || clientSecret == "" || username == "" || password == "" {
		return nil, fmt.Errorf(
			"secret %s/%s must contain non-empty %q, %q, %q, and %q keys",
			secret.GetNamespace(),
			secret.GetName(),
			secretKeyClientID,
			secretKeyClientSecret,
			secretKeyUsername,
			secretKeyPassword,
		)
	}

	return &credentials{
		clientID:     clientID,
		clientSecret: clientSecret,
		username:     username,
		password:     password,
	}, nil
}

func loadConfig(rawJSON *apiextensionsv1.JSON) (*Config, error) {
	if rawJSON == nil {
		return nil, fmt.Errorf("config is required")
	}

	var cfg Config
	if err := json.Unmarshal(rawJSON.Raw, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if cfg.CredentialsSecretName == "" {
		return nil, fmt.Errorf("credentialsSecretName is required")
	}

	return &cfg, nil
}

func normalizeZone(zone string) string {
	return strings.TrimSuffix(zone, ".")
}

func relativeRecordName(fqdn, zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	fqdn = strings.TrimSuffix(fqdn, ".")

	trimmed := strings.TrimSuffix(fqdn, "."+zone)
	trimmed = strings.TrimSuffix(trimmed, ".")
	if trimmed == "" {
		return "@"
	}
	return trimmed
}

func isACMERecord(record contabo.DNSRecord, name, value string) bool {
	if !strings.EqualFold(record.Type, "TXT") {
		return false
	}
	if record.Name != name {
		return false
	}
	if value != "" && record.Data != value {
		return false
	}
	return true
}

func (c *Config) ttl() int {
	if c.TTL <= 0 {
		return defaultTTL
	}
	return c.TTL
}

func (c *Config) timeout() time.Duration {
	if c.TimeoutSecs <= 0 {
		return defaultTimeout
	}
	return time.Duration(c.TimeoutSecs) * time.Second
}
