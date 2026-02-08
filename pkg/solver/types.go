package solver

// Config is the JSON webhook config passed via the Issuer/ClusterIssuer.
type Config struct {
	CredentialsSecretName      string `json:"credentialsSecretName"`
	CredentialsSecretNamespace string `json:"credentialsSecretNamespace,omitempty"`
	BaseURL                    string `json:"baseUrl"`
	AuthURL                    string `json:"authUrl"`
	TTL                        int    `json:"ttl"`
	TimeoutSecs                int    `json:"timeoutSeconds"`
}
