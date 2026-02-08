# cert-manager-webhook-contabo

This is a cert-manager webhook implementation for managing ACME DNS-01 TXT records in Contabo DNS Zones.

## Webhook config
Example solver config for an Issuer/ClusterIssuer:

```yaml
config:
  credentialsSecretName: "contabo-credentials"
  # optional; defaults to the Challenge resource namespace
  # credentialsSecretNamespace: "cert-manager"
  baseUrl: "https://api.contabo.com" # optional
  authUrl: "https://auth.contabo.com/auth/realms/contabo/protocol/openid-connect/token" # optional
  ttl: 120 # optional
  timeoutSeconds: 15 # optional
```

In the example above, the `contabo-credentials` referenced secret must contain these keys:
- `clientId`
- `clientSecret`
- `username`
- `password`

All 4 of these can be grabbed from the [Contabo control panel](https://my.contabo.com/api/details).
