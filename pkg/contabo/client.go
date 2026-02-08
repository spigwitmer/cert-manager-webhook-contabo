package contabo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	defaultBaseURL = "https://api.contabo.com"
	defaultAuthURL = "https://auth.contabo.com/auth/realms/contabo/protocol/openid-connect/token"
)

// Client manages authentication and requests to the Contabo DNS API.
type Client struct {
	baseURL    string
	authURL    string
	clientID   string
	secret     string
	username   string
	password   string
	httpClient *http.Client

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

func NewClient(baseURL, clientID, secret, username, password string, timeout time.Duration) (*Client, error) {
	return NewClientWithAuthURL(baseURL, defaultAuthURL, clientID, secret, username, password, timeout)
}

func NewClientWithAuthURL(baseURL, authURL, clientID, secret, username, password string, timeout time.Duration) (*Client, error) {
	if clientID == "" || secret == "" || username == "" || password == "" {
		return nil, errors.New("clientID, clientSecret, username, and password are required")
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	if authURL == "" {
		authURL = defaultAuthURL
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	return &Client{
		baseURL:    baseURL,
		authURL:    authURL,
		clientID:   clientID,
		secret:     secret,
		username:   username,
		password:   password,
		httpClient: &http.Client{Timeout: timeout},
	}, nil
}

// CreateRecord creates a DNS record within a zone.
func (c *Client) CreateRecord(ctx context.Context, zone string, req CreateRecordRequest) error {
	return c.doJSON(ctx, http.MethodPost, fmt.Sprintf("/v1/dns/zones/%s/records", url.PathEscape(zone)), req, nil)
}

// ListRecords lists DNS records for a zone.
func (c *Client) ListRecords(ctx context.Context, zone string, search string) ([]DNSRecord, error) {
	endpoint := fmt.Sprintf("/v1/dns/zones/%s/records", url.PathEscape(zone))
	if search != "" {
		endpoint += "?search=" + url.QueryEscape(search)
	}

	var resp listRecordsResponse
	if err := c.doJSON(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

// DeleteRecord deletes a DNS record by ID.
func (c *Client) DeleteRecord(ctx context.Context, zone, recordID string) error {
	return c.doJSON(ctx, http.MethodDelete, fmt.Sprintf("/v1/dns/zones/%s/records/%s", url.PathEscape(zone), url.PathEscape(recordID)), nil, nil)
}

func (c *Client) doJSON(ctx context.Context, method, path string, reqBody any, out any) error {
	if err := c.ensureToken(ctx); err != nil {
		return err
	}

	var body *bytes.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	} else {
		body = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-request-id", uuid.NewString())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		var apiErr apiErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.ErrorMessage != "" {
			return fmt.Errorf("contabo api error: %s", apiErr.ErrorMessage)
		}
		return fmt.Errorf("contabo api error: status %s", resp.Status)
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.accessToken != "" && time.Until(c.expiresAt) > 30*time.Second {
		return nil
	}

	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.secret)
	form.Set("username", c.username)
	form.Set("password", c.password)
	form.Set("grant_type", "password")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.authURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("x-request-id", uuid.NewString())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("token request failed: status %s", resp.Status)
	}

	var token tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return err
	}

	if token.AccessToken == "" {
		return errors.New("token response missing access_token")
	}

	c.accessToken = token.AccessToken
	c.expiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)

	return nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type apiErrorResponse struct {
	ErrorMessage string `json:"message"`
}

type listRecordsResponse struct {
	Data []DNSRecord `json:"data"`
}

// DNSRecord represents a DNS record from the Contabo API.
type DNSRecord struct {
	RecordID int64  `json:"recordId"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Data     string `json:"data"`
	TTL      int    `json:"ttl"`
	Prio     int    `json:"prio"`
}

// CreateRecordRequest represents the request payload for creating a DNS record.
type CreateRecordRequest struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  int    `json:"ttl"`
	Prio int    `json:"prio"`
	Data string `json:"data"`
}
