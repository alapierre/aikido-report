package publicapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// tokenExpiryMargin is subtracted from the reported token lifetime so a
// token is refreshed before it actually expires mid-operation.
const tokenExpiryMargin = 60 * time.Second

// defaultTokenLifetime is assumed when the token response carries no
// usable expires_in value.
const defaultTokenLifetime = 3600 * time.Second

// tokenSource caches the OAuth access token in memory only. Nothing is
// ever written to disk.
type tokenSource struct {
	client *Client

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// token returns a valid access token, fetching a new one when the cached
// token is missing or about to expire.
func (t *tokenSource) token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.accessToken != "" && t.client.now().Before(t.expiresAt) {
		return t.accessToken, nil
	}
	tok, expiresIn, err := t.fetch(ctx)
	if err != nil {
		return "", err
	}
	t.accessToken = tok
	t.expiresAt = t.client.now().Add(expiresIn - tokenExpiryMargin)
	return tok, nil
}

// invalidate drops the cached token so the next call fetches a fresh one.
func (t *tokenSource) invalidate() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.accessToken = ""
}

// fetch performs the OAuth client-credentials exchange:
// POST /api/oauth/token with HTTP Basic authentication.
func (t *tokenSource) fetch(ctx context.Context) (token string, lifetime time.Duration, err error) {
	c := t.client
	u := c.baseURL.String() + "/api/oauth/token"
	payload := bytes.NewBufferString(`{"grant_type":"client_credentials"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, payload)
	if err != nil {
		return "", 0, fmt.Errorf("publicapi: building token request: %w", err)
	}
	req.SetBasicAuth(c.clientID, c.secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("publicapi: requesting OAuth token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("publicapi: OAuth token request failed: %w", newAPIError(resp, http.MethodPost, "/api/oauth/token"))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	if err != nil {
		return "", 0, fmt.Errorf("publicapi: reading token response: %w", err)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", 0, fmt.Errorf("publicapi: decoding token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", 0, fmt.Errorf("publicapi: token response contains no access token")
	}
	lifetime = defaultTokenLifetime
	if tr.ExpiresIn > 0 {
		lifetime = time.Duration(tr.ExpiresIn) * time.Second
	}
	return tr.AccessToken, lifetime, nil
}
