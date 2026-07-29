// Package publicapi is a minimal client for the Aikido Security public
// REST API (https://apidocs.aikido.dev). It implements only the operations
// this tool needs: OAuth client-credentials authentication, listing
// container repositories and code repositories, triggering scans, and
// exporting issues. It is deliberately not a general-purpose SDK.
//
// Transport concerns (retry, pagination, error classification, response
// size limits) live here; domain logic does not.
package publicapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// defaultMaxResponseBytes bounds any successful response body read into
	// memory.
	defaultMaxResponseBytes = 64 << 20
	// maxErrorBodyBytes bounds how much of an error response is read.
	maxErrorBodyBytes = 4 << 10

	// maxAttempts is the total number of tries for a retryable request.
	maxAttempts = 4
	// retryBaseDelay is the first backoff delay; it doubles per attempt.
	retryBaseDelay = 1 * time.Second
	// retryMaxDelay caps a single backoff or Retry-After wait.
	retryMaxDelay = 60 * time.Second
)

// Config holds everything needed to construct a Client.
type Config struct {
	// BaseURL is the Aikido application base URL, e.g. https://app.aikido.dev.
	BaseURL string
	// ClientID and ClientSecret are OAuth client credentials created in the
	// Aikido workspace settings.
	ClientID     string
	ClientSecret string
	// HTTPTimeout bounds a single HTTP request (not a whole operation).
	HTTPTimeout time.Duration
	// UserAgent is sent with every request.
	UserAgent string
	// Logger receives debug/warn transport logs; defaults to slog.Default().
	Logger *slog.Logger
}

// Client talks to the Aikido public API. It is safe for concurrent use.
type Client struct {
	baseURL    *url.URL
	clientID   string
	secret     string
	userAgent  string
	httpClient *http.Client
	logger     *slog.Logger

	tokens *tokenSource

	// maxResponseBytes bounds successful response bodies; overridable in
	// tests.
	maxResponseBytes int64

	// now and sleep are injection points for tests; they default to
	// time.Now and a context-aware timer wait.
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

// errResponseTooLarge marks an oversized response; it is permanent, not
// retryable.
var errResponseTooLarge = errors.New("response exceeds size limit")

// New validates the configuration and returns a ready Client.
func New(cfg Config) (*Client, error) {
	base, err := validateBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("publicapi: client ID and client secret are required")
	}
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	c := &Client{
		baseURL:   base,
		clientID:  cfg.ClientID,
		secret:    cfg.ClientSecret,
		userAgent: cfg.UserAgent,
		httpClient: &http.Client{
			Timeout: timeout,
			// The Authorization header must never travel to another host.
			// Cross-host redirects are refused outright instead of silently
			// dropping credentials.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("publicapi: too many redirects")
				}
				if req.URL.Host != via[0].URL.Host {
					return fmt.Errorf("publicapi: refusing redirect to different host %q", req.URL.Host)
				}
				return nil
			},
		},
		logger:           logger,
		maxResponseBytes: defaultMaxResponseBytes,
		now:              time.Now,
		sleep:            sleepContext,
	}
	c.tokens = &tokenSource{client: c}
	return c, nil
}

func validateBaseURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("publicapi: base URL is required")
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return nil, fmt.Errorf("publicapi: invalid base URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("publicapi: base URL must use http(s), got %q", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("publicapi: base URL has no host: %q", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("publicapi: base URL must not contain query or fragment: %q", raw)
	}
	return u, nil
}

// BaseURL returns the configured base URL without a trailing slash,
// suitable for building dashboard links.
func (c *Client) BaseURL() string {
	return c.baseURL.String()
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// get performs an authenticated GET with retries for transient failures
// (429/502/503/504 and network errors) and returns the response body.
func (c *Client) get(ctx context.Context, path string, query url.Values) ([]byte, error) {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		body, err := c.doOnce(ctx, http.MethodGet, path, query, nil)
		if err == nil {
			return body, nil
		}
		lastErr = err
		// When the caller's context is done the operation budget is spent;
		// a per-request HTTP timeout with a live context stays retryable.
		if ctx.Err() != nil {
			return nil, err
		}
		wait, retryable := retryDelay(err, attempt)
		if !retryable || attempt == maxAttempts {
			return nil, err
		}
		c.logger.Debug("retrying request",
			"method", http.MethodGet, "path", path, "attempt", attempt, "wait", wait, "error", errMessage(err))
		if serr := c.sleep(ctx, wait); serr != nil {
			return nil, serr
		}
	}
	return nil, lastErr
}

// post performs an authenticated POST. Scan triggers are not idempotent,
// so POST requests are never retried automatically.
func (c *Client) post(ctx context.Context, path string, query url.Values) ([]byte, error) {
	return c.doOnce(ctx, http.MethodPost, path, query, nil)
}

// doOnce performs a single authenticated request. On 401 the cached token
// is dropped and the request is repeated once with a fresh token, which
// covers tokens expiring during long polling runs.
func (c *Client) doOnce(ctx context.Context, method, path string, query url.Values, body io.Reader) ([]byte, error) {
	token, err := c.tokens.token(ctx)
	if err != nil {
		return nil, err
	}
	respBody, err := c.roundTrip(ctx, method, path, query, token)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized {
		c.tokens.invalidate()
		token, terr := c.tokens.token(ctx)
		if terr != nil {
			return nil, terr
		}
		return c.roundTrip(ctx, method, path, query, token)
	}
	return respBody, err
}

func (c *Client) roundTrip(ctx context.Context, method, path string, query url.Values, token string) ([]byte, error) {
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + path
	if query != nil {
		u.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("publicapi: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	start := c.now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("publicapi: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	c.logger.Debug("aikido api request",
		"method", method, "path", path, "status", resp.StatusCode, "duration", c.now().Sub(start))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, newAPIError(resp, method, path)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("publicapi: reading response of %s %s: %w", method, path, err)
	}
	if int64(len(data)) > c.maxResponseBytes {
		return nil, fmt.Errorf("publicapi: response of %s %s over %d bytes: %w", method, path, c.maxResponseBytes, errResponseTooLarge)
	}
	return data, nil
}

// retryDelay decides whether an error is worth retrying and how long to
// wait before the next attempt. Retry-After from the server wins over the
// exponential backoff.
func retryDelay(err error, attempt int) (time.Duration, bool) {
	backoff := min(retryBaseDelay<<(attempt-1), retryMaxDelay)
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			if apiErr.RetryAfter > 0 {
				return min(apiErr.RetryAfter, retryMaxDelay), true
			}
			return backoff, true
		default:
			return 0, false
		}
	}
	if errors.Is(err, errResponseTooLarge) {
		return 0, false
	}
	// Remaining errors from httpClient.Do are network-level (connection
	// refused/reset, per-request timeout) and safe to retry for GET; caller
	// context expiry is handled by the retry loop itself.
	return backoff, true
}

// errMessage returns an error string safe for logs (control characters
// stripped, length capped).
func errMessage(err error) string {
	return sanitize(err.Error(), 200)
}
