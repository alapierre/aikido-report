package publicapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// maxErrorMessageLen caps the server-provided message embedded in an error.
const maxErrorMessageLen = 400

// APIError describes a non-2xx response. It never contains credentials,
// authorization headers, or unbounded response bodies.
type APIError struct {
	StatusCode int
	Method     string
	Path       string
	// Message is a sanitized, length-limited excerpt of the response body.
	Message string
	// RetryAfter is the server-requested wait, when provided (429/503).
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("aikido api: %s %s returned HTTP %d", e.Method, e.Path, e.StatusCode)
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

// newAPIError builds an APIError from a non-2xx response, reading at most
// maxErrorBodyBytes of the body.
func newAPIError(resp *http.Response, method, path string) *APIError {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	return &APIError{
		StatusCode: resp.StatusCode,
		Method:     method,
		Path:       path,
		Message:    extractErrorMessage(body),
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
	}
}

// extractErrorMessage prefers a structured error/message field from a JSON
// body and falls back to the sanitized raw body. HTML pages from reverse
// proxies collapse to a short placeholder instead of being quoted.
func extractErrorMessage(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return ""
	}
	var payload struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Message          string `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		parts := make([]string, 0, 2)
		for _, p := range []string{payload.Error, payload.Message, payload.ErrorDescription} {
			if p != "" {
				parts = append(parts, p)
			}
		}
		if len(parts) > 0 {
			return sanitize(strings.Join(parts, ": "), maxErrorMessageLen)
		}
	}
	if strings.HasPrefix(trimmed, "<") {
		return "(non-JSON error response)"
	}
	return sanitize(trimmed, maxErrorMessageLen)
}

// sanitize strips control characters and caps the length so server output
// cannot corrupt logs or error messages.
func sanitize(s string, maxLen int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(' ')
		case unicode.IsControl(r):
			// dropped
		default:
			b.WriteRune(r)
		}
		if b.Len() >= maxLen {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// parseRetryAfter understands both delta-seconds and HTTP-date forms.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
