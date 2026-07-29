package publicapi

import (
	"strings"
	"testing"
	"time"
)

func TestSanitize(t *testing.T) {
	tests := []struct {
		in     string
		maxLen int
		want   string
	}{
		{"plain", 100, "plain"},
		{"tab\tand\nnewline", 100, "tab and newline"},
		{"nul\x00byte\x1b[31m", 100, "nulbyte[31m"},
		{strings.Repeat("x", 50), 10, "xxxxxxxxxx"},
		{"  padded  ", 100, "padded"},
	}
	for _, tt := range tests {
		if got := sanitize(tt.in, tt.maxLen); got != tt.want {
			t.Errorf("sanitize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExtractErrorMessage(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"error field", `{"error":"invalid_client"}`, "invalid_client"},
		{"message field", `{"message":"rate limited"}`, "rate limited"},
		{"error and description", `{"error":"invalid_request","error_description":"missing grant"}`, "invalid_request: missing grant"},
		{"plain text", "something broke", "something broke"},
		{"html", "<html><body>502</body></html>", "(non-JSON error response)"},
		{"empty", "", ""},
		{"json without known keys", `{"status":"failed"}`, `{"status":"failed"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractErrorMessage([]byte(tt.body)); got != tt.want {
				t.Errorf("extractErrorMessage(%q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("15"); got != 15*time.Second {
		t.Errorf("seconds form: got %v", got)
	}
	if got := parseRetryAfter(""); got != 0 {
		t.Errorf("empty: got %v", got)
	}
	if got := parseRetryAfter("garbage"); got != 0 {
		t.Errorf("garbage: got %v", got)
	}
	future := time.Now().Add(30 * time.Second).UTC().Format(time.RFC1123)
	future = strings.Replace(future, "UTC", "GMT", 1)
	if got := parseRetryAfter(future); got <= 0 || got > 31*time.Second {
		t.Errorf("http-date form: got %v", got)
	}
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC1123)
	past = strings.Replace(past, "UTC", "GMT", 1)
	if got := parseRetryAfter(past); got != 0 {
		t.Errorf("past http-date: got %v", got)
	}
}

func TestAPIErrorString(t *testing.T) {
	err := &APIError{StatusCode: 403, Method: "GET", Path: "/api/public/v1/containers", Message: "missing scope"}
	want := "aikido api: GET /api/public/v1/containers returned HTTP 403: missing scope"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}
