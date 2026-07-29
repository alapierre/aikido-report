package publicapi

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenIsCachedAcrossRequests(t *testing.T) {
	mux := http.NewServeMux()
	tokenCalls := serveToken(t, mux)
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		requireBearer(t, r)
		_, _ = w.Write([]byte(`[]`))
	})
	c := newTestClient(t, mux)
	for i := 0; i < 3; i++ {
		if _, err := c.ListContainers(t.Context(), "x"); err != nil {
			t.Fatalf("ListContainers #%d: %v", i, err)
		}
	}
	if tokenCalls.Load() != 1 {
		t.Errorf("token endpoint called %d times, want 1 (cached)", tokenCalls.Load())
	}
}

func TestTokenRefreshedAfterExpiry(t *testing.T) {
	mux := http.NewServeMux()
	var tokenCalls atomic.Int32
	mux.HandleFunc("POST /api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		n := tokenCalls.Add(1)
		_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":300,"token_type":"bearer"}`, n)
	})
	var seenTokens []string
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		seenTokens = append(seenTokens, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`[]`))
	})
	c := newTestClient(t, mux)

	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }

	if _, err := c.ListContainers(t.Context(), "x"); err != nil {
		t.Fatal(err)
	}
	// Move time past expires_in (300s) minus the safety margin.
	now = now.Add(4 * time.Minute)
	if _, err := c.ListContainers(t.Context(), "x"); err != nil {
		t.Fatal(err)
	}
	if tokenCalls.Load() != 2 {
		t.Errorf("token endpoint called %d times, want 2", tokenCalls.Load())
	}
	if len(seenTokens) != 2 || seenTokens[0] != "Bearer tok-1" || seenTokens[1] != "Bearer tok-2" {
		t.Errorf("seen tokens: %v", seenTokens)
	}
}

func TestTokenRequestUsesBasicAuthAndGrantType(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok {
			t.Error("missing Basic auth")
		}
		if id != testClientID || secret != testClientSecret {
			t.Errorf("credentials = %q:%q", id, secret)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"grant_type":"client_credentials"`) {
			t.Errorf("body = %s", body)
		}
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"expires_in":3600}`, testToken)
	})
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		requireBearer(t, r)
		_, _ = w.Write([]byte(`[]`))
	})
	c := newTestClient(t, mux)
	if _, err := c.ListContainers(t.Context(), "x"); err != nil {
		t.Fatal(err)
	}
}

func TestTokenResponseWithoutAccessToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token_type":"bearer","expires_in":3600}`))
	})
	c := newTestClient(t, mux)
	_, err := c.ListContainers(t.Context(), "x")
	if err == nil || !strings.Contains(err.Error(), "no access token") {
		t.Fatalf("expected missing-token error, got %v", err)
	}
}

func TestTokenResponseMalformedJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{broken`))
	})
	c := newTestClient(t, mux)
	if _, err := c.ListContainers(t.Context(), "x"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestTokenBadCredentials(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"Client authentication failed"}`))
	})
	c := newTestClient(t, mux)
	_, err := c.ListContainers(t.Context(), "x")
	if err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("expected invalid_client in error, got %v", err)
	}
}

func TestTokenWithoutExpiresInAssumesDefaultLifetime(t *testing.T) {
	mux := http.NewServeMux()
	var tokenCalls atomic.Int32
	mux.HandleFunc("POST /api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		_, _ = fmt.Fprintf(w, `{"access_token":%q}`, testToken)
	})
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	c := newTestClient(t, mux)
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }

	if _, err := c.ListContainers(t.Context(), "x"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Minute)
	if _, err := c.ListContainers(t.Context(), "x"); err != nil {
		t.Fatal(err)
	}
	if tokenCalls.Load() != 1 {
		t.Errorf("token fetched %d times within default lifetime, want 1", tokenCalls.Load())
	}
	now = now.Add(31 * time.Minute)
	if _, err := c.ListContainers(t.Context(), "x"); err != nil {
		t.Fatal(err)
	}
	if tokenCalls.Load() != 2 {
		t.Errorf("token fetched %d times after default lifetime, want 2", tokenCalls.Load())
	}
}
