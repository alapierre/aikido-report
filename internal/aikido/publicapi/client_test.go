package publicapi

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testClientID     = "test-client-id"
	testClientSecret = "sup3r-secret-value"
	testToken        = "test-access-token"
)

// serveToken installs a default OAuth token endpoint that validates Basic
// credentials and the grant type.
func serveToken(t *testing.T, mux *http.ServeMux) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	mux.HandleFunc("POST /api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		id, secret, ok := r.BasicAuth()
		if !ok || id != testClientID || secret != testClientSecret {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "client_credentials") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unsupported_grant_type"}`))
			return
		}
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"expires_in":3600,"token_type":"bearer"}`, testToken)
	})
	return &calls
}

// newTestClient builds a Client against the given mux with sleeping
// disabled (waits complete instantly but honor cancellation).
func newTestClient(t *testing.T, mux *http.ServeMux) *Client {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := New(Config{
		BaseURL:      srv.URL,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		HTTPTimeout:  5 * time.Second,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	return c
}

func requireBearer(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
		t.Errorf("unexpected Authorization header: %q", got)
	}
}

func TestBaseURLValidation(t *testing.T) {
	valid := Config{ClientID: "a", ClientSecret: "b"}
	tests := []struct {
		name    string
		baseURL string
		wantErr bool
	}{
		{"https ok", "https://app.aikido.dev", false},
		{"trailing slash ok", "https://app.aikido.dev/", false},
		{"empty", "", true},
		{"no scheme", "app.aikido.dev", true},
		{"ftp", "ftp://app.aikido.dev", true},
		{"with query", "https://app.aikido.dev?x=1", true},
		{"with fragment", "https://app.aikido.dev#x", true},
	}
	for _, tt := range tests {
		cfg := valid
		cfg.BaseURL = tt.baseURL
		_, err := New(cfg)
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: New(%q) error = %v, wantErr %v", tt.name, tt.baseURL, err, tt.wantErr)
		}
	}
}

func TestMissingCredentials(t *testing.T) {
	if _, err := New(Config{BaseURL: "https://app.aikido.dev"}); err == nil {
		t.Fatal("expected error for missing credentials")
	}
}

func TestPermanentStatusesAreNotRetried(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			mux := http.NewServeMux()
			serveToken(t, mux)
			var calls atomic.Int32
			mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"error":"nope"}`))
			})
			c := newTestClient(t, mux)
			_, err := c.ListContainers(t.Context(), "x")
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected APIError, got %v", err)
			}
			if apiErr.StatusCode != status {
				t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, status)
			}
			if got := calls.Load(); got != 1 {
				t.Errorf("endpoint called %d times, want 1 (no retry)", got)
			}
		})
	}
}

func TestRetryOn429RespectsRetryAfter(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	var calls atomic.Int32
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message":"rate limited"}`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	})
	c := newTestClient(t, mux)
	var waits []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	if _, err := c.ListContainers(t.Context(), "x"); err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("endpoint called %d times, want 2", calls.Load())
	}
	if len(waits) != 1 || waits[0] != 7*time.Second {
		t.Errorf("waits = %v, want [7s] from Retry-After", waits)
	}
}

func TestRetryOnServerErrorsThenSuccess(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			mux := http.NewServeMux()
			serveToken(t, mux)
			var calls atomic.Int32
			mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) <= 2 {
					w.WriteHeader(status)
					return
				}
				_, _ = w.Write([]byte(`[]`))
			})
			c := newTestClient(t, mux)
			if _, err := c.ListContainers(t.Context(), "x"); err != nil {
				t.Fatalf("ListContainers: %v", err)
			}
			if calls.Load() != 3 {
				t.Errorf("endpoint called %d times, want 3", calls.Load())
			}
		})
	}
}

func TestRetryExhausted(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	var calls atomic.Int32
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := newTestClient(t, mux)
	_, err := c.ListContainers(t.Context(), "x")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 APIError after exhausted retries, got %v", err)
	}
	if calls.Load() != maxAttempts {
		t.Errorf("endpoint called %d times, want %d", calls.Load(), maxAttempts)
	}
}

func TestRetryBackoffGrowsExponentially(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	c := newTestClient(t, mux)
	var waits []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	if _, err := c.ListContainers(t.Context(), "x"); err == nil {
		t.Fatal("expected error")
	}
	want := []time.Duration{retryBaseDelay, 2 * retryBaseDelay, 4 * retryBaseDelay}
	if len(waits) != len(want) {
		t.Fatalf("waits = %v, want %v", waits, want)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Errorf("wait %d = %v, want %v", i, waits[i], want[i])
		}
	}
}

func TestPostIsNeverRetried(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	var calls atomic.Int32
	mux.HandleFunc("POST /api/public/v1/containers/101/scan", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := newTestClient(t, mux)
	if err := c.TriggerContainerScan(t.Context(), 101); err == nil {
		t.Fatal("expected error")
	}
	if calls.Load() != 1 {
		t.Errorf("scan trigger called %d times, want 1", calls.Load())
	}
}

func TestTokenRefreshedOn401(t *testing.T) {
	mux := http.NewServeMux()
	tokenCalls := serveToken(t, mux)
	var calls atomic.Int32
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		requireBearer(t, r)
		_, _ = w.Write([]byte(`[]`))
	})
	c := newTestClient(t, mux)
	if _, err := c.ListContainers(t.Context(), "x"); err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if tokenCalls.Load() != 2 {
		t.Errorf("token endpoint called %d times, want 2 (initial + refresh)", tokenCalls.Load())
	}
	if calls.Load() != 2 {
		t.Errorf("endpoint called %d times, want 2", calls.Load())
	}
}

func TestCrossHostRedirectRefused(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example.com/steal", http.StatusFound)
	})
	c := newTestClient(t, mux)
	_, err := c.ListContainers(t.Context(), "x")
	if err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Fatalf("expected redirect refusal, got %v", err)
	}
}

func TestContextCancellationAbortsRequest(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	started := make(chan struct{})
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	})
	c := newTestClient(t, mux)
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-started
		cancel()
	}()
	_, err := c.ListContainers(ctx, "x")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestHTTPTimeoutIsRetried(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	var calls atomic.Int32
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			// Stall past the per-request timeout; the overall context stays
			// alive so the client should retry.
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			return
		}
		_, _ = w.Write([]byte(`[]`))
	})
	c := newTestClient(t, mux)
	c.httpClient.Timeout = 100 * time.Millisecond
	if _, err := c.ListContainers(t.Context(), "x"); err != nil {
		t.Fatalf("ListContainers after timeouts: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("endpoint called %d times, want 3", calls.Load())
	}
}

func TestOversizedResponseIsPermanentError(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	var calls atomic.Int32
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`[{"id":1},{"id":2}]`))
	})
	c := newTestClient(t, mux)
	c.maxResponseBytes = 8
	_, err := c.ListContainers(t.Context(), "x")
	if !errors.Is(err, errResponseTooLarge) {
		t.Fatalf("expected errResponseTooLarge, got %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("oversized response fetched %d times, want 1 (no retry)", calls.Load())
	}
}

func TestErrorBodyIsSanitizedAndTruncated(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	nasty := "bad\x00\x01thing " + strings.Repeat("A", 5000)
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(nasty))
	})
	c := newTestClient(t, mux)
	_, err := c.ListContainers(t.Context(), "x")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %v", err)
	}
	if len(apiErr.Message) > maxErrorMessageLen {
		t.Errorf("message length %d exceeds %d", len(apiErr.Message), maxErrorMessageLen)
	}
	if strings.ContainsAny(apiErr.Message, "\x00\x01") {
		t.Error("message contains control characters")
	}
}

func TestHTMLErrorBodyIsNotQuoted(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html><body>Bad gateway from proxy</body></html>"))
	})
	c := newTestClient(t, mux)
	_, err := c.ListContainers(t.Context(), "x")
	if err == nil || strings.Contains(err.Error(), "<html>") {
		t.Fatalf("HTML body must not be quoted, got %v", err)
	}
}

// TestSecretsNeverAppearInErrors drives the main failure paths and asserts
// no error message leaks the client secret in plain or base64 form.
func TestSecretsNeverAppearInErrors(t *testing.T) {
	basic := base64.StdEncoding.EncodeToString([]byte(testClientID + ":" + testClientSecret))
	assertClean := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("expected error")
		}
		msg := err.Error()
		if strings.Contains(msg, testClientSecret) || strings.Contains(msg, basic) {
			t.Errorf("error leaks credentials: %q", msg)
		}
	}

	t.Run("oauth failure", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		})
		c := newTestClient(t, mux)
		_, err := c.ListContainers(t.Context(), "x")
		assertClean(t, err)
	})

	t.Run("api failure", func(t *testing.T) {
		mux := http.NewServeMux()
		serveToken(t, mux)
		mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"missing scope"}`))
		})
		c := newTestClient(t, mux)
		_, err := c.ListContainers(t.Context(), "x")
		assertClean(t, err)
	})

	t.Run("network failure", func(t *testing.T) {
		c, err := New(Config{
			BaseURL:      "http://127.0.0.1:1",
			ClientID:     testClientID,
			ClientSecret: testClientSecret,
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		c.sleep = func(ctx context.Context, d time.Duration) error { return nil }
		_, lerr := c.ListContainers(t.Context(), "x")
		assertClean(t, lerr)
	})
}

func TestQueryParametersAreEncoded(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	var gotQuery string
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		if got := r.URL.Query().Get("filter_name"); got != "my app/weird&name" {
			t.Errorf("filter_name = %q", got)
		}
		_, _ = w.Write([]byte(`[]`))
	})
	c := newTestClient(t, mux)
	if _, err := c.ListContainers(t.Context(), "my app/weird&name"); err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if !strings.Contains(gotQuery, "filter_name=my+app%2Fweird%26name") {
		t.Errorf("query not encoded as expected: %q", gotQuery)
	}
}

func TestUserAgentAndAcceptHeaders(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "aikido-report-test/1.0" {
			t.Errorf("User-Agent = %q", got)
		}
		_, _ = w.Write([]byte(`[]`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := New(Config{
		BaseURL:      srv.URL,
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		UserAgent:    "aikido-report-test/1.0",
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.ListContainers(t.Context(), "x"); err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
}

func TestListContainersDecodesFixture(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		requireBearer(t, r)
		http.ServeFile(w, r, "../../../testdata/api/containers.json")
	})
	c := newTestClient(t, mux)
	containers, err := c.ListContainers(t.Context(), "application")
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(containers) != 2 {
		t.Fatalf("got %d containers, want 2", len(containers))
	}
	first := containers[0]
	if first.ID != 101 || first.Name != "application" || first.RegistryName != "registry.example.com" ||
		first.LastScannedTag != "1.2.3" || first.IsEmpty || !first.IsActive {
		t.Errorf("unexpected first container: %+v", first)
	}
	second := containers[1]
	if second.LastScannedAt != -1 || !second.IsEmpty {
		t.Errorf("unexpected second container: %+v", second)
	}
}

func TestGetContainer(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	mux.HandleFunc("GET /api/public/v1/containers/101", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":101,"name":"application","registry_name":"registry.example.com","last_scanned_tag":"2.0.0","last_scanned_at":1753700001,"is_active":true,"is_empty":false}`))
	})
	c := newTestClient(t, mux)
	container, err := c.GetContainer(t.Context(), 101)
	if err != nil {
		t.Fatalf("GetContainer: %v", err)
	}
	if container.LastScannedTag != "2.0.0" {
		t.Errorf("LastScannedTag = %q", container.LastScannedTag)
	}
}

func TestMalformedJSONResponse(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id": broken`))
	})
	c := newTestClient(t, mux)
	if _, err := c.ListContainers(t.Context(), "x"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestPaginationFollowsAllPages(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	var pagesSeen []string
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		pagesSeen = append(pagesSeen, q.Get("page"))
		if q.Get("per_page") != "100" {
			t.Errorf("per_page = %q, want 100", q.Get("per_page"))
		}
		if q.Get("filter_status") != "all" {
			t.Errorf("filter_status = %q, want all", q.Get("filter_status"))
		}
		page := q.Get("page")
		count := containersPerPage
		if page == "1" {
			count = 37
		}
		var items []string
		for i := 0; i < count; i++ {
			items = append(items, fmt.Sprintf(`{"id":%d,"name":"app"}`, len(pagesSeen)*1000+i))
		}
		_, _ = fmt.Fprintf(w, "[%s]", strings.Join(items, ","))
	})
	c := newTestClient(t, mux)
	containers, err := c.ListContainers(t.Context(), "app")
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(containers) != containersPerPage+37 {
		t.Errorf("got %d containers, want %d", len(containers), containersPerPage+37)
	}
	if len(pagesSeen) != 2 || pagesSeen[0] != "0" || pagesSeen[1] != "1" {
		t.Errorf("pages requested: %v, want [0 1]", pagesSeen)
	}
}

func TestPaginationRunawayGuard(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	var calls atomic.Int32
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		items := make([]string, containersPerPage)
		for i := range items {
			items[i] = `{"id":1,"name":"app"}`
		}
		_, _ = fmt.Fprintf(w, "[%s]", strings.Join(items, ","))
	})
	c := newTestClient(t, mux)
	_, err := c.ListContainers(t.Context(), "app")
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("expected pagination guard error, got %v", err)
	}
	if calls.Load() != maxListPages {
		t.Errorf("endpoint called %d times, want %d", calls.Load(), maxListPages)
	}
}

func TestEmptyPageStopsPagination(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	mux.HandleFunc("GET /api/public/v1/containers", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	c := newTestClient(t, mux)
	containers, err := c.ListContainers(t.Context(), "app")
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(containers) != 0 {
		t.Errorf("got %d containers, want 0", len(containers))
	}
}

func TestTriggerContainerScanSuccess(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	var called atomic.Int32
	mux.HandleFunc("POST /api/public/v1/containers/101/scan", func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		requireBearer(t, r)
		_, _ = w.Write([]byte(`{"success":1}`))
	})
	c := newTestClient(t, mux)
	if err := c.TriggerContainerScan(t.Context(), 101); err != nil {
		t.Fatalf("TriggerContainerScan: %v", err)
	}
	if called.Load() != 1 {
		t.Errorf("trigger called %d times, want 1", called.Load())
	}
}

func TestTriggerInactiveContainerReturnsAPIError(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	mux.HandleFunc("POST /api/public/v1/containers/101/scan", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"The container must be active before it can be scanned."}`))
	})
	c := newTestClient(t, mux)
	err := c.TriggerContainerScan(t.Context(), 101)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 APIError, got %v", err)
	}
	if !strings.Contains(apiErr.Message, "must be active") {
		t.Errorf("message = %q", apiErr.Message)
	}
}

func TestListCodeRepos(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	mux.HandleFunc("GET /api/public/v1/repositories/code", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("filter_name"); got != "my-project" {
			t.Errorf("filter_name = %q", got)
		}
		http.ServeFile(w, r, "../../../testdata/api/coderepos.json")
	})
	c := newTestClient(t, mux)
	repos, err := c.ListCodeRepos(t.Context(), "my-project")
	if err != nil {
		t.Fatalf("ListCodeRepos: %v", err)
	}
	if len(repos) != 1 {
		t.Fatalf("got %d repos, want 1", len(repos))
	}
	repo := repos[0]
	if repo.ID != 55 || repo.Name != "my-project" || repo.Branch != "master" || !repo.Active {
		t.Errorf("unexpected repo: %+v", repo)
	}
}

func TestTriggerCodeRepoScanQueryParams(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	mux.HandleFunc("POST /api/public/v1/repositories/code/55/scan", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("include_sast_scan") != "true" || q.Get("include_secrets_scan") != "true" {
			t.Errorf("unexpected query: %v", q)
		}
		if q.Has("include_iac_scan") {
			t.Errorf("include_iac_scan should be absent, got %v", q)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	c := newTestClient(t, mux)
	if err := c.TriggerCodeRepoScan(t.Context(), 55, ScanTypes{SAST: true, Secrets: true}); err != nil {
		t.Fatalf("TriggerCodeRepoScan: %v", err)
	}
}

func TestExportOpenIssues(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	mux.HandleFunc("GET /api/public/v1/issues/export", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("format") != "json" || q.Get("filter_status") != "open" {
			t.Errorf("unexpected query: %v", q)
		}
		if q.Get("filter_container_repo_id") != "101" {
			t.Errorf("filter_container_repo_id = %q", q.Get("filter_container_repo_id"))
		}
		if q.Has("page") {
			t.Error("page must be omitted so the endpoint exports everything")
		}
		if q.Has("filter_severities") {
			t.Error("severities must not be filtered at fetch time")
		}
		http.ServeFile(w, r, "../../../testdata/api/issues_container.json")
	})
	c := newTestClient(t, mux)
	issues, err := c.ExportOpenIssues(t.Context(), IssueFilter{ContainerRepoID: 101})
	if err != nil {
		t.Fatalf("ExportOpenIssues: %v", err)
	}
	if len(issues) != 3 {
		t.Fatalf("got %d issues, want 3", len(issues))
	}
	first := issues[0]
	if first.CVEID != "CVE-2025-12345" || first.Severity != "critical" || first.AffectedPackage != "openssl" {
		t.Errorf("unexpected first issue: %+v", first)
	}
	if first.AttackSurface != "docker_container" {
		t.Errorf("AttackSurface = %q, want docker_container", first.AttackSurface)
	}
	if len(first.PatchedVersions) != 2 {
		t.Errorf("PatchedVersions = %v", first.PatchedVersions)
	}
	secret := issues[2]
	if secret.StartLine != 42 || secret.AffectedFile != "app/config/settings.py" {
		t.Errorf("unexpected secret issue: %+v", secret)
	}
}

func TestExportIssuesRequiresFilter(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	c := newTestClient(t, mux)
	if _, err := c.ExportOpenIssues(t.Context(), IssueFilter{}); err == nil {
		t.Fatal("expected error for empty filter")
	}
}

func TestExportIssuesByCodeRepo(t *testing.T) {
	mux := http.NewServeMux()
	serveToken(t, mux)
	mux.HandleFunc("GET /api/public/v1/issues/export", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("filter_code_repo_id"); got != "55" {
			t.Errorf("filter_code_repo_id = %q", got)
		}
		http.ServeFile(w, r, "../../../testdata/api/issues_code.json")
	})
	c := newTestClient(t, mux)
	issues, err := c.ExportOpenIssues(t.Context(), IssueFilter{CodeRepoID: 55})
	if err != nil {
		t.Fatalf("ExportOpenIssues: %v", err)
	}
	if len(issues) != 4 {
		t.Fatalf("got %d issues, want 4", len(issues))
	}
	sast := issues[0]
	if sast.Type != "sast" || sast.StartLine != 118 || sast.EndLine != 124 || sast.AffectedFile != "internal/db/query.go" {
		t.Errorf("unexpected sast issue: %+v", sast)
	}
	if sast.AttackSurface != "backend" {
		t.Errorf("AttackSurface = %q, want backend", sast.AttackSurface)
	}
}
