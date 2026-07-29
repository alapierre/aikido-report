package publicapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// codeReposPerPage is the documented maximum page size for code repos.
const codeReposPerPage = 200

// ScanTypes selects which optional scanners a triggered repository scan
// should include. The dependency (SCA) scan always runs.
type ScanTypes struct {
	SAST    bool
	IaC     bool
	Secrets bool
}

// ListCodeRepos returns all code repositories matching the server-side
// name filter, following pagination to the end.
func (c *Client) ListCodeRepos(ctx context.Context, nameFilter string) ([]CodeRepo, error) {
	var all []CodeRepo
	for page := 0; ; page++ {
		if page >= maxListPages {
			return nil, fmt.Errorf("publicapi: code repository listing exceeded %d pages, aborting", maxListPages)
		}
		q := url.Values{
			"include_inactive": {"true"},
			"page":             {strconv.Itoa(page)},
			"per_page":         {strconv.Itoa(codeReposPerPage)},
		}
		if nameFilter != "" {
			q.Set("filter_name", nameFilter)
		}
		body, err := c.get(ctx, "/api/public/v1/repositories/code", q)
		if err != nil {
			return nil, fmt.Errorf("listing code repositories: %w", err)
		}
		items, err := decodeList[CodeRepo](body, "repositories", "data", "items")
		if err != nil {
			return nil, fmt.Errorf("publicapi: code repositories response: %w", err)
		}
		all = append(all, items...)
		if len(items) < codeReposPerPage {
			return all, nil
		}
	}
}

// GetCodeRepo fetches a single code repository by its Aikido ID.
func (c *Client) GetCodeRepo(ctx context.Context, id int) (CodeRepo, error) {
	body, err := c.get(ctx, fmt.Sprintf("/api/public/v1/repositories/code/%d", id), nil)
	if err != nil {
		return CodeRepo{}, fmt.Errorf("fetching code repository %d: %w", id, err)
	}
	var repo CodeRepo
	if err := json.Unmarshal(body, &repo); err != nil {
		return CodeRepo{}, fmt.Errorf("publicapi: decoding code repository %d: %w", id, err)
	}
	return repo, nil
}

// TriggerCodeRepoScan requests a scan of the code repository. This call is
// never retried automatically.
func (c *Client) TriggerCodeRepoScan(ctx context.Context, id int, types ScanTypes) error {
	q := url.Values{}
	if types.SAST {
		q.Set("include_sast_scan", "true")
	}
	if types.IaC {
		q.Set("include_iac_scan", "true")
	}
	if types.Secrets {
		q.Set("include_secrets_scan", "true")
	}
	if _, err := c.post(ctx, fmt.Sprintf("/api/public/v1/repositories/code/%d/scan", id), q); err != nil {
		return fmt.Errorf("triggering scan of code repository %d: %w", id, err)
	}
	return nil
}
