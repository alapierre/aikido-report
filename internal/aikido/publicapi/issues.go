package publicapi

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// IssueFilter narrows an issue export to one scan target. Exactly one of
// the fields should be set.
type IssueFilter struct {
	ContainerRepoID int
	CodeRepoID      int
}

// ExportOpenIssues fetches all open issues for the given target via
// GET /issues/export. Per the documentation, omitting the page parameter
// makes the endpoint return every matching issue in a single response, so
// no pagination loop is needed here; the transport-level response size
// limit still applies. Severity is deliberately not filtered: the report
// always contains all open findings, and the quality gate applies its
// threshold locally.
func (c *Client) ExportOpenIssues(ctx context.Context, filter IssueFilter) ([]Issue, error) {
	q := url.Values{
		"format":        {"json"},
		"filter_status": {"open"},
	}
	switch {
	case filter.ContainerRepoID != 0:
		q.Set("filter_container_repo_id", strconv.Itoa(filter.ContainerRepoID))
	case filter.CodeRepoID != 0:
		q.Set("filter_code_repo_id", strconv.Itoa(filter.CodeRepoID))
	default:
		return nil, fmt.Errorf("publicapi: issue filter must specify a container or code repository")
	}
	body, err := c.get(ctx, "/api/public/v1/issues/export", q)
	if err != nil {
		return nil, fmt.Errorf("exporting issues: %w", err)
	}
	issues, err := decodeList[Issue](body, "issues", "data", "items")
	if err != nil {
		return nil, fmt.Errorf("publicapi: issues export response: %w", err)
	}
	return issues, nil
}
