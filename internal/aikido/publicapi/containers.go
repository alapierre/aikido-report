package publicapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

const (
	// containersPerPage is the documented maximum page size.
	containersPerPage = 100
	// maxListPages guards against runaway pagination; combined with the
	// page size it caps a listing at 10 000 records, far above anything a
	// name-filtered query should return.
	maxListPages = 100
)

// ListContainers returns all container repositories whose name matches the
// server-side filter, following pagination to the end. filter_status=all
// is requested on purpose: the API defaults to active-only and the caller
// needs to see inactive repositories to report them meaningfully.
func (c *Client) ListContainers(ctx context.Context, nameFilter string) ([]Container, error) {
	var all []Container
	for page := 0; ; page++ {
		if page >= maxListPages {
			return nil, fmt.Errorf("publicapi: container listing exceeded %d pages, aborting", maxListPages)
		}
		q := url.Values{
			"filter_status": {"all"},
			"page":          {strconv.Itoa(page)},
			"per_page":      {strconv.Itoa(containersPerPage)},
		}
		if nameFilter != "" {
			q.Set("filter_name", nameFilter)
		}
		body, err := c.get(ctx, "/api/public/v1/containers", q)
		if err != nil {
			return nil, fmt.Errorf("listing container repositories: %w", err)
		}
		items, err := decodeList[Container](body, "containers", "data", "items")
		if err != nil {
			return nil, fmt.Errorf("publicapi: containers response: %w", err)
		}
		all = append(all, items...)
		if len(items) < containersPerPage {
			return all, nil
		}
	}
}

// GetContainer fetches a single container repository by its Aikido ID.
func (c *Client) GetContainer(ctx context.Context, id int) (Container, error) {
	body, err := c.get(ctx, fmt.Sprintf("/api/public/v1/containers/%d", id), nil)
	if err != nil {
		return Container{}, fmt.Errorf("fetching container repository %d: %w", id, err)
	}
	var container Container
	if err := json.Unmarshal(body, &container); err != nil {
		return Container{}, fmt.Errorf("publicapi: decoding container %d: %w", id, err)
	}
	return container, nil
}

// TriggerContainerScan requests an ad-hoc scan of the container repository.
// The API accepts no tag: Aikido scans whatever the repository's tag filter
// selects. This call is never retried automatically.
func (c *Client) TriggerContainerScan(ctx context.Context, id int) error {
	if _, err := c.post(ctx, fmt.Sprintf("/api/public/v1/containers/%d/scan", id), nil); err != nil {
		return fmt.Errorf("triggering scan of container repository %d: %w", id, err)
	}
	return nil
}
