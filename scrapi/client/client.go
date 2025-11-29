package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a helper for calling the SCRAPI demo server.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Token      string
}

// Register posts a COSE_Sign1 payload to /entries and returns the locator ID and receipt bytes.
func (c *Client) Register(ctx context.Context, cosePayload []byte) (string, []byte, error) {
	return c.RegisterWithContentType(ctx, cosePayload, "application/cose")
}

// RegisterWithContentType posts a payload to /entries with the given content type.
func (c *Client) RegisterWithContentType(ctx context.Context, payload []byte, contentType string) (string, []byte, error) {
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	endpoint := strings.TrimSuffix(c.BaseURL, "/") + "/entries"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", nil, fmt.Errorf("build request: %w", err)
	}
	if contentType == "" {
		contentType = "application/cose"
	}
	req.Header.Set("Content-Type", contentType)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("POST entries: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", nil, fmt.Errorf("unexpected status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return "", nil, fmt.Errorf("missing Location header")
	}
	locParts := strings.Split(strings.TrimSuffix(location, "/"), "/")
	locator := locParts[len(locParts)-1]

	var receipt []byte
	switch resp.StatusCode {
	case http.StatusCreated:
		receipt, err = io.ReadAll(resp.Body)
		if err != nil {
			return "", nil, fmt.Errorf("read receipt: %w", err)
		}
	case http.StatusAccepted:
		// Pending; caller can poll later.
	default:
	}

	return locator, receipt, nil
}

// FetchReceipt polls /entries/{id} until success or a max number of attempts.
func (c *Client) FetchReceipt(ctx context.Context, id string, maxAttempts int, delay time.Duration) ([]byte, error) {
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.BaseURL, "/")+"/entries/"+id, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("GET entries/%s: %w", id, err)
		}
		if resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			return io.ReadAll(resp.Body)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusAccepted && attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
				continue
			}
		}
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return nil, fmt.Errorf("receipt not available after %d attempts", maxAttempts)
}
