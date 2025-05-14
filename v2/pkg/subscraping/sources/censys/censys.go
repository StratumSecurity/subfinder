// Package censys logic
package censys

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/StratumSecurity/subfinder/v2/pkg/subscraping"
)

const (
	maxCensysPages = 10
	maxPerPage     = 100
)

// Request structures for the new API
type searchRequest struct {
	Q string `json:"q"`
}

// Response structures for the new API
type response struct {
	Result     result `json:"result"`
	Status     string `json:"status"`
	StatusCode int    `json:"status_code"`
}

type result struct {
	Query string `json:"query"`
	Total int    `json:"total"`
	Hits  []hit  `json:"hits"`
	Links links  `json:"links"`
}

type hit struct {
	CertificateV1 certificateV1 `json:"certificate_v1"`
}

type certificateV1 struct {
	Resource resource `json:"resource"`
}

type resource struct {
	Names []string `json:"names"`
}

type links struct {
	Next string `json:"next"`
	Prev string `json:"prev"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []apiKey
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

type apiKey struct {
	token string // Personal Access Token
	orgID string // Organization ID
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey.token == "" || randomApiKey.orgID == "" {
			s.skipped = true
			return
		}

		// New Censys API v3 endpoint
		certSearchEndpoint := "https://api.platform.censys.io/v3/global/search/query"
		cursor := ""
		currentPage := 1

		// We'll use the domain directly in our specific query below

		for {
			// Use the correct Censys Query Language syntax with the proper field name
			// Based on the working curl command, the field name is cert.names
			specificQuery := fmt.Sprintf("cert.names: \"%s\"", domain)
			requestBody := fmt.Sprintf(`{"query":"%s"}`, strings.ReplaceAll(specificQuery, `"`, `\"`))

			// Query is ready for API requests

			// Add cursor and pagination as URL parameters
			queryParams := map[string]string{}
			queryParams["per_page"] = fmt.Sprintf("%d", maxPerPage)

			if cursor != "" {
				queryParams["cursor"] = cursor
			}

			// Use the simple JSON string as request body
			reqBody := []byte(requestBody)

			// Create request headers
			headers := map[string]string{
				"Accept":            "application/vnd.censys.api.v3.search.v1+json",
				"Content-Type":      "application/json",
				"Authorization":     "Bearer " + randomApiKey.token,
				"X-Organization-ID": randomApiKey.orgID,
			}

			// Build the URL with query parameters
			endpointURL := certSearchEndpoint
			first := true
			for k, v := range queryParams {
				if first {
					endpointURL += "?"
					first = false
				} else {
					endpointURL += "&"
				}
				endpointURL += k + "=" + v
			}

			// Make the API request
			resp, err := session.HTTPRequest(
				ctx,
				"POST",
				endpointURL,
				"", // No cookies
				headers,
				bytes.NewReader(reqBody),
				subscraping.BasicAuth{}, // Empty basic auth
			)

			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			// Read the response body
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				resp.Body.Close()
				return
			}

			// Response received from Censys API

			// Parse the response
			var censysResponse response
			err = jsoniter.Unmarshal(respBody, &censysResponse)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				resp.Body.Close()
				return
			}

			// Print the parsed response for debugging
			if censysResponse.Result.Total > 0 {
				fmt.Printf("[%s] Found %d certificate results for %s\n", s.Name(), censysResponse.Result.Total, domain)
			}

			resp.Body.Close()

			// Process the results
			for _, hit := range censysResponse.Result.Hits {
				// Process each hit

				// Extract names from the certificate data
				if hit.CertificateV1.Resource.Names != nil {
					for _, name := range hit.CertificateV1.Resource.Names {
						// Check if the name is a subdomain of the target domain
						if name != "" && strings.HasSuffix(name, domain) && name != domain {
							results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: name}
							s.results++
						}
					}
				}
			}

			// Exit the censys enumeration if last page is reached
			cursor = censysResponse.Result.Links.Next
			if cursor == "" || currentPage >= maxCensysPages {
				break
			}
			currentPage++
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "censys"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = subscraping.CreateApiKeys(keys, func(k, v string) apiKey {
		// The first part is the Personal Access Token, the second part is the Organization ID
		return apiKey{token: k, orgID: v}
	})
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
