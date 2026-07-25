package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var apiClient = &http.Client{Timeout: 10 * time.Second}

type zoraxyClient struct {
	baseURL, apiKey, csrf, cookie string
}

func newZoraxyClient(port int, apiKey, csrf, cookie string) *zoraxyClient {
	return &zoraxyClient{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		apiKey:  apiKey, csrf: csrf, cookie: cookie,
	}
}

func (c *zoraxyClient) do(method, path string, params url.Values) ([]byte, int, error) {
	var body io.Reader
	if params != nil {
		body = strings.NewReader(params.Encode())
	}
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, 0, err
	}
	if params != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", c.apiKey)
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
		req.Header.Set("X-Zoraxy-Csrf", c.csrf)
	}
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}
	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return raw, resp.StatusCode, nil
}

type proxyEndpoint struct {
	RootOrMatchingDomain string `json:"RootOrMatchingDomain"`
}

type vdirInfo struct {
	MatchingPath string `json:"MatchingPath"`
}

type forwardAuthConfig struct {
	Address string `json:"address"`
}

func extractCSRF(r *http.Request) string {
	if t := r.Header.Get("X-CSRF-Token"); t != "" {
		return t
	}
	return r.Header.Get("X-Zoraxy-Csrf")
}

func extractCookie(r *http.Request) string {
	return r.Header.Get("Cookie")
}

func getGlobalForwardAuth(zPort int, apiKey, csrf, cookie string) (*forwardAuthConfig, error) {
	z := newZoraxyClient(zPort, apiKey, csrf, cookie)
	raw, code, err := z.do("GET", "/api/sso/forward-auth", nil)
	if err != nil {
		return nil, err
	}
	if code >= 400 {
		return nil, fmt.Errorf("HTTP %d", code)
	}
	var cfg forwardAuthConfig
	return &cfg, json.Unmarshal(raw, &cfg)
}

func installGlobalForwardAuth(zPort int, apiKey, csrf, cookie, addr string) error {
	z := newZoraxyClient(zPort, apiKey, csrf, cookie)
	_, code, err := z.do("POST", "/api/sso/forward-auth", url.Values{
		"address":             {addr},
		"useXOriginalHeaders": {"true"},
		"ignoredPaths":        {"/.within.website/"},
	})
	if err != nil {
		return err
	}
	if code >= 400 {
		return fmt.Errorf("HTTP %d", code)
	}
	return nil
}

func enableRoute(zPort int, apiKey, csrf, cookie, domain, anubisURL string) error {
	z := newZoraxyClient(zPort, apiKey, csrf, cookie)
	_, code, err := z.do("POST", "/api/proxy/edit", url.Values{
		"rootname": {domain}, "authprovider": {"2"},
	})
	if err != nil {
		return err
	}
	if code >= 400 {
		return fmt.Errorf("edit HTTP %d", code)
	}
	// vdir points to this plugin's static port
	z.do("POST", "/api/proxy/vdir/add", url.Values{
		"type": {"host"}, "endpoint": {domain},
		"path": {"/.within.website/"}, "domain": {fmt.Sprintf("127.0.0.1:%d", staticPort)},
		"reqTLS": {"false"},
	})
	return nil
}

func disableRoute(zPort int, apiKey, csrf, cookie, domain string) error {
	z := newZoraxyClient(zPort, apiKey, csrf, cookie)
	_, code, err := z.do("POST", "/api/proxy/edit", url.Values{
		"rootname": {domain}, "authprovider": {"0"},
	})
	if err != nil {
		return err
	}
	if code >= 400 {
		return fmt.Errorf("edit HTTP %d", code)
	}
	// clean up vdir too
	z.do("POST", "/api/proxy/vdir/del", url.Values{
		"type": {"host"}, "path": {domain}, "vdir": {"/.within.website/"},
	})
	return nil
}

func listRoutes(zPort int, apiKey, csrf, cookie string) ([]map[string]any, error) {
	z := newZoraxyClient(zPort, apiKey, csrf, cookie)
	raw, code, err := z.do("GET", "/api/proxy/list?type=host", nil)
	if err != nil {
		return nil, err
	}
	if code >= 400 {
		return nil, fmt.Errorf("HTTP %d", code)
	}
	var eps []proxyEndpoint
	if err := json.Unmarshal(raw, &eps); err != nil {
		return nil, err
	}

	var out []map[string]any
	for _, ep := range eps {
		d := ep.RootOrMatchingDomain
		if d == "/" || d == "" {
			continue
		}
		protected := false
		if raw, _, err := z.do("GET", "/api/proxy/vdir/list?type=host&ep="+url.QueryEscape(d), nil); err == nil {
			var vds []vdirInfo
			if json.Unmarshal(raw, &vds) == nil {
				for _, v := range vds {
					if strings.HasPrefix(v.MatchingPath, "/.within.website") {
						protected = true
						break
					}
				}
			}
		}
		out = append(out, map[string]any{"domain": d, "protected": protected})
	}
	return out, nil
}
