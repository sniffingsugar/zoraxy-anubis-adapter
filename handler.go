package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

const anubisCheckPath = "/.within.website/x/cmd/anubis/api/check"

var listenPort int

// fixed port for /check and vdir — doesn't change between restarts
const staticPort = 9698

func handleForwardAuth(cm *ConfigManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := cm.Get()

		if cfg.AnubisURL == "" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// never challenge anubis's own paths — prevents redirect loops
		origURL := r.Header.Get("X-Original-URL")
		fwdUri := r.Header.Get("X-Forwarded-Uri")
		if strings.Contains(origURL, "/.within.website/") || strings.Contains(fwdUri, "/.within.website/") {
			w.WriteHeader(http.StatusOK)
			return
		}

		base := strings.TrimRight(cfg.AnubisURL, "/")
		req, err := http.NewRequestWithContext(r.Context(), "GET", base+anubisCheckPath, nil)
		if err != nil {
			w.WriteHeader(http.StatusOK)
			return
		}

		// pass everything through
		for k, vs := range r.Header {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}

		// zoraxy forward-auth doesn't send client IP. use 127.0.0.1 so both
		// check and challenge paths evaluate the same policy in anubis.
		req.Header.Set("X-Real-Ip", "127.0.0.1")

		resp, err := httpClient.Do(req)
		if err != nil {
			log.Printf("[anubis-adapter] unreachable: %v", err)
			if cfg.FailMode == "closed" {
				http.Error(w, "Anubis unreachable", http.StatusServiceUnavailable)
			} else {
				w.WriteHeader(http.StatusOK)
			}
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			w.WriteHeader(http.StatusOK)
		case resp.StatusCode == http.StatusForbidden:
			http.Error(w, "Access denied", http.StatusForbidden)
		default:
			// redirect to challenge page on same host
			var originalURL string
			if ou := r.Header.Get("X-Original-URL"); ou != "" {
				originalURL = ou
			} else {
				proto := r.Header.Get("X-Forwarded-Proto")
				if proto == "" {
					proto = "https"
				}
				host := r.Header.Get("X-Forwarded-Host")
				if host == "" {
					host = r.Host
				}
				uri := r.Header.Get("X-Forwarded-Uri")
				if uri == "" {
					uri = "/"
				}
				originalURL = proto + "://" + host + uri
			}
			w.Header().Set("Location", "/.within.website/?redir="+url.QueryEscape(originalURL))
			w.WriteHeader(http.StatusUnauthorized)
		}
	}
}

func handleStatus(cm *ConfigManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := cm.Get()
		reachable := false

		if cfg.AnubisURL != "" {
			if resp, err := httpClient.Get(strings.TrimRight(cfg.AnubisURL, "/") + anubisCheckPath); err == nil {
				reachable = true
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"anubis_url":       cfg.AnubisURL,
			"anubis_reachable": reachable,
			"fail_mode":        cfg.FailMode,
			"check_port":       staticPort,
			"ui_port":          listenPort,
		})
	}
}

// handleAnubisProxy is the catch-all that proxies /.within.website/ traffic
// to Anubis. Zoraxy's vdir strips the matching path, so we add it back.
func handleAnubisProxy(cm *ConfigManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := cm.Get()
		target, err := url.Parse(strings.TrimRight(cfg.AnubisURL, "/"))
		if err != nil {
			http.Error(w, "bad anubis url", http.StatusInternalServerError)
			return
		}

		// handle both: zoraxy may or may not strip the vdir path
		if !strings.HasPrefix(r.URL.Path, "/.within.website") {
			r.URL.Path = "/.within.website" + r.URL.Path
			if r.URL.Path == "/.within.website" {
				r.URL.Path = "/.within.website/"
			}
		}

		// force same IP as forward-auth path so anubis JWT policy hash matches
		r.Header.Set("X-Real-Ip", "127.0.0.1")

		httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
	}
}
