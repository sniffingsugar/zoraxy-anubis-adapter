package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	zp "zoraxy-anubis-adapter/zoraxy_plugin"
)

//go:embed web/* icon.png
var webFS embed.FS

var pluginSpec = &zp.IntroSpect{
	ID:           "com.sniffingsugar.zoraxy-anubis-adapter",
	Name:         "Anubis Bot Protection",
	Author:       "sniffingsugar",
	Description:  "Forward-Auth adapter for Anubis AI crawler defense.",
	URL:          "https://github.com/sniffingsugar/zoraxy-anubis-adapter",
	Type:         zp.PluginType_Utilities,
	VersionMajor: 1, VersionMinor: 0, VersionPatch: 0,
	UIPath: "/ui",
	PermittedAPIEndpoints: []zp.PermittedAPIEndpoint{
		{Method: "GET", Endpoint: "/api/proxy/list", Reason: "List proxy rules"},
		{Method: "GET", Endpoint: "/api/proxy/vdir/list", Reason: "List vdirs"},
	},
}

var zPort int
var apiKey string

func main() {
	config, err := zp.ServeAndRecvSpec(pluginSpec)
	if err != nil {
		fmt.Println("dev mode")
		config = &zp.ConfigureSpec{Port: 9699}
	}

	zPort = config.ZoraxyPort
	apiKey = config.APIKey
	listenPort = config.Port

	if zPort == 0 {
		zPort = 8000
	}

	pluginDir := filepath.Dir(os.Args[0])
	if exe, err := os.Executable(); err == nil {
		pluginDir = filepath.Dir(exe)
	}

	// write icon.png next to the binary so zoraxy plugin manager shows it
	if icon, err := webFS.ReadFile("icon.png"); err == nil {
		os.WriteFile(filepath.Join(pluginDir, "icon.png"), icon, 0644)
	}

	cm := NewConfigManager(pluginDir)
	if err := cm.Load(); err != nil {
		log.Printf("[anubis-adapter] config: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/check", handleForwardAuth(cm))
	mux.HandleFunc("/ui/api/config", handleConfigAPI(cm))
	mux.HandleFunc("/ui/api/status", handleStatus(cm))
	mux.HandleFunc("/ui/api/routes", handleRoutes(cm))
	mux.HandleFunc("/ui/api/global", handleGlobal(cm))

	ui := zp.NewPluginEmbedUIRouter(pluginSpec.ID, &webFS, "web", "/ui")
	ui.AttachHandlerToMux(mux)
	ui.RegisterTerminateHandler(func() { log.Println("[anubis-adapter] bye") }, mux)

	// catch-all: proxy /.within.website/ traffic to Anubis (vdir strips path, we add it back)
	mux.HandleFunc("/", handleAnubisProxy(cm))

	log.Printf("[anubis-adapter] ui :%d  check/vdir :%d  anubis=%s",
		listenPort, staticPort, cm.Get().AnubisURL)

	// static port server — forward-auth + vdir, never changes
	go func() {
		if err := http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", staticPort), mux); err != nil {
			log.Printf("[anubis-adapter] static port %d unavailable: %v", staticPort, err)
		}
	}()

	// dynamic port server — zoraxy UI proxy
	log.Fatalf("[anubis-adapter] %v", http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", listenPort), mux))
}

func adapterAddr() string {
	return fmt.Sprintf("http://127.0.0.1:%d/check", staticPort)
}

func handleConfigAPI(cm *ConfigManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(cm.Get())
		case http.MethodPost:
			var body struct {
				AnubisURL string `json:"anubis_url"`
				FailMode  string `json:"fail_mode"`
			}
			if err := json.NewDecoder(io.LimitReader(http.MaxBytesReader(w, r.Body, 4096), 4096)).Decode(&body); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			if err := validateAnubisURL(body.AnubisURL); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if body.FailMode == "" {
				body.FailMode = "open"
			}
			if body.FailMode != "open" && body.FailMode != "closed" {
				http.Error(w, "fail_mode: open|closed", http.StatusBadRequest)
				return
			}
			if err := cm.Set(body.AnubisURL, body.FailMode); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		default:
			http.Error(w, "nope", http.StatusMethodNotAllowed)
		}
	}
}

func handleRoutes(cm *ConfigManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if apiKey == "" {
			http.Error(w, `{"error":"no api key"}`, http.StatusForbidden)
			return
		}
		csrf := extractCSRF(r)
		cookie := extractCookie(r)
		switch r.Method {
		case http.MethodGet:
			routes, err := listRoutes(zPort, apiKey, csrf, cookie)
			if err != nil {
				http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(routes)
		case http.MethodPost:
			var body struct {
				Domain string `json:"domain"`
				Enable bool   `json:"enable"`
			}
			if err := json.NewDecoder(io.LimitReader(http.MaxBytesReader(w, r.Body, 4096), 4096)).Decode(&body); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			var err error
			if body.Enable {
				err = enableRoute(zPort, apiKey, csrf, cookie, body.Domain, cm.Get().AnubisURL)
			} else {
				err = disableRoute(zPort, apiKey, csrf, cookie, body.Domain)
			}
			if err != nil {
				http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			}
		}
	}
}

func handleGlobal(cm *ConfigManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if apiKey == "" {
			http.Error(w, `{"error":"no api key"}`, http.StatusForbidden)
			return
		}
		csrf := extractCSRF(r)
		cookie := extractCookie(r)
		switch r.Method {
		case http.MethodGet:
			cfg, err := getGlobalForwardAuth(zPort, apiKey, csrf, cookie)
			if err != nil {
				json.NewEncoder(w).Encode(map[string]any{"installed": false, "error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"installed": cfg.Address != "", "address": cfg.Address})
		case http.MethodPost:
			if err := installGlobalForwardAuth(zPort, apiKey, csrf, cookie, adapterAddr()); err != nil {
				http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"ok": true})
		}
	}
}
