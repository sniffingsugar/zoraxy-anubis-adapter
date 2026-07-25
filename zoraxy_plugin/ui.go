package zoraxy_plugin

import (
	"embed"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type PluginUiRouter struct {
	PluginID       string
	TargetFs       *embed.FS
	TargetFsPrefix string
	HandlerPrefix  string
}

func NewPluginEmbedUIRouter(pluginID string, targetFs *embed.FS, targetFsPrefix string, handlerPrefix string) *PluginUiRouter {
	if !strings.HasPrefix(targetFsPrefix, "/") {
		targetFsPrefix = "/" + targetFsPrefix
	}
	targetFsPrefix = strings.TrimSuffix(targetFsPrefix, "/")
	if !strings.HasPrefix(handlerPrefix, "/") {
		handlerPrefix = "/" + handlerPrefix
	}
	handlerPrefix = strings.TrimSuffix(handlerPrefix, "/")
	return &PluginUiRouter{
		PluginID:       pluginID,
		TargetFs:       targetFs,
		TargetFsPrefix: targetFsPrefix,
		HandlerPrefix:  handlerPrefix,
	}
}

func (p *PluginUiRouter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rewrittenURL := strings.TrimPrefix(r.RequestURI, p.HandlerPrefix)
		rewrittenURL = strings.ReplaceAll(rewrittenURL, "//", "/")
		parsed, err := url.Parse(rewrittenURL)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		r.URL = parsed
		r.RequestURI = rewrittenURL

		subFS, err := fs.Sub(*p.TargetFs, strings.TrimPrefix(p.TargetFsPrefix, "/"))
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		csrfToken := r.Header.Get("X-Zoraxy-Csrf")
		if csrfToken == "" {
			csrfToken = "missing-csrf-token"
		}
		p.serveWithCSRF(w, r, http.FileServer(http.FS(subFS)), csrfToken)
	})
}

func (p *PluginUiRouter) serveWithCSRF(w http.ResponseWriter, r *http.Request, fsHandler http.Handler, csrfToken string) {
	if strings.HasSuffix(r.URL.Path, ".html") || strings.HasSuffix(r.URL.Path, "/") {
		var targetFilePath string
		if strings.HasSuffix(r.URL.Path, "/") {
			targetFilePath = strings.TrimPrefix(r.URL.Path, "/") + "index.html"
		} else {
			targetFilePath = strings.TrimPrefix(r.URL.Path, "/")
		}
		targetFilePath = strings.TrimPrefix(p.TargetFsPrefix+"/"+targetFilePath, "/")
		content, err := fs.ReadFile(*p.TargetFs, targetFilePath)
		if err == nil {
			body := strings.ReplaceAll(string(content), "{{.csrfToken}}", csrfToken)
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(body))
			return
		}
	}
	fsHandler.ServeHTTP(w, r)
}

func (p *PluginUiRouter) AttachHandlerToMux(mux *http.ServeMux) {
	p.HandlerPrefix = strings.TrimSuffix(p.HandlerPrefix, "/")
	mux.Handle(p.HandlerPrefix+"/", p.Handler())
}

func (p *PluginUiRouter) RegisterTerminateHandler(termFunc func(), mux *http.ServeMux) {
	if mux == nil {
		mux = http.DefaultServeMux
	}
	mux.HandleFunc(p.HandlerPrefix+"/term", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		go func() {
			time.Sleep(100 * time.Millisecond)
			os.Exit(0)
		}()
	})
}
