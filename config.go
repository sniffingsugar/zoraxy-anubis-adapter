package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Config struct {
	AnubisURL string `json:"anubis_url"`
	FailMode  string `json:"fail_mode"`
}

type ConfigManager struct {
	mu   sync.RWMutex
	data Config
	path string
}

func NewConfigManager(dir string) *ConfigManager {
	return &ConfigManager{
		path: filepath.Join(dir, "config.json"),
		data: Config{AnubisURL: "http://127.0.0.1:8923", FailMode: "open"},
	}
}

func (c *ConfigManager) Load() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	raw, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(raw, &c.data)
}

func (c *ConfigManager) Get() Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data
}

func (c *ConfigManager) Set(anubisURL, failMode string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data.AnubisURL = anubisURL
	c.data.FailMode = failMode
	raw, _ := json.MarshalIndent(c.data, "", "  ")
	return os.WriteFile(c.path, raw, 0600)
}

func validateAnubisURL(s string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if s := strings.ToLower(u.Scheme); s != "http" && s != "https" {
		return fmt.Errorf("must be http(s)")
	}
	if u.Host == "" {
		return fmt.Errorf("missing host")
	}
	return nil
}
