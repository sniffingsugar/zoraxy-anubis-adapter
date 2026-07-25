package zoraxy_plugin

import (
	"encoding/json"
	"fmt"
	"os"
)

type PluginType int

const (
	PluginType_Router    PluginType = 0
	PluginType_Utilities PluginType = 1
)

type StaticCaptureRule struct {
	CapturePath string `json:"capture_path"`
}

type RuntimeConstantValue struct {
	ZoraxyVersion    string `json:"zoraxy_version"`
	ZoraxyUUID       string `json:"zoraxy_uuid"`
	DevelopmentBuild bool   `json:"development_build"`
}

type PermittedAPIEndpoint struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
	Reason   string `json:"reason"`
}

type IntroSpect struct {
	ID                    string               `json:"id"`
	Name                  string               `json:"name"`
	Author                string               `json:"author"`
	AuthorContact         string               `json:"author_contact"`
	Description           string               `json:"description"`
	URL                   string               `json:"url"`
	Type                  PluginType           `json:"type"`
	VersionMajor          int                  `json:"version_major"`
	VersionMinor          int                  `json:"version_minor"`
	VersionPatch          int                  `json:"version_patch"`
	StaticCapturePaths    []StaticCaptureRule  `json:"static_capture_paths,omitempty"`
	StaticCaptureIngress  string               `json:"static_capture_ingress,omitempty"`
	DynamicCaptureSniff   string               `json:"dynamic_capture_sniff,omitempty"`
	DynamicCaptureIngress string               `json:"dynamic_capture_ingress,omitempty"`
	UIPath                string               `json:"ui_path"`
	SubscriptionPath      string               `json:"subscription_path,omitempty"`
	SubscriptionsEvents   map[string]string    `json:"subscriptions_events,omitempty"`
	PermittedAPIEndpoints []PermittedAPIEndpoint `json:"permitted_api_endpoints,omitempty"`
}

type ConfigureSpec struct {
	Port         int                  `json:"port"`
	RuntimeConst RuntimeConstantValue `json:"runtime_const"`
	APIKey       string               `json:"api_key,omitempty"`
	ZoraxyPort   int                  `json:"zoraxy_port,omitempty"`
}

func ServeIntroSpect(spec *IntroSpect) {
	if len(os.Args) > 1 && os.Args[1] == "-introspect" {
		data, _ := json.MarshalIndent(spec, "", "  ")
		fmt.Println(string(data))
		os.Exit(0)
	}
}

func RecvConfigureSpec() (*ConfigureSpec, error) {
	for i, arg := range os.Args {
		if len(arg) > 11 && arg[:11] == "-configure=" {
			var cs ConfigureSpec
			if err := json.Unmarshal([]byte(arg[11:]), &cs); err != nil {
				return nil, err
			}
			return &cs, nil
		} else if arg == "-configure" {
			if len(os.Args) <= i+1 {
				return nil, fmt.Errorf("no config after -configure flag")
			}
			var cs ConfigureSpec
			if err := json.Unmarshal([]byte(os.Args[i+1]), &cs); err != nil {
				return nil, err
			}
			return &cs, nil
		}
	}
	return nil, fmt.Errorf("no -configure flag found")
}

func ServeAndRecvSpec(spec *IntroSpect) (*ConfigureSpec, error) {
	ServeIntroSpect(spec)
	return RecvConfigureSpec()
}
