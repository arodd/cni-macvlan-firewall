package main

// PortMapEntry mirrors the CNI runtimeConfig.portMappings schema used by the portMap capability.
type PortMapEntry struct {
	HostPort      uint16 `json:"hostPort"`
	ContainerPort uint16 `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"hostIP,omitempty"`
}

// NetConf represents the plugin configuration passed on stdin.
type NetConf struct {
	CniVersion    string `json:"cniVersion"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	RuntimeConfig struct {
		PortMappings []PortMapEntry `json:"portMappings"`
	} `json:"runtimeConfig,omitempty"`

	PrevResult map[string]interface{} `json:"prevResult,omitempty"`
}
