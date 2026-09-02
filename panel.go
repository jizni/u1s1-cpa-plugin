// panel.go serves the u1s1 dashboard resource page. The HTML is embedded so the
// page ships with the plugin and loads no third-party script (it runs in the
// management origin and must stay trusted code).
package main

import (
	"embed"
	"encoding/json"
	"strings"
)

//go:embed panel.html
var panelFS embed.FS

// renderPanel injects the host-provided management base path so the page's fetch
// calls keep working if the host ever moves /v0/management.
func renderPanel() []byte {
	raw, err := panelFS.ReadFile("panel.html")
	if err != nil {
		return []byte("<!doctype html><meta charset=utf-8><p>u1s1 panel asset missing.</p>")
	}
	baseJSON, _ := json.Marshal(loadedManagementBase())
	out := strings.ReplaceAll(string(raw), "__U1S1_MANAGEMENT_BASE_PATH_JSON__", string(baseJSON))
	return []byte(out)
}
