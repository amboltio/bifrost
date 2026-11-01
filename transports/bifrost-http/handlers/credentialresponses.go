package handlers

import (
	"bytes"
	"encoding/json"
	"strings"

	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/valyala/fasthttp"
)

// redactManagementVirtualKeys operates on response bytes, never shared store or
// governance objects. Inference responses pay only the path-prefix check.
func redactManagementVirtualKeys(ctx *fasthttp.RequestCtx, body []byte) ([]byte, error) {
	if !bytes.HasPrefix(ctx.Path(), []byte("/api/")) {
		return body, nil
	}
	if !bytes.Contains(body, []byte("virtual_key")) && !bytes.Contains(bytes.ToLower(body), []byte("x-bf-vk")) && !bytes.Contains(body, []byte("sk-bf-")) {
		return body, nil
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	redactCredentialNodes(document, false)
	return providerUtils.MarshalSorted(document)
}

func redactCredentialNodes(value any, virtualKey bool) {
	switch node := value.(type) {
	case []any:
		for _, child := range node {
			redactCredentialNodes(child, virtualKey)
		}
	case map[string]any:
		if virtualKey {
			secret, _ := node["value"].(string)
			if wrapped, ok := node["value"].(map[string]any); ok {
				secret, _ = wrapped["value"].(string)
			}
			prefix := []rune(secret)
			if len(prefix) > 10 {
				prefix = prefix[:10]
			} else if len(prefix) > 0 {
				prefix = prefix[:len(prefix)-1]
			}
			node["value"] = ""
			node["value_prefix"] = string(prefix)
			delete(node, "previous_value")
			delete(node, "value_hash")
			delete(node, "previous_value_hash")
		}
		for key, child := range node {
			switch strings.ToLower(key) {
			case "virtual_key_value", "x-bf-vk", "authorization", "x-api-key", "api-key", "x-goog-api-key", "cookie", "set-cookie", "x-bifrost-setup-token":
				node[key] = ""
				continue
			}
			if raw, ok := child.(string); ok {
				lower := strings.ToLower(raw)
				if strings.Contains(lower, `"x-bf-vk"`) || strings.Contains(lower, `"authorization"`) || strings.Contains(lower, `"virtual_key_value"`) {
					// Log previews may contain JSON encoded as a string. A truncated
					// credential-bearing preview is dropped rather than leaked.
					var embedded any
					decoder := json.NewDecoder(strings.NewReader(raw))
					decoder.UseNumber()
					if err := decoder.Decode(&embedded); err != nil {
						node[key] = "[redacted credential-bearing payload]"
						continue
					}
					redactCredentialNodes(embedded, false)
					clean, err := providerUtils.MarshalSorted(embedded)
					if err != nil {
						node[key] = "[redacted credential-bearing payload]"
					} else {
						node[key] = string(clean)
					}
					continue
				}
			}
			redactCredentialNodes(child, key == "virtual_key" || key == "virtual_keys")
		}
	}
}
