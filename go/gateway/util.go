package gateway

import "encoding/json"

// decodeToMap round-trips a JSON-serializable value into a map[string]any so it
// can be canonicalized by the sdk JCS layer with consistent (float64) number
// typing. It is the gateway-local counterpart of the sdk helper and the bridge
// between typed structs and canonical signing/hashing.
func decodeToMap(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}
