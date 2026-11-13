package browser

import "testing"

func TestToJSValueNestedMapsAndSlices(t *testing.T) {
	input := map[string]interface{}{
		"formIndex": 2,
		"params": []map[string]string{
			{"param_name": "q", "param_value": "payload"},
			{"param_name": "page", "param_value": "1"},
		},
	}
	out, ok := toJSValue(input).(map[string]interface{})
	if !ok {
		t.Fatalf("top-level value is %T, want map[string]interface{}", toJSValue(input))
	}
	if got, ok := out["formIndex"].(float64); !ok || got != 2 {
		t.Fatalf("formIndex = %#v, want 2 (float64)", out["formIndex"])
	}
	params, ok := out["params"].([]interface{})
	if !ok || len(params) != 2 {
		t.Fatalf("params = %#v, want []interface{} of length 2", out["params"])
	}
	first, ok := params[0].(map[string]interface{})
	if !ok {
		t.Fatalf("params[0] is %T, want map[string]interface{}", params[0])
	}
	if first["param_name"] != "q" || first["param_value"] != "payload" {
		t.Fatalf("unexpected first param: %#v", first)
	}
}

func TestToJSValuePrimitives(t *testing.T) {
	if got := toJSValue("text"); got != "text" {
		t.Fatalf("string conversion = %#v", got)
	}
	if got := toJSValue(nil); got != nil {
		t.Fatalf("nil conversion = %#v", got)
	}
	if got, ok := toJSValue(map[string]string{"a": "b"}).(map[string]interface{}); !ok || got["a"] != "b" {
		t.Fatalf("map[string]string conversion = %#v", toJSValue(map[string]string{"a": "b"}))
	}
}
