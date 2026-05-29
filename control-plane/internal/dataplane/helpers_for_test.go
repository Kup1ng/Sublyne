package dataplane

import "encoding/json"

// jsonUnmarshalTestImpl wraps json.Unmarshal so manager_test.go does
// not have to import encoding/json directly — keeps the import list
// of the test file readable.
func jsonUnmarshalTestImpl(b []byte, v any) error { return json.Unmarshal(b, v) }
