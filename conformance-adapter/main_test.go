// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package main

import (
	"encoding/json"
	"testing"

	"github.com/governedobjects/governed-objects-go/version"
)

func newSession(t *testing.T) *session {
	t.Helper()
	s := &session{}
	if err := s.reset(); err != nil {
		t.Fatal(err)
	}
	return s
}

// The adapter declares the implementation name and the single-source version.
func TestCapabilitiesDeclareNameAndVersion(t *testing.T) {
	resp := newSession(t).handle(request{ID: "1", Op: "capabilities"})
	impl, ok := resp.Capabilities["implementation"].(map[string]string)
	if !ok || impl["name"] != "governed-objects-go" || impl["version"] != version.Version {
		t.Fatalf("implementation declaration %v", resp.Capabilities["implementation"])
	}
}

// F9: syntactically valid requests that omit required semantic members must
// produce one structured response and leave the session serviceable.
func TestMalformedRequestsGetStructuredResponses(t *testing.T) {
	lines := []string{
		`{"id":"a","op":"add_relationship","actor":"x","object_id":"o"}`,
		`{"id":"b","op":"remove_relationship","actor":"x","object_id":"o"}`,
		`{"id":"c","op":"restore","actor":"x","objects":[{"history":[{"relationship":null,"baseline_relationships":null}]}]}`,
		`{"id":"d","op":"create","actor":"x","type":"t"}`,
		`{"id":"e","op":"mutate"}`,
		`{"id":"f","op":"replay","object_id":"o"}`,
		`{"id":"g","op":"semantic_view"}`,
		`{"id":"h","op":"no-such-op"}`,
	}
	s := newSession(t)
	for _, line := range lines {
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			t.Fatal(err)
		}
		resp := s.handle(req)
		if resp.ID != req.ID || resp.Outcome == "" {
			t.Fatalf("%s: unstructured response %+v", line, resp)
		}
	}
	if resp := s.handle(request{ID: "z", Op: "capabilities"}); !resp.Ok {
		t.Fatalf("session not serviceable after malformed requests: %+v", resp)
	}
}
