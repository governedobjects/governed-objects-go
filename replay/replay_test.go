// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package replay_test

import (
	"encoding/json"
	"github.com/governedobjects/governed-objects-go/auth"
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/events"
	"github.com/governedobjects/governed-objects-go/internal/testtypes"
	"github.com/governedobjects/governed-objects-go/replay"
	"github.com/governedobjects/governed-objects-go/runtime"
	"github.com/governedobjects/governed-objects-go/store"
	"github.com/governedobjects/governed-objects-go/types"
	"maps"
	"reflect"
	"testing"
)

type supported struct {
	t types.PortableType
	b types.Behavior
}
type resolver map[types.Binding]supported

func (r resolver) ResolveType(binding types.Binding) (types.PortableType, types.Behavior, bool) {
	v, ok := r[binding]
	return v.t.Clone(), v.b, ok
}
func c(action core.Action) core.OperationContext {
	return core.OperationContext{Actor: "issuer", Action: action}
}

func history(t *testing.T) ([]events.CanonicalEvent, resolver) {
	t.Helper()
	p, b := testtypes.Probe()
	s := store.NewMemoryStore()
	r := runtime.NewRuntime(s, auth.NewGrantAuthorizer(map[core.Actor][]auth.Capability{"issuer": {auth.CapCreate, auth.CapRead, auth.CapUpdate, auth.CapTransition, auth.CapAddRelationship, auth.CapRemoveRelationship}}))
	if r.RegisterType(p, b) != nil {
		t.Fatal("register")
	}
	check := func(out core.Outcome, _ *store.ObjectRecord) {
		if out.Kind != core.OutcomeAccepted {
			t.Fatal(out)
		}
	}
	check(r.CreateObject(c(core.ActionCreate), "frame", p.Binding(), map[string]string{"signal": "#initial", "phase": "idle"}))
	check(r.UpdateState(c(core.ActionUpdate), "frame", p.Binding(), map[string]string{"signal": "#next"}))
	check(r.TransitionLifecycle(c(core.ActionTransition), "frame", p.Binding(), "sent"))
	rel := core.Relationship{Source: "frame", Type: "links", Target: "outside"}
	check(r.AddRelationship(c(core.ActionAddRelationship), "frame", rel))
	check(r.UpdateState(c(core.ActionUpdate), "frame", p.Binding(), map[string]string{"signal": "#final"}))
	check(r.RemoveRelationship(c(core.ActionRemoveRelationship), "frame", rel))
	check(r.TransitionLifecycle(c(core.ActionTransition), "frame", p.Binding(), "sealed"))
	obj, _ := r.Inspect("frame")
	saved := obj.CanonicalEvents
	stored, _ := s.Get("frame")
	stored.Attributes = map[string]string{"corrupt": "not an answer"}
	r = nil
	s = nil
	obj = nil
	return saved, resolver{p.Binding(): {p, b}}
}

func TestReconstructionUsesActualHistoryWithoutCache(t *testing.T) {
	h, res := history(t)
	tokens := []core.ObjectVersion{40, 77, 12, 97, 3, 58, 76}
	for i := range h {
		h[i].ResultingVersion = tokens[i]
	}
	key := types.Binding{Identity: h[0].TypeIdentity, Version: h[0].TypeVersion}
	def := res[key]
	reduce := def.b.Reduce
	calls := 0
	def.b.Reduce = func(before map[string]string, e types.StateEffect) (map[string]string, error) {
		calls++
		return reduce(before, e)
	}
	res[key] = def
	result, err := replay.Reconstruct(h, res)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(result.Attributes, map[string]string{"signal": "#final", "phase": "sealed"}) || len(result.Relationships) != 0 || result.ObjectVersion != 76 || result.ObservedVersionHighWater != 97 || calls != 5 {
		t.Fatalf("reconstruction %+v calls=%d", result, calls)
	}
	if !reflect.DeepEqual(result.CanonicalEvents, h) {
		t.Fatal("history rewritten or sorted")
	}
	result.Attributes["signal"] = "#vandal"
	result.CanonicalEvents[0].PostImage["signal"] = "#vandal"
	if h[0].PostImage["signal"] != "#initial" {
		t.Fatal("history alias")
	}
	for _, field := range []string{"GovernanceReference", "AuditRecords", "VersionHighWater", "Imports"} {
		if _, ok := reflect.TypeOf(*result).FieldByName(field); ok {
			t.Fatal("fabricated operational field", field)
		}
	}
}

func TestReconstructionRejectsMalformedHistories(t *testing.T) {
	base, res := history(t)
	for _, name := range []string{"missing-image", "invalid-image", "payload-mismatch", "from-mismatch", "second-create", "missing-create", "mixed-id", "mixed-binding", "duplicate-token", "zero-token", "unknown-effect", "duplicate-add", "absent-remove", "relationship-image"} {
		t.Run(name, func(t *testing.T) {
			data, _ := json.Marshal(base)
			var h []events.CanonicalEvent
			if json.Unmarshal(data, &h) != nil {
				t.Fatal("copy")
			}
			switch name {
			case "missing-image":
				h[1].PostImage = nil
			case "invalid-image":
				delete(h[1].PostImage, "signal")
			case "payload-mismatch":
				h[1].Payload["signal"] = "#contradiction"
			case "from-mismatch":
				h[2].Payload["from"] = "sealed"
			case "second-create":
				h[1].Kind = events.KindCreated
			case "missing-create":
				h = h[1:]
			case "mixed-id":
				h[1].CanonicalID = "other"
			case "mixed-binding":
				h[1].TypeVersion = "other"
			case "duplicate-token":
				h[1].ResultingVersion = h[0].ResultingVersion
			case "zero-token":
				h[1].ResultingVersion = 0
			case "unknown-effect":
				h[1].Kind = "unknown"
			case "duplicate-add":
				h[5].Kind = events.KindRelationshipAdded
			case "absent-remove":
				h[3].Kind = events.KindRelationshipRemoved
			case "relationship-image":
				h[3].PostImage = map[string]string{}
			}
			if _, err := replay.Reconstruct(h, res); err == nil {
				t.Fatal("malformed history accepted")
			}
		})
	}
	if _, err := replay.Reconstruct(base, nil); err == nil {
		t.Fatal("nil resolver")
	}
	if _, err := replay.Reconstruct(nil, res); err == nil {
		t.Fatal("empty history")
	}
	for i := range base {
		t.Run("unsupported-at-position-"+string(rune('1'+i)), func(t *testing.T) {
			h := append([]events.CanonicalEvent(nil), base...)
			h[i].TypeVersion = "unsupported"
			if _, err := replay.Reconstruct(h, res); err == nil {
				t.Fatal("unsupported binding interpreted")
			}
		})
	}
	for binding, def := range res {
		def.b.Reduce = nil
		res[binding] = def
	}
	if _, err := replay.Reconstruct(base, res); err == nil {
		t.Fatal("missing behavior")
	}
}

func TestEmptyImageNativeJSONAndIndependentMarker(t *testing.T) {
	zero := types.PortableType{Identity: "check.empty", Version: "z"}
	b, _ := types.NewPortableBehavior(zero)
	evt := events.CanonicalEvent{CanonicalID: "empty", TypeIdentity: zero.Identity, TypeVersion: zero.Version, Kind: events.KindCreated, ResultingVersion: 1, PostImage: map[string]string{}}
	data, _ := json.Marshal(evt)
	var restored events.CanonicalEvent
	if json.Unmarshal(data, &restored) != nil || restored.PostImage == nil {
		t.Fatal("present empty image lost")
	}
	result, err := replay.Reconstruct([]events.CanonicalEvent{restored}, resolver{zero.Binding(): {zero, b}})
	if err != nil || result.Attributes == nil {
		t.Fatal("zero-field reconstruction", err)
	}
	restored.PostImage = nil
	if _, err := replay.Reconstruct([]events.CanonicalEvent{restored}, resolver{zero.Binding(): {zero, b}}); err == nil {
		t.Fatal("absent image guessed")
	}
	m, mb := testtypes.Marker()
	e := events.CanonicalEvent{CanonicalID: "marker", TypeIdentity: m.Identity, TypeVersion: m.Version, Kind: events.KindCreated, ResultingVersion: 3, PostImage: map[string]string{"label": "point", "value": "12.3400"}}
	result, err = replay.Reconstruct([]events.CanonicalEvent{e}, resolver{m.Binding(): {m, mb}})
	if err != nil || result.Attributes["value"] != "12.3400" {
		t.Fatal("independent type reconstruction", err)
	}
}
