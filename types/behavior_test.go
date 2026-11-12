// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package types_test

import (
	"errors"
	"maps"
	"reflect"
	"testing"

	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/events"
	"github.com/governedobjects/governed-objects-go/internal/statefold"
	"github.com/governedobjects/governed-objects-go/types"
)

func definition() types.PortableType {
	return types.PortableType{
		Identity: "check.signal-frame", Version: "a1",
		Fields:          map[string]types.FieldKind{"signal": types.FieldString, "phase": types.FieldLifecycle},
		LifecycleStates: []string{"idle", "sent"},
		Transitions:     [][2]string{{"idle", "sent"}, {"sent", "sent"}},
	}
}

func portable(t *testing.T, def types.PortableType) types.Behavior {
	t.Helper()
	b, err := types.NewPortableBehavior(def)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPortableBehaviorOwnsDefinition(t *testing.T) {
	def := definition()
	b := portable(t, def)
	def.Fields["signal"] = types.FieldDecimal
	def.LifecycleStates[0] = "vandalized"
	def.Transitions[0] = [2]string{"sent", "idle"}
	state := map[string]string{"signal": "  retained  ", "phase": "idle"}
	if err := b.ValidateCreate(state); err != nil {
		t.Fatal(err)
	}
	if err := b.ValidateTransition(state, "sent"); err != nil {
		t.Fatal(err)
	}
	if state["signal"] != "  retained  " {
		t.Fatal("content normalized")
	}
}

func TestPortableBehaviorRejectsInvalidDefinition(t *testing.T) {
	for _, def := range []types.PortableType{
		{},
		{Identity: "test", Version: "1", Fields: map[string]types.FieldKind{"bad": "nested"}},
		{Identity: "test", Version: "1", LifecycleStates: []string{"unused"}},
	} {
		if _, err := types.NewPortableBehavior(def); err == nil {
			t.Fatal("invalid definition accepted")
		}
	}
}

func TestPortableBehaviorPresenceAndDecimalLexicalValues(t *testing.T) {
	def := types.PortableType{Identity: "check.scalar-marker", Version: "b7", Fields: map[string]types.FieldKind{"value": types.FieldDecimal}}
	b := portable(t, def)
	for _, value := range []string{"0", "01", "-0.00", "12.3400"} {
		state := map[string]string{"value": value}
		after, err := statefold.State(def, b, nil, types.StateEffect{Kind: events.KindCreated, PostImage: state})
		if err != nil || after["value"] != value {
			t.Fatalf("lexical value %q: %v %v", value, after, err)
		}
	}
	for _, value := range []string{"", "1e2", "NaN", "1.", ".1", " 1"} {
		if err := b.ValidateCreate(map[string]string{"value": value}); err == nil {
			t.Fatalf("invalid decimal %q", value)
		}
	}
	if err := b.ValidateTransition(map[string]string{"value": "1"}, "sent"); err == nil {
		t.Fatal("no-lifecycle type accepted transition")
	}
	zero := types.PortableType{Identity: "check.empty", Version: "1"}
	zb := portable(t, zero)
	for _, state := range []map[string]string{nil, {}} {
		after, err := statefold.State(zero, zb, nil, types.StateEffect{Kind: events.KindCreated, PostImage: state})
		if state == nil {
			if err == nil {
				t.Fatal("absent state accepted as empty")
			}
		} else if err != nil || after == nil || len(after) != 0 {
			t.Fatalf("present empty state lost: %v %v", after, err)
		}
	}
}

func TestPortableAcceptedEffectsRemainDistinctFromCommands(t *testing.T) {
	def := definition()
	b := portable(t, def)
	before := map[string]string{"signal": "old", "phase": "idle"}
	if err := b.ValidateUpdate(before, map[string]string{}); err == nil {
		t.Fatal("empty ordinary update accepted")
	}
	if _, err := statefold.State(def, b, before, types.StateEffect{Kind: events.KindStateUpdated, Payload: map[string]string{}, PostImage: maps.Clone(before)}); err != nil {
		t.Fatalf("accepted same-state effect rejected: %v", err)
	}
	// Historical portable admission permits this full lifecycle image, though
	// the ordinary lifecycle method will construct an image changing phase only.
	after, err := statefold.State(def, b, before, types.StateEffect{
		Kind:      events.KindLifecycleTransition,
		Payload:   map[string]string{"from": "idle", "to": "sent"},
		PostImage: map[string]string{"signal": "new", "phase": "sent"},
	})
	if err != nil || after["signal"] != "new" {
		t.Fatalf("portable accepted semantics tightened: %v %v", after, err)
	}
	// No initial lifecycle is imposed by the schema-only convenience.
	if _, err := statefold.State(def, b, nil, types.StateEffect{Kind: events.KindCreated, PostImage: after}); err != nil {
		t.Fatal(err)
	}
	if err := b.ValidateCreate(map[string]string{"signal": "", "phase": "idle"}); err != nil {
		t.Fatal("schema-only behavior added a blank-string domain constraint")
	}
}

func TestPortableMalformedEffectsRefuse(t *testing.T) {
	def := definition()
	b := portable(t, def)
	before := map[string]string{"signal": "old", "phase": "idle"}
	good := map[string]string{"signal": "new", "phase": "idle"}
	cases := []struct {
		name   string
		before map[string]string
		effect types.StateEffect
	}{
		{"missing-image", nil, types.StateEffect{Kind: events.KindCreated}},
		{"missing-field", nil, types.StateEffect{Kind: events.KindCreated, PostImage: map[string]string{"signal": "x"}}},
		{"unknown-field", nil, types.StateEffect{Kind: events.KindCreated, PostImage: map[string]string{"signal": "x", "phase": "idle", "other": "x"}}},
		{"unknown-lifecycle", nil, types.StateEffect{Kind: events.KindCreated, PostImage: map[string]string{"signal": "x", "phase": "unknown"}}},
		{"second-create", before, types.StateEffect{Kind: events.KindCreated, PostImage: good}},
		{"no-baseline", nil, types.StateEffect{Kind: events.KindStateUpdated, PostImage: good}},
		{"create-payload", nil, types.StateEffect{Kind: events.KindCreated, PostImage: good, Payload: map[string]string{"signal": "other"}}},
		{"create-unknown-payload", nil, types.StateEffect{Kind: events.KindCreated, PostImage: good, Payload: map[string]string{"other": ""}}},
		{"update-payload", before, types.StateEffect{Kind: events.KindStateUpdated, PostImage: good, Payload: map[string]string{"signal": "other"}}},
		{"update-unexplained", before, types.StateEffect{Kind: events.KindStateUpdated, PostImage: good, Payload: map[string]string{}}},
		{"update-lifecycle", before, types.StateEffect{Kind: events.KindStateUpdated, PostImage: map[string]string{"signal": "old", "phase": "sent"}}},
		{"update-lifecycle-in-payload", before, types.StateEffect{Kind: events.KindStateUpdated, PostImage: before, Payload: map[string]string{"phase": "idle"}}},
		{"lifecycle-from", before, types.StateEffect{Kind: events.KindLifecycleTransition, PostImage: map[string]string{"signal": "old", "phase": "sent"}, Payload: map[string]string{"from": "sent", "to": "sent"}}},
		{"lifecycle-extra", before, types.StateEffect{Kind: events.KindLifecycleTransition, PostImage: map[string]string{"signal": "old", "phase": "sent"}, Payload: map[string]string{"from": "idle", "to": "sent", "other": "x"}}},
		{"unknown-effect", before, types.StateEffect{Kind: "unknown", PostImage: good}},
		{"relationship-as-state", before, types.StateEffect{Kind: events.KindRelationshipAdded, PostImage: good}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pristineBefore, pristineImage, pristinePayload := maps.Clone(tc.before), maps.Clone(tc.effect.PostImage), maps.Clone(tc.effect.Payload)
			if _, err := statefold.State(def, b, tc.before, tc.effect); err == nil {
				t.Fatal("malformed effect accepted")
			}
			if !reflect.DeepEqual(tc.before, pristineBefore) || !reflect.DeepEqual(tc.effect.PostImage, pristineImage) || !reflect.DeepEqual(tc.effect.Payload, pristinePayload) {
				t.Fatal("refusal changed input")
			}
		})
	}
}

func TestFoldConstrainsSuppliedBehaviorAndCopiesCallbacks(t *testing.T) {
	def := definition()
	base := portable(t, def)
	image := map[string]string{"signal": "new", "phase": "idle"}
	before := map[string]string{"signal": "old", "phase": "idle"}
	var retained map[string]string
	b := base
	b.ValidateState = func(s map[string]string) error { s["signal"] = "vandalized"; return nil }
	b.ValidateCreate = func(s map[string]string) error { s["signal"] = "vandalized"; return nil }
	b.Reduce = func(prior map[string]string, e types.StateEffect) (map[string]string, error) {
		prior["signal"] = "vandalized"
		e.Payload["signal"] = "vandalized"
		retained = e.PostImage
		return e.PostImage, nil
	}
	after, err := statefold.State(def, b, before, types.StateEffect{Kind: events.KindStateUpdated, PostImage: image, Payload: map[string]string{"signal": "new"}})
	if err != nil || after["signal"] != "new" || before["signal"] != "old" || image["signal"] != "new" {
		t.Fatalf("callback ownership failure: %v %v", after, err)
	}
	retained["signal"] = "late"
	if after["signal"] != "new" {
		t.Fatal("returned reducer alias retained")
	}
	for _, mode := range []string{"mismatch", "nil", "bad-schema", "error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			b := base
			b.Reduce = func(prior map[string]string, e types.StateEffect) (map[string]string, error) {
				prior["signal"] = "vandalized"
				e.PostImage["signal"] = "vandalized"
				switch mode {
				case "nil":
					return nil, nil
				case "bad-schema":
					return map[string]string{"signal": "vandalized"}, nil
				case "error":
					return nil, errors.New("private callback detail")
				case "panic":
					panic("trusted extension defect")
				default:
					return e.PostImage, nil
				}
			}
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				if _, err := statefold.State(def, b, before, types.StateEffect{Kind: events.KindStateUpdated, PostImage: image}); err == nil {
					t.Error("invalid callback result accepted")
				}
			}()
			if panicked != (mode == "panic") || before["signal"] != "old" || image["signal"] != "new" {
				t.Fatal("panic or input ownership contract violated")
			}
		})
	}
	// A permissive callback cannot waive the immutable schema or lifecycle.
	b = base
	b.ValidateState = func(map[string]string) error { return nil }
	b.Reduce = func(_ map[string]string, e types.StateEffect) (map[string]string, error) { return e.PostImage, nil }
	if _, err := statefold.State(def, b, before, types.StateEffect{Kind: events.KindStateUpdated, PostImage: map[string]string{"signal": "new", "phase": "sent"}}); err == nil {
		t.Fatal("supplied behavior bypassed lifecycle constraint")
	}
}

func TestFoldRequiresEveryHook(t *testing.T) {
	def := definition()
	for i := 0; i < 5; i++ {
		b := portable(t, def)
		switch i {
		case 0:
			b.ValidateState = nil
		case 1:
			b.ValidateCreate = nil
		case 2:
			b.ValidateUpdate = nil
		case 3:
			b.ValidateTransition = nil
		case 4:
			b.Reduce = nil
		}
		if statefold.Complete(b) {
			t.Fatal("missing hook accepted")
		}
		if _, err := statefold.State(def, b, nil, types.StateEffect{Kind: events.KindCreated, PostImage: map[string]string{"signal": "x", "phase": "idle"}}); err == nil {
			t.Fatal("incomplete behavior interpreted state")
		}
	}
}

func TestAcceptedRelationshipFold(t *testing.T) {
	id := core.CanonicalIdentity("frame-1")
	e := events.CanonicalEvent{CanonicalID: id, Kind: events.KindRelationshipAdded, Payload: map[string]string{"relationship_type": "links", "target": "absent-target"}}
	rels, err := statefold.Relationship(id, nil, e)
	if err != nil || len(rels) != 1 || rels[0].Target != "absent-target" {
		t.Fatalf("addition: %v %v", rels, err)
	}
	if _, err := statefold.Relationship(id, rels, e); err == nil {
		t.Fatal("accepted duplicate addition deduplicated")
	}
	e.Kind = events.KindRelationshipRemoved
	removed, err := statefold.Relationship(id, rels, e)
	if err != nil || len(removed) != 0 || len(rels) != 1 {
		t.Fatalf("removal ownership: %v %v", removed, err)
	}
	if _, err := statefold.Relationship(id, removed, e); err == nil {
		t.Fatal("accepted absent removal ignored")
	}
	for _, bad := range []events.CanonicalEvent{
		{CanonicalID: "other", Kind: events.KindRelationshipAdded, Payload: e.Payload},
		{CanonicalID: id, Kind: events.KindRelationshipAdded, Payload: e.Payload, PostImage: map[string]string{}},
		{CanonicalID: id, Kind: events.KindRelationshipAdded, Payload: map[string]string{"relationship_type": "links"}},
		{CanonicalID: id, Kind: events.KindRelationshipAdded, Payload: map[string]string{"relationship_type": "links", "target": ""}},
		{CanonicalID: id, Kind: "unknown", Payload: e.Payload},
	} {
		if _, err := statefold.Relationship(id, nil, bad); err == nil {
			t.Fatal("malformed relationship accepted")
		}
	}
	if _, err := statefold.Relationship(id, append(rels, rels...), e); err == nil {
		t.Fatal("multiset baseline accepted")
	}
}

func TestHistoryClonePreservesPresenceAndOwnership(t *testing.T) {
	history := []events.CanonicalEvent{{PostImage: nil}, {PostImage: map[string]string{}, Payload: map[string]string{}}, {PostImage: map[string]string{"value": "x"}}}
	copy := statefold.CloneHistory(history)
	if copy[0].PostImage != nil || copy[1].PostImage == nil || copy[1].Payload == nil {
		t.Fatal("presence lost")
	}
	copy[1].Payload["other"] = "x"
	copy[2].PostImage["value"] = "changed"
	if len(history[1].Payload) != 0 || history[2].PostImage["value"] != "x" {
		t.Fatal("history alias")
	}
	if statefold.CloneHistory(nil) != nil || statefold.CloneHistory([]events.CanonicalEvent{}) == nil {
		t.Fatal("slice presence lost")
	}
}
