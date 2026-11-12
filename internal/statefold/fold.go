// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

// Package statefold owns bounded accepted-effect validation and relationship
// set folding. It has no authority, runtime, store, or reference dependency.
package statefold

import (
	"fmt"
	"maps"
	"slices"

	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/events"
	"github.com/governedobjects/governed-objects-go/types"
)

// Complete reports whether every required hook is supplied.
func Complete(b types.Behavior) bool {
	return b.ValidateState != nil && b.ValidateCreate != nil && b.ValidateUpdate != nil && b.ValidateTransition != nil && b.Reduce != nil
}

// ValidateState constrains supplied behavior by the immutable schema. Each
// hook receives a fresh copy; its writes cannot redefine the checked state.
func ValidateState(t types.PortableType, b types.Behavior, state map[string]string) error {
	if !Complete(b) {
		return fmt.Errorf("missing behavior")
	}
	if state == nil {
		return fmt.Errorf("state is absent")
	}
	if err := t.ValidateCreateState(state); err != nil {
		return err
	}
	return b.ValidateState(maps.Clone(state))
}

// State folds one state effect with pristine comparison inputs. A missing
// image may be interpreted only by an explicitly supplied reducer (for
// example a privately selected legacy resolver); portable behavior refuses it.
// There is no built-in legacy, cached-state or latest-definition fallback.
func State(t types.PortableType, b types.Behavior, before map[string]string, effect types.StateEffect) (map[string]string, error) {
	if !Complete(b) {
		return nil, fmt.Errorf("missing behavior")
	}
	before = maps.Clone(before)
	image := maps.Clone(effect.PostImage)
	payload := maps.Clone(effect.Payload)
	if effect.Kind == events.KindCreated {
		if before != nil {
			return nil, fmt.Errorf("second creation")
		}
	} else {
		if effect.Kind != events.KindStateUpdated && effect.Kind != events.KindLifecycleTransition {
			return nil, fmt.Errorf("unknown state effect")
		}
		if err := ValidateState(t, b, before); err != nil {
			return nil, err
		}
	}
	if image != nil {
		if err := ValidateState(t, b, image); err != nil {
			return nil, err
		}
	}
	after, err := b.Reduce(maps.Clone(before), types.StateEffect{Kind: effect.Kind, Payload: maps.Clone(payload), PostImage: maps.Clone(image)})
	if err != nil {
		return nil, err
	}
	after = maps.Clone(after)
	if err := ValidateState(t, b, after); err != nil {
		return nil, err
	}
	if image != nil && !maps.Equal(image, after) {
		return nil, fmt.Errorf("reducer/image mismatch")
	}
	lc := t.LifecycleField()
	switch effect.Kind {
	case events.KindCreated:
		if err := b.ValidateCreate(maps.Clone(after)); err != nil {
			return nil, err
		}
		for k, v := range payload {
			if got, ok := after[k]; !ok || got != v {
				return nil, fmt.Errorf("creation payload mismatch")
			}
		}
	case events.KindStateUpdated:
		if lc != "" && before[lc] != after[lc] {
			return nil, fmt.Errorf("state effect changes lifecycle")
		}
		if payload != nil {
			for k, v := range payload {
				if err := t.ValidateUpdate(map[string]string{k: v}); err != nil {
					return nil, err
				}
				if after[k] != v {
					return nil, fmt.Errorf("state payload mismatch")
				}
			}
			for k, v := range after {
				if before[k] != v {
					if value, ok := payload[k]; !ok || value != v {
						return nil, fmt.Errorf("state change absent from payload")
					}
				}
			}
		}
	case events.KindLifecycleTransition:
		if err := t.ValidateLifecycleTransition(before[lc], after[lc]); err != nil {
			return nil, err
		}
		if payload != nil && (len(payload) != 2 || payload["from"] != before[lc] || payload["to"] != after[lc]) {
			return nil, fmt.Errorf("lifecycle payload mismatch")
		}
	}
	return after, nil
}

// Relationship folds accepted additions/removals, never ordinary no-ops.
// Duplicate accepted additions and absent accepted removals are refused.
func Relationship(id core.CanonicalIdentity, before []core.Relationship, evt events.CanonicalEvent) ([]core.Relationship, error) {
	if evt.CanonicalID != id || id == "" || evt.PostImage != nil || len(evt.Payload) != 2 {
		return nil, fmt.Errorf("malformed relationship effect")
	}
	rel := core.Relationship{Source: id, Type: core.RelationshipType(evt.Payload["relationship_type"]), Target: core.CanonicalIdentity(evt.Payload["target"])}
	if rel.Type == "" || rel.Target == "" {
		return nil, fmt.Errorf("incomplete relationship")
	}
	seen := make(map[core.Relationship]bool, len(before))
	idx := -1
	for i, prior := range before {
		if prior.Source != id || prior.Type == "" || prior.Target == "" || seen[prior] {
			return nil, fmt.Errorf("invalid relationship set")
		}
		seen[prior] = true
		if prior == rel {
			idx = i
		}
	}
	out := slices.Clone(before)
	switch evt.Kind {
	case events.KindRelationshipAdded:
		if idx >= 0 {
			return nil, fmt.Errorf("duplicate accepted addition")
		}
		return append(out, rel), nil
	case events.KindRelationshipRemoved:
		if idx < 0 {
			return nil, fmt.Errorf("absent accepted removal")
		}
		return append(out[:idx:idx], out[idx+1:]...), nil
	default:
		return nil, fmt.Errorf("unknown relationship effect")
	}
}

// CloneHistory preserves order, envelope fields, and nil/empty presence.
func CloneHistory(history []events.CanonicalEvent) []events.CanonicalEvent {
	out := slices.Clone(history)
	for i := range out {
		out[i].Payload = maps.Clone(out[i].Payload)
		out[i].PostImage = maps.Clone(out[i].PostImage)
	}
	return out
}
