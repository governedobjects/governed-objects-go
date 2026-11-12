// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package types

import (
	"fmt"
	"maps"

	"github.com/governedobjects/governed-objects-go/events"
)

// StateEffect describes an already-accepted state effect, not a command or
// authority, allocation, storage, or operational metadata.
type StateEffect struct {
	Kind      events.Kind
	Payload   map[string]string
	PostImage map[string]string
}

// Behavior supplies exact bounded type semantics. Every function is required.
// Hooks are trusted, pure, nonreentrant and must not perform I/O or retain
// mutable arguments. Callers remain responsible for mutable closure captures.
type Behavior struct {
	ValidateState      func(state map[string]string) error
	ValidateCreate     func(state map[string]string) error
	ValidateUpdate     func(before, set map[string]string) error
	ValidateTransition func(before map[string]string, to string) error
	Reduce             func(before map[string]string, effect StateEffect) (map[string]string, error)
}

// NewPortableBehavior explicitly selects the bounded schema-only semantics.
// It adds no domain constraints, authority, baseline lifecycle, or defaults.
// Accepted lifecycle effects may also change non-lifecycle fields; ordinary
// lifecycle commands construct a narrower image. Reducing history is not
// re-executing ordinary commands.
func NewPortableBehavior(t PortableType) (Behavior, error) {
	t = t.Clone()
	if err := t.Validate(); err != nil {
		return Behavior{}, err
	}
	validate := func(state map[string]string) error {
		if state == nil {
			return fmt.Errorf("state is absent")
		}
		return t.ValidateCreateState(state)
	}
	return Behavior{
		ValidateState:  validate,
		ValidateCreate: validate,
		ValidateUpdate: func(before, set map[string]string) error {
			if err := validate(before); err != nil {
				return err
			}
			return t.ValidateUpdate(set)
		},
		ValidateTransition: func(before map[string]string, to string) error {
			if err := validate(before); err != nil {
				return err
			}
			return t.ValidateLifecycleTransition(before[t.LifecycleField()], to)
		},
		Reduce: func(before map[string]string, effect StateEffect) (map[string]string, error) {
			if err := validate(effect.PostImage); err != nil {
				return nil, err
			}
			after := effect.PostImage
			lc := t.LifecycleField()
			switch effect.Kind {
			case events.KindCreated:
				if before != nil {
					return nil, fmt.Errorf("creation after baseline")
				}
				for k, v := range effect.Payload {
					if got, ok := after[k]; !ok || got != v {
						return nil, fmt.Errorf("creation payload/image mismatch")
					}
				}
			case events.KindStateUpdated:
				if err := validate(before); err != nil {
					return nil, err
				}
				if lc != "" && before[lc] != after[lc] {
					return nil, fmt.Errorf("state effect changes lifecycle")
				}
				if effect.Payload != nil {
					// An empty payload is valid for an accepted same-state revision.
					for k, v := range effect.Payload {
						if err := t.ValidateUpdate(map[string]string{k: v}); err != nil {
							return nil, err
						}
						if after[k] != v {
							return nil, fmt.Errorf("state payload/image mismatch")
						}
					}
					for k, v := range after {
						if before[k] != v {
							if value, ok := effect.Payload[k]; !ok || value != v {
								return nil, fmt.Errorf("state change absent from payload")
							}
						}
					}
				}
			case events.KindLifecycleTransition:
				if err := validate(before); err != nil {
					return nil, err
				}
				if err := t.ValidateLifecycleTransition(before[lc], after[lc]); err != nil {
					return nil, err
				}
				if effect.Payload != nil && (len(effect.Payload) != 2 || effect.Payload["from"] != before[lc] || effect.Payload["to"] != after[lc]) {
					return nil, fmt.Errorf("lifecycle payload/image mismatch")
				}
			default:
				return nil, fmt.Errorf("not a state effect")
			}
			return maps.Clone(after), nil
		},
	}, nil
}
