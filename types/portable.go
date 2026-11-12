// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package types

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"

	"github.com/governedobjects/governed-objects-go/core"
)

// EXPERIMENTAL. Declarative portable Core
// types in the shape of the conformance suite's fixture type definitions, so
// fixture objects run under their exact Type Identity and Type Version strings
// with no type mapping.

// FieldKind is the kind of a portable state field.
type FieldKind string

const (
	FieldString    FieldKind = "string"
	FieldDecimal   FieldKind = "decimal-string"
	FieldLifecycle FieldKind = "lifecycle"
)

// ActionKind classifies a type-declared action.
type ActionKind string

const (
	ActionKindState     ActionKind = "state"
	ActionKindLifecycle ActionKind = "lifecycle"
)

// PortableAction is a type-declared action. Lifecycle actions name their
// permitted source states and their target.
type PortableAction struct {
	Kind ActionKind `json:"kind"`
	From []string   `json:"from,omitempty"`
	To   string     `json:"to,omitempty"`
}

// Binding is a (Type Identity, Type Version) pair.
type Binding struct {
	Identity core.TypeIdentity
	Version  core.TypeVersion
}

// PortableType is a declarative type whose Accepted Canonical State is a
// flat map of string fields; the lifecycle field (if any) holds the
// lifecycle state.
type PortableType struct {
	Identity          core.TypeIdentity
	Version           core.TypeVersion
	Fields            map[string]FieldKind
	LifecycleStates   []string
	Transitions       [][2]string
	RelationshipTypes []string
	Actions           map[string]PortableAction
}

var decimalPattern = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`)

func (t PortableType) Binding() Binding { return Binding{t.Identity, t.Version} }

// Clone returns a copy of t sharing no map or slice with it.
func (t PortableType) Clone() PortableType {
	t.Fields = maps.Clone(t.Fields)
	t.LifecycleStates = slices.Clone(t.LifecycleStates)
	t.Transitions = slices.Clone(t.Transitions)
	t.RelationshipTypes = slices.Clone(t.RelationshipTypes)
	if t.Actions != nil {
		actions := make(map[string]PortableAction, len(t.Actions))
		for name, a := range t.Actions {
			a.From = slices.Clone(a.From)
			actions[name] = a
		}
		t.Actions = actions
	}
	return t
}

// LifecycleField returns the lifecycle field name, or "" when the type has
// no lifecycle.
func (t PortableType) LifecycleField() string {
	for name, kind := range t.Fields {
		if kind == FieldLifecycle {
			return name
		}
	}
	return ""
}

// Validate checks the definition itself.
func (t PortableType) Validate() error {
	if t.Identity == "" || t.Version == "" {
		return fmt.Errorf("portable type requires identity and version")
	}
	lifecycleFields := 0
	for name, kind := range t.Fields {
		switch kind {
		case FieldString, FieldDecimal:
		case FieldLifecycle:
			lifecycleFields++
		default:
			return fmt.Errorf("field %q: unsupported kind %q", name, kind)
		}
	}
	if lifecycleFields > 1 {
		return fmt.Errorf("more than one lifecycle field")
	}
	if lifecycleFields == 0 && (len(t.LifecycleStates) > 0 || len(t.Transitions) > 0) {
		return fmt.Errorf("lifecycle states declared without a lifecycle field")
	}
	for _, tr := range t.Transitions {
		if !t.isState(tr[0]) || !t.isState(tr[1]) {
			return fmt.Errorf("transition %v uses an undeclared state", tr)
		}
	}
	for name, a := range t.Actions {
		switch a.Kind {
		case ActionKindState:
		case ActionKindLifecycle:
			for _, from := range a.From {
				if !t.TransitionPermitted(from, a.To) {
					return fmt.Errorf("action %q %s->%s is not a declared transition", name, from, a.To)
				}
			}
		default:
			return fmt.Errorf("action %q: unsupported kind %q", name, a.Kind)
		}
	}
	return nil
}

func (t PortableType) isState(s string) bool {
	for _, st := range t.LifecycleStates {
		if st == s {
			return true
		}
	}
	return false
}

// TransitionPermitted reports whether from -> to is a declared transition.
func (t PortableType) TransitionPermitted(from, to string) bool {
	for _, tr := range t.Transitions {
		if tr[0] == from && tr[1] == to {
			return true
		}
	}
	return false
}

// ValidateCreateState requires every declared field, no others, string
// values, decimal shape for decimal fields, and a declared lifecycle state.
func (t PortableType) ValidateCreateState(state map[string]string) error {
	for _, name := range sortedKeys(state) {
		if _, ok := t.Fields[name]; !ok {
			return fmt.Errorf("unknown field %q", name)
		}
	}
	for _, name := range sortedFieldNames(t.Fields) {
		value, ok := state[name]
		if !ok {
			return fmt.Errorf("missing declared field %q", name)
		}
		if err := t.checkValue(name, value); err != nil {
			return err
		}
	}
	return nil
}

// ValidateUpdate requires a non-empty subset of non-lifecycle fields.
func (t PortableType) ValidateUpdate(set map[string]string) error {
	if len(set) == 0 {
		return fmt.Errorf("state update requires at least one field")
	}
	for _, name := range sortedKeys(set) {
		kind, ok := t.Fields[name]
		if !ok {
			return fmt.Errorf("unknown field %q", name)
		}
		if kind == FieldLifecycle {
			return fmt.Errorf("field %q is changed only by lifecycle transition", name)
		}
		if err := t.checkValue(name, set[name]); err != nil {
			return err
		}
	}
	return nil
}

// ValidateLifecycleTransition checks a lifecycle move.
func (t PortableType) ValidateLifecycleTransition(from, to string) error {
	if t.LifecycleField() == "" {
		return fmt.Errorf("type %s has no lifecycle", t.Identity)
	}
	if !t.isState(to) {
		return fmt.Errorf("invalid lifecycle state %q", to)
	}
	if !t.TransitionPermitted(from, to) {
		return fmt.Errorf("invalid transition from %q to %q", from, to)
	}
	return nil
}

func (t PortableType) checkValue(name, value string) error {
	switch t.Fields[name] {
	case FieldDecimal:
		if !decimalPattern.MatchString(value) {
			return fmt.Errorf("field %q is not a decimal string", name)
		}
	case FieldLifecycle:
		if !t.isState(value) {
			return fmt.Errorf("field %q value %q is not a declared lifecycle state", name, value)
		}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedFieldNames(m map[string]FieldKind) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
