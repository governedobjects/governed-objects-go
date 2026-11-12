// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package main

// Suite-owned fixtures. The conformance suite defines every fixture type, actor and
// fixture rule the scenarios depend on (fixtures/fixtures.json in the suite) and sends
// the definitions in the define_fixture_types request. This file only implements
// those definitions through the Go runtime's public API; it defines no fixture rule of
// its own.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/governedobjects/governed-objects-go/auth"
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/runtime"
	"github.com/governedobjects/governed-objects-go/types"
)

type fixtureAction struct {
	Kind string   `json:"kind"`
	From []string `json:"from"`
	To   string   `json:"to"`
}

type fixtureRule struct {
	ID        string   `json:"id"`
	Field     string   `json:"field"`
	Rule      string   `json:"rule"`
	AppliesTo []string `json:"applies_to"`
}

type fixtureLifecycle struct {
	Field       string      `json:"field"`
	Initial     string      `json:"initial"`
	States      []string    `json:"states"`
	Transitions [][2]string `json:"transitions"`
}

type fixtureType struct {
	Version          string                   `json:"version"`
	Fields           map[string]string        `json:"fields"`
	RequiredOnCreate []string                 `json:"required_on_create"`
	Lifecycle        fixtureLifecycle         `json:"lifecycle"`
	CreateDefaults   map[string]string        `json:"create_defaults"`
	Relationships    []string                 `json:"relationship_types"`
	Actions          map[string]fixtureAction `json:"actions"`
	Rules            []fixtureRule            `json:"rules"`
}

type fixtureSet struct {
	Version string                 `json:"fixtures_version"`
	Actors  map[string][]string    `json:"actors"`
	Types   map[string]fixtureType `json:"types"`
}

// permissionCapability maps the suite's abstract permissions to the runtime's capabilities.
var permissionCapability = map[string]auth.Capability{
	"read":                auth.CapRead,
	"create":              auth.CapCreate,
	"update":              auth.CapUpdate,
	"transition":          auth.CapTransition,
	"add_relationship":    auth.CapAddRelationship,
	"remove_relationship": auth.CapRemoveRelationship,
	"import":              auth.CapImport,
}

var fieldKinds = map[string]types.FieldKind{
	"string":         types.FieldString,
	"decimal-string": types.FieldDecimal,
	"lifecycle":      types.FieldLifecycle,
}

func parseFixtures(raw json.RawMessage) (*fixtureSet, error) {
	var fx fixtureSet
	if err := json.Unmarshal(raw, &fx); err != nil {
		return nil, fmt.Errorf("fixture definitions: %v", err)
	}
	if len(fx.Types) == 0 {
		return nil, fmt.Errorf("fixture definitions declare no types")
	}
	for id, t := range fx.Types {
		for _, r := range t.Rules {
			if r.Rule != "non-blank-string" {
				return nil, fmt.Errorf("fixture %s rule %s: unsupported rule kind %q", id, r.ID, r.Rule)
			}
		}
		for _, k := range t.Fields {
			if _, ok := fieldKinds[k]; !ok {
				return nil, fmt.Errorf("fixture %s: unsupported field kind %q", id, k)
			}
		}
	}
	for actor, perms := range fx.Actors {
		for _, p := range perms {
			if _, ok := permissionCapability[p]; !ok {
				return nil, fmt.Errorf("actor %s: unknown permission %q", actor, p)
			}
		}
	}
	return &fx, nil
}

func (fx *fixtureSet) actorNames() []string {
	names := make([]string, 0, len(fx.Actors))
	for a := range fx.Actors {
		names = append(names, a)
	}
	sort.Strings(names)
	return names
}

func (fx *fixtureSet) typeIDs() []string {
	ids := make([]string, 0, len(fx.Types))
	for id := range fx.Types {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (t fixtureType) portable(id string) types.PortableType {
	fields := map[string]types.FieldKind{}
	for name, kind := range t.Fields {
		fields[name] = fieldKinds[kind]
	}
	actions := map[string]types.PortableAction{}
	for name, a := range t.Actions {
		pa := types.PortableAction{From: a.From, To: a.To}
		if a.Kind == "lifecycle" {
			pa.Kind = types.ActionKindLifecycle
		} else {
			pa.Kind = types.ActionKindState
		}
		actions[name] = pa
	}
	return types.PortableType{
		Identity:          core.TypeIdentity(id),
		Version:           core.TypeVersion(t.Version),
		Fields:            fields,
		LifecycleStates:   t.Lifecycle.States,
		Transitions:       t.Lifecycle.Transitions,
		RelationshipTypes: t.Relationships,
		Actions:           actions,
	}
}

func (t fixtureType) appliesTo(r fixtureRule, op string) bool {
	for _, a := range r.AppliesTo {
		if a == op {
			return true
		}
	}
	return false
}

func (t fixtureType) checkRules(op string, state map[string]string) error {
	for _, r := range t.Rules {
		if !t.appliesTo(r, op) {
			continue
		}
		if v, ok := state[r.Field]; ok && strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s: %s must not be blank", r.ID, r.Field)
		}
	}
	return nil
}

// register installs the type through the public Runtime.RegisterType API: the
// schema-only portable behavior plus the suite's fixture rules.
func (t fixtureType) register(rt *runtime.Runtime, id string) error {
	pt := t.portable(id)
	base, err := types.NewPortableBehavior(pt)
	if err != nil {
		return err
	}
	b := base
	b.ValidateCreate = func(state map[string]string) error {
		if err := base.ValidateCreate(state); err != nil {
			return err
		}
		for _, f := range t.RequiredOnCreate {
			if _, ok := state[f]; !ok {
				return fmt.Errorf("%s is required", f)
			}
		}
		return t.checkRules("create", state)
	}
	b.ValidateUpdate = func(before, set map[string]string) error {
		if err := base.ValidateUpdate(before, set); err != nil {
			return err
		}
		return t.checkRules("update", set)
	}
	return rt.RegisterType(pt, b)
}

// withDefaults fills create_defaults for fields the request did not supply.
func (t fixtureType) withDefaults(state map[string]string) map[string]string {
	for k, v := range t.CreateDefaults {
		if _, ok := state[k]; !ok {
			state[k] = v
		}
	}
	return state
}
