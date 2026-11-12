// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package auth

import "github.com/governedobjects/governed-objects-go/core"

// Capability names an authorized action on a type (AUTH-BASE-001).
type Capability string

const (
	CapRead               Capability = "read"
	CapUpdate             Capability = "update"
	CapTransition         Capability = "transition"
	CapAddRelationship    Capability = "add_relationship"
	CapRemoveRelationship Capability = "remove_relationship"
	CapCreate             Capability = "create"
	// CapImport grants privileged new-target interchange import
	// (EXPERIMENTAL).
	CapImport Capability = "import"
)

// Authorizer evaluates whether an actor may perform an action (AUTH-BASE-001).
type Authorizer interface {
	Allowed(actor core.Actor, action core.Action, typeID core.TypeIdentity) bool
}

// StaticAuthorizer is a simple capability map sufficient for Core exercise.
type StaticAuthorizer struct {
	grants map[core.Actor]map[Capability]bool
}

func NewStaticAuthorizer() *StaticAuthorizer {
	return NewGrantAuthorizer(nil)
}

// NewGrantAuthorizer builds a StaticAuthorizer from explicit grants
// (EXPERIMENTAL: fixture actors are configured
// out of band rather than hard-coded).
func NewGrantAuthorizer(grants map[core.Actor][]Capability) *StaticAuthorizer {
	out := make(map[core.Actor]map[Capability]bool, len(grants))
	for actor, caps := range grants {
		set := make(map[Capability]bool, len(caps))
		for _, c := range caps {
			set[c] = true
		}
		out[actor] = set
	}
	return &StaticAuthorizer{grants: out}
}

func (a *StaticAuthorizer) Allowed(actor core.Actor, action core.Action, _ core.TypeIdentity) bool {
	caps, ok := a.grants[actor]
	if !ok {
		return false
	}
	return caps[actionToCapability(action)]
}

func actionToCapability(action core.Action) Capability {
	switch action {
	case core.ActionCreate:
		return CapCreate
	case core.ActionRead:
		return CapRead
	case core.ActionUpdate:
		return CapUpdate
	case core.ActionTransition:
		return CapTransition
	case core.ActionAddRelationship:
		return CapAddRelationship
	case core.ActionRemoveRelationship:
		return CapRemoveRelationship
	case core.ActionImport:
		return CapImport
	default:
		return ""
	}
}
