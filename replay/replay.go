// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

// Package replay reconstructs canonical content from accepted history only.
package replay

import (
	"fmt"
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/events"
	"github.com/governedobjects/governed-objects-go/internal/statefold"
	"github.com/governedobjects/governed-objects-go/types"
)

type Resolver interface {
	ResolveType(types.Binding) (types.PortableType, types.Behavior, bool)
}

// Result intentionally omits governance, audit, imports and allocation counters.
// ObservedVersionHighWater is only a lower bound, not a source-store watermark.
// This is not a ready-to-install persistence record or an admission API.
type Result struct {
	CanonicalID              core.CanonicalIdentity
	TypeIdentity             core.TypeIdentity
	TypeVersion              core.TypeVersion
	ObjectVersion            core.ObjectVersion
	Attributes               map[string]string
	Relationships            []core.Relationship
	CanonicalEvents          []events.CanonicalEvent
	ObservedVersionHighWater core.ObjectVersion
}

func Reconstruct(history []events.CanonicalEvent, resolver Resolver) (*Result, error) {
	if len(history) == 0 || resolver == nil {
		return nil, fmt.Errorf("replay requires history and resolver")
	}
	history = statefold.CloneHistory(history)
	first := history[0]
	if first.CanonicalID == "" || first.TypeIdentity == "" || first.TypeVersion == "" {
		return nil, fmt.Errorf("replay position 1: incomplete binding or identity")
	}
	result := &Result{CanonicalID: first.CanonicalID, TypeIdentity: first.TypeIdentity, TypeVersion: first.TypeVersion}
	seen := make(map[core.ObjectVersion]bool, len(history))
	for i, evt := range history {
		refuse := func(class string) (*Result, error) { return nil, fmt.Errorf("replay position %d: %s", i+1, class) }
		binding := types.Binding{Identity: evt.TypeIdentity, Version: evt.TypeVersion}
		t, b, ok := resolver.ResolveType(binding)
		if !ok || t.Binding() != binding || !statefold.Complete(b) {
			return refuse("unsupported binding or behavior")
		}
		t = t.Clone()
		if t.Validate() != nil {
			return refuse("invalid definition")
		}
		if evt.CanonicalID != first.CanonicalID || evt.TypeIdentity != first.TypeIdentity || evt.TypeVersion != first.TypeVersion {
			return refuse("inconsistent identity or binding")
		}
		if (i == 0) != (evt.Kind == events.KindCreated) {
			return refuse("creation must be exactly first")
		}
		if evt.ResultingVersion <= 0 || seen[evt.ResultingVersion] {
			return refuse("invalid or reused token")
		}
		seen[evt.ResultingVersion] = true
		switch evt.Kind {
		case events.KindCreated, events.KindStateUpdated, events.KindLifecycleTransition:
			state, err := statefold.State(t, b, result.Attributes, types.StateEffect{Kind: evt.Kind, Payload: evt.Payload, PostImage: evt.PostImage})
			if err != nil {
				return refuse("invalid state effect")
			}
			result.Attributes = state
		case events.KindRelationshipAdded, events.KindRelationshipRemoved:
			rels, err := statefold.Relationship(first.CanonicalID, result.Relationships, evt)
			if err != nil {
				return refuse("invalid relationship effect")
			}
			result.Relationships = rels
		default:
			return refuse("unknown effect")
		}
		result.ObjectVersion = evt.ResultingVersion
		if evt.ResultingVersion > result.ObservedVersionHighWater {
			result.ObservedVersionHighWater = evt.ResultingVersion
		}
	}
	result.CanonicalEvents = statefold.CloneHistory(history)
	return result, nil
}
