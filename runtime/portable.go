// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package runtime

import (
	"fmt"
	"maps"

	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/events"
	"github.com/governedobjects/governed-objects-go/internal/statefold"
	"github.com/governedobjects/governed-objects-go/store"
	"github.com/governedobjects/governed-objects-go/types"
)

// RegisterType installs one immutable exact definition/behavior per identity.
// Every duplicate identity, including the same binding, is rejected. Hooks are
// trusted pure nonreentrant code; mutable captures cannot be frozen by copying.
func (r *Runtime) RegisterType(t types.PortableType, b types.Behavior) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t = t.Clone()
	if err := t.Validate(); err != nil {
		return err
	}
	if !statefold.Complete(b) {
		return fmt.Errorf("all five behavior functions are required")
	}
	if _, ok := r.portable[t.Identity]; ok {
		return fmt.Errorf("type identity already registered")
	}
	if r.portable == nil {
		r.portable = make(map[core.TypeIdentity]types.PortableType)
		r.behaviors = make(map[core.TypeIdentity]types.Behavior)
	}
	r.portable[t.Identity] = t
	r.behaviors[t.Identity] = b
	return nil
}

func (r *Runtime) RegisterPortableType(t types.PortableType) error {
	b, err := types.NewPortableBehavior(t)
	if err != nil {
		return err
	}
	return r.RegisterType(t, b)
}

func (r *Runtime) PortableType(id core.TypeIdentity) (types.PortableType, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.portable[id]
	return t.Clone(), ok
}

func (r *Runtime) resolveType(binding types.Binding) (types.PortableType, types.Behavior, bool) {
	t, ok := r.portable[binding.Identity]
	b := r.behaviors[binding.Identity]
	if !ok || t.Binding() != binding || !statefold.Complete(b) {
		return types.PortableType{}, types.Behavior{}, false
	}
	return t, b, true
}

// ResolveType is a trusted administrative lookup, not an authorized endpoint.
func (r *Runtime) ResolveType(binding types.Binding) (types.PortableType, types.Behavior, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, b, ok := r.resolveType(binding)
	return t.Clone(), b, ok
}

func (r *Runtime) SetGovernance(refs map[types.Binding]core.GovernanceReference) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.governance = maps.Clone(refs)
}

func (r *Runtime) Inspect(id core.CanonicalIdentity) (*store.ObjectRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	obj, err := r.store.Snapshot(id)
	return obj, err == nil
}

func (r *Runtime) CreateObject(ctx core.OperationContext, id core.CanonicalIdentity, binding types.Binding, state map[string]string) (core.Outcome, *store.ObjectRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx = snapshotContext(ctx)
	out, obj := r.createObject(ctx, id, binding, maps.Clone(state))
	return r.disclose(ctx, id, out, obj)
}

func (r *Runtime) createObject(ctx core.OperationContext, id core.CanonicalIdentity, binding types.Binding, state map[string]string) (core.Outcome, *store.ObjectRecord) {
	if ctx.Action != core.ActionCreate {
		return core.Invalid(reasonExpectedCreate, 0), nil
	}
	if !r.authorizer.Allowed(ctx.Actor, core.ActionCreate, binding.Identity) {
		r.audit(id, "denied_create", reasonUnauthorized)
		return core.Denied(reasonUnauthorized, 0), nil
	}
	t, b, ok := r.resolveType(binding)
	if !ok {
		return core.Refused("unsupported binding", 0), nil
	}
	if _, exists := r.store.Get(id); exists {
		return core.Invalid(reasonExists, 0), nil
	}
	if id == "" {
		return core.Invalid("canonical identity is required", 0), nil
	}
	if err := statefold.ValidateState(t, b, state); err != nil {
		return core.Invalid(err.Error(), 0), nil
	}
	if err := b.ValidateCreate(maps.Clone(state)); err != nil {
		return core.Invalid(err.Error(), 0), nil
	}
	attrs, err := statefold.State(t, b, nil, types.StateEffect{Kind: events.KindCreated, PostImage: state})
	if err != nil {
		return core.Invalid(err.Error(), 0), nil
	}
	version := core.ObjectVersion(1)
	evt := r.newEvent(id, t.Identity, t.Version, events.KindCreated, version, ctx.Actor, nil)
	evt.PostImage = maps.Clone(attrs)
	obj := &store.ObjectRecord{CanonicalID: id, TypeIdentity: t.Identity, TypeVersion: t.Version, ObjectVersion: version, Attributes: maps.Clone(attrs), GovernanceReference: r.governance[binding], CanonicalEvents: []events.CanonicalEvent{evt}}
	r.store.Put(obj)
	return core.Accepted(version), obj
}

func (r *Runtime) UpdateState(ctx core.OperationContext, id core.CanonicalIdentity, binding types.Binding, set map[string]string) (core.Outcome, *store.ObjectRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx = snapshotContext(ctx)
	out, obj := r.mutateState(ctx, id, binding, maps.Clone(set), "", false)
	return r.disclose(ctx, id, out, obj)
}

func (r *Runtime) TransitionLifecycle(ctx core.OperationContext, id core.CanonicalIdentity, binding types.Binding, to string) (core.Outcome, *store.ObjectRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx = snapshotContext(ctx)
	out, obj := r.mutateState(ctx, id, binding, nil, to, true)
	return r.disclose(ctx, id, out, obj)
}

func (r *Runtime) mutateState(ctx core.OperationContext, id core.CanonicalIdentity, binding types.Binding, set map[string]string, to string, transition bool) (core.Outcome, *store.ObjectRecord) {
	action, denied, kind := core.ActionUpdate, "denied_update", events.KindStateUpdated
	if transition {
		action, denied, kind = core.ActionTransition, "denied_transition", events.KindLifecycleTransition
	}
	obj, out := r.target(ctx, id, action, denied)
	if out != nil {
		return *out, obj
	}
	if (types.Binding{Identity: obj.TypeIdentity, Version: obj.TypeVersion}) != binding {
		return core.Invalid("operation binding does not match object", obj.ObjectVersion), obj
	}
	if out = r.checkVersion(ctx, obj); out != nil {
		r.audit(id, "conflict", out.Reason)
		return *out, obj
	}
	t, b, _ := r.resolveType(binding)
	reject := func(err error) (core.Outcome, *store.ObjectRecord) {
		r.audit(id, "validation_denied", err.Error())
		return core.Invalid(err.Error(), obj.ObjectVersion), obj
	}
	if err := statefold.ValidateState(t, b, obj.Attributes); err != nil {
		return reject(err)
	}
	image := maps.Clone(obj.Attributes)
	payload := maps.Clone(set)
	if transition {
		field := t.LifecycleField()
		from := obj.Attributes[field]
		if err := t.ValidateLifecycleTransition(from, to); err != nil {
			return reject(err)
		}
		if err := b.ValidateTransition(maps.Clone(obj.Attributes), to); err != nil {
			return reject(err)
		}
		image[field] = to
		payload = map[string]string{"from": from, "to": to}
	} else {
		if err := t.ValidateUpdate(set); err != nil {
			return reject(err)
		}
		if err := b.ValidateUpdate(maps.Clone(obj.Attributes), maps.Clone(set)); err != nil {
			return reject(err)
		}
		for k, v := range set {
			image[k] = v
		}
	}
	after, err := statefold.State(t, b, obj.Attributes, types.StateEffect{Kind: kind, Payload: payload, PostImage: image})
	if err != nil {
		return reject(err)
	}
	v, refused := r.allocateVersion(obj)
	if refused != nil {
		r.audit(id, "refused", refused.Reason)
		return *refused, obj
	}
	obj.Attributes = maps.Clone(after)
	issueVersion(obj, v)
	evt := r.newEvent(id, obj.TypeIdentity, obj.TypeVersion, kind, v, ctx.Actor, maps.Clone(payload))
	evt.PostImage = maps.Clone(after)
	obj.CanonicalEvents = append(obj.CanonicalEvents, evt)
	r.store.Put(obj)
	return core.Accepted(v), obj
}

func copyMap(m map[string]string) map[string]string { return maps.Clone(m) }
