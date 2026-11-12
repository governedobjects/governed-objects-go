// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package runtime

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/governedobjects/governed-objects-go/auth"
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/events"
	"github.com/governedobjects/governed-objects-go/internal/statefold"
	"github.com/governedobjects/governed-objects-go/store"
	"github.com/governedobjects/governed-objects-go/types"
)

// Runtime serializes evaluation and commit within one instance. Store and
// Authorizer must be nonnil trusted integrations. No types or actors are
// installed by construction. Hooks must be pure and must not reenter Runtime.
type Runtime struct {
	mu         sync.Mutex
	store      *store.MemoryStore
	authorizer auth.Authorizer
	portable   map[core.TypeIdentity]types.PortableType
	behaviors  map[core.TypeIdentity]types.Behavior
	governance map[types.Binding]core.GovernanceReference
}

const (
	reasonUnauthorized    = "unauthorized"
	reasonStale           = "stale object version"
	reasonNotFound        = "object not found"
	reasonExists          = "object already exists"
	reasonExpectedCreate  = "expected create action"
	reasonRelationshipSrc = "relationship source must match object"
	reasonRelationshipReq = "relationship requires type and target"
	reasonInvalid         = "invalid request"
	reasonRefused         = "refused"
)

var contentFreeReasons = map[string]bool{
	reasonUnauthorized: true, reasonStale: true, reasonNotFound: true,
	reasonExists: true, reasonExpectedCreate: true, reasonRelationshipSrc: true,
	reasonRelationshipReq: true,
}

func NewRuntime(s *store.MemoryStore, a auth.Authorizer) *Runtime {
	return &Runtime{store: s, authorizer: a}
}

func snapshotContext(ctx core.OperationContext) core.OperationContext {
	if ctx.ExpectedVersion != nil {
		v := *ctx.ExpectedVersion
		ctx.ExpectedVersion = &v
	}
	return ctx
}

// Exact support must precede type-ID permission when deciding disclosure.
// Accepted writer-without-read results retain the existing contract.
func (r *Runtime) disclose(ctx core.OperationContext, id core.CanonicalIdentity, out core.Outcome, obj *store.ObjectRecord) (core.Outcome, *store.ObjectRecord) {
	if out.Kind == core.OutcomeAccepted {
		return out, obj.Clone()
	}
	target, exists := r.store.Get(id)
	if !exists {
		return out, obj.Clone()
	}
	_, _, supported := r.resolveType(types.Binding{Identity: target.TypeIdentity, Version: target.TypeVersion})
	if supported && r.authorizer.Allowed(ctx.Actor, core.ActionRead, target.TypeIdentity) {
		return out, obj.Clone()
	}
	reason := out.Reason
	if !contentFreeReasons[reason] {
		switch out.Kind {
		case core.OutcomeDenied:
			reason = reasonUnauthorized
		case core.OutcomeConflict:
			reason = reasonStale
		case core.OutcomeRefused:
			reason = reasonRefused
		default:
			reason = reasonInvalid
		}
	}
	return core.Outcome{Kind: out.Kind, Reason: reason}, nil
}

func (r *Runtime) Read(ctx core.OperationContext, id core.CanonicalIdentity) (core.Outcome, *store.ObjectRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	obj, ok := r.store.Get(id)
	if !ok {
		return core.Invalid(reasonNotFound, 0), nil
	}
	allowed := r.authorizer.Allowed(ctx.Actor, core.ActionRead, obj.TypeIdentity)
	_, _, supported := r.resolveType(types.Binding{Identity: obj.TypeIdentity, Version: obj.TypeVersion})
	if !allowed || !supported {
		r.audit(id, "denied_read", reasonUnauthorized)
		return core.Denied(reasonUnauthorized, 0), nil
	}
	return core.Accepted(obj.ObjectVersion), obj.Clone()
}

// target checks method-routed authority before protected support/state/token
// checks. Detached candidates never alias canonical storage during evaluation.
func (r *Runtime) target(ctx core.OperationContext, id core.CanonicalIdentity, action core.Action, deniedKind string) (*store.ObjectRecord, *core.Outcome) {
	obj, ok := r.store.Get(id)
	if !ok {
		out := core.Invalid(reasonNotFound, 0)
		return nil, &out
	}
	if !r.authorizer.Allowed(ctx.Actor, action, obj.TypeIdentity) {
		r.audit(id, deniedKind, fmt.Sprintf("actor %q unauthorized", ctx.Actor))
		out := core.Denied(reasonUnauthorized, obj.ObjectVersion)
		return obj, &out
	}
	if _, _, ok := r.resolveType(types.Binding{Identity: obj.TypeIdentity, Version: obj.TypeVersion}); !ok {
		out := core.Refused("unsupported binding", obj.ObjectVersion)
		return obj, &out
	}
	return obj.Clone(), nil
}

func (r *Runtime) AddRelationship(ctx core.OperationContext, id core.CanonicalIdentity, rel core.Relationship) (core.Outcome, *store.ObjectRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx = snapshotContext(ctx)
	out, obj := r.relationship(ctx, id, rel, true)
	return r.disclose(ctx, id, out, obj)
}

func (r *Runtime) RemoveRelationship(ctx core.OperationContext, id core.CanonicalIdentity, rel core.Relationship) (core.Outcome, *store.ObjectRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx = snapshotContext(ctx)
	out, obj := r.relationship(ctx, id, rel, false)
	return r.disclose(ctx, id, out, obj)
}

func (r *Runtime) relationship(ctx core.OperationContext, id core.CanonicalIdentity, rel core.Relationship, add bool) (core.Outcome, *store.ObjectRecord) {
	action, denied, kind := core.ActionRemoveRelationship, "denied_relationship_remove", events.KindRelationshipRemoved
	if add {
		action, denied, kind = core.ActionAddRelationship, "denied_relationship", events.KindRelationshipAdded
	}
	obj, out := r.target(ctx, id, action, denied)
	if out != nil {
		return *out, obj
	}
	if out = r.checkVersion(ctx, obj); out != nil {
		r.audit(id, "conflict", out.Reason)
		return *out, obj
	}
	if rel.Source != id {
		return core.Invalid(reasonRelationshipSrc, obj.ObjectVersion), obj
	}
	if rel.Type == "" || rel.Target == "" {
		return core.Invalid(reasonRelationshipReq, obj.ObjectVersion), obj
	}
	idx := relationshipIndex(obj.Relationships, rel.Type, rel.Target)
	if (add && idx >= 0) || (!add && idx < 0) {
		return core.Accepted(obj.ObjectVersion), obj
	}
	payload := map[string]string{"relationship_type": string(rel.Type), "target": string(rel.Target)}
	rels, err := statefold.Relationship(id, obj.Relationships, events.CanonicalEvent{CanonicalID: id, Kind: kind, Payload: payload})
	if err != nil {
		return core.Invalid(err.Error(), obj.ObjectVersion), obj
	}
	v, refused := r.allocateVersion(obj)
	if refused != nil {
		r.audit(id, "refused", refused.Reason)
		return *refused, obj
	}
	obj.Relationships = rels
	issueVersion(obj, v)
	obj.CanonicalEvents = append(obj.CanonicalEvents, r.newEvent(id, obj.TypeIdentity, obj.TypeVersion, kind, v, ctx.Actor, payload))
	r.store.Put(obj)
	return core.Accepted(v), obj
}

func relationshipIndex(rels []core.Relationship, t core.RelationshipType, target core.CanonicalIdentity) int {
	for i, rel := range rels {
		if rel.Type == t && rel.Target == target {
			return i
		}
	}
	return -1
}

func (r *Runtime) allocateVersion(obj *store.ObjectRecord) (core.ObjectVersion, *core.Outcome) {
	top := obj.ObjectVersion
	if obj.VersionHighWater > top {
		top = obj.VersionHighWater
	}
	if top == math.MaxInt64 {
		out := core.Refused(core.ReasonObjectVersionSpaceExhausted, obj.ObjectVersion)
		return 0, &out
	}
	return top + 1, nil
}

func issueVersion(obj *store.ObjectRecord, v core.ObjectVersion) {
	obj.ObjectVersion = v
	obj.VersionHighWater = v
}

func (r *Runtime) checkVersion(ctx core.OperationContext, obj *store.ObjectRecord) *core.Outcome {
	if ctx.ExpectedVersion != nil && *ctx.ExpectedVersion != obj.ObjectVersion {
		out := core.Conflict(reasonStale, obj.ObjectVersion)
		return &out
	}
	return nil
}

func (r *Runtime) newEvent(id core.CanonicalIdentity, t core.TypeIdentity, tv core.TypeVersion, k events.Kind, v core.ObjectVersion, actor core.Actor, payload map[string]string) events.CanonicalEvent {
	return events.CanonicalEvent{Sequence: r.store.NextEventSequence(), Kind: k, CanonicalID: id, TypeIdentity: t, TypeVersion: tv, ResultingVersion: v, Timestamp: time.Now().UTC(), Payload: payload, Actor: actor}
}

func (r *Runtime) audit(id core.CanonicalIdentity, kind, detail string) {
	obj, ok := r.store.Get(id)
	if !ok {
		return
	}
	rec := events.AuditRecord{Sequence: r.store.NextAuditSequence(), Kind: kind, CanonicalID: id, Detail: detail, Timestamp: time.Now().UTC()}
	obj.AuditRecords = append(obj.AuditRecords, rec)
	r.store.Put(obj)
}
