// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package events

import (
	"time"

	"github.com/governedobjects/governed-objects-go/core"
)

// Kind classifies canonical history records (EVT-ACCEPT-001).
type Kind string

const (
	KindCreated             Kind = "object_created"
	KindStateUpdated        Kind = "state_updated"
	KindLifecycleTransition Kind = "lifecycle_transition"
	KindRelationshipAdded   Kind = "relationship_added"
	KindRelationshipRemoved Kind = "relationship_removed"
)

// CanonicalEvent represents an accepted semantic change (EVT-ACCEPT-001).
type CanonicalEvent struct {
	Sequence         int64                  `json:"sequence"`
	Kind             Kind                   `json:"kind"`
	CanonicalID      core.CanonicalIdentity `json:"canonical_id"`
	TypeIdentity     core.TypeIdentity      `json:"type_identity"`
	TypeVersion      core.TypeVersion       `json:"type_version"`
	ResultingVersion core.ObjectVersion     `json:"resulting_version"`
	Timestamp        time.Time              `json:"timestamp"`
	Payload          map[string]string      `json:"payload,omitempty"`
	Actor            core.Actor             `json:"actor,omitempty"`
	// PostImage is the full Accepted Canonical State after a create, state
	// update, or lifecycle transition. Present empty maps must survive native
	// JSON; relationship effects have a nil image. Artifact formats are separate.
	PostImage map[string]string `json:"post_image"`
}

// AuditRecord holds non-canonical operational evidence (EVT-SEPARATE-001).
type AuditRecord struct {
	Sequence    int64
	Kind        string
	CanonicalID core.CanonicalIdentity
	Detail      string
	Timestamp   time.Time
}
