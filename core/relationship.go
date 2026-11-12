// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package core

// RelationshipType names a directed semantic edge (REL-EDGE-001).
type RelationshipType string

const (
	RelDependsOn RelationshipType = "depends_on"
	RelOwnedBy   RelationshipType = "owned_by"
)

// Relationship is a typed canonical edge from source to target (REL-EDGE-001).
type Relationship struct {
	Source CanonicalIdentity `json:"source"`
	Type   RelationshipType  `json:"type"`
	Target CanonicalIdentity `json:"target"`
}
