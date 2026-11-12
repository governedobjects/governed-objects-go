// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package core

// Actor identifies who requests a governed operation (OP-CTX-001).
type Actor string

// Action names the requested operation.
type Action string

const (
	ActionCreate             Action = "create"
	ActionRead               Action = "read"
	ActionUpdate             Action = "update"
	ActionTransition         Action = "transition"
	ActionAddRelationship    Action = "add_relationship"
	ActionRemoveRelationship Action = "remove_relationship"
	// ActionImport is the privileged new-target interchange import
	// (EXPERIMENTAL).
	ActionImport Action = "import"
)

// OperationContext carries semantic inputs for evaluation (OP-CTX-001).
type OperationContext struct {
	Actor           Actor
	Action          Action
	Target          CanonicalIdentity
	Parameters      map[string]string
	ExpectedVersion *ObjectVersion
}
