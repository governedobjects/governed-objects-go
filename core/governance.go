// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package core

// GovernanceReference is an opaque, type-scoped reference to locally
// configured governance, recorded on an object at creation.
//
// EXPERIMENTAL. It is never recomputed after
// creation and never consulted for authorization; it grants nothing.
type GovernanceReference string
