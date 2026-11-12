// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package core

// CanonicalIdentity is the durable organization-controlled identity (CORE-ID-001).
type CanonicalIdentity string

// TypeIdentity identifies the semantic type governing an object (TYPE-ID-001).
type TypeIdentity string

// TypeVersion identifies a revision of portable type semantics (TYPE-VERSION-001).
type TypeVersion string

// ObjectVersion is a concurrency token for Accepted Canonical State (CON-VERSION-001).
type ObjectVersion int64
