// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package core

// OutcomeKind distinguishes governed operation results per OP-OUTCOME-001.
type OutcomeKind string

const (
	OutcomeAccepted OutcomeKind = "accepted"
	OutcomeDenied   OutcomeKind = "denied"
	OutcomeConflict OutcomeKind = "conflict"
	OutcomeInvalid  OutcomeKind = "invalid"
	// OutcomeRefused is EXPERIMENTAL:
	// a runtime capacity refusal outside the four OP-OUTCOME-001 categories.
	OutcomeRefused OutcomeKind = "refused"
)

// ReasonObjectVersionSpaceExhausted refuses a mutation when no unused Object
// Version remains for the object (EXPERIMENTAL).
const ReasonObjectVersionSpaceExhausted = "OBJECT_VERSION_SPACE_EXHAUSTED"

// Outcome is the observable result of a governed operation.
type Outcome struct {
	Kind    OutcomeKind
	Reason  string
	Version ObjectVersion
}

func Accepted(version ObjectVersion) Outcome {
	return Outcome{Kind: OutcomeAccepted, Version: version}
}

func Denied(reason string, version ObjectVersion) Outcome {
	return Outcome{Kind: OutcomeDenied, Reason: reason, Version: version}
}

func Conflict(reason string, version ObjectVersion) Outcome {
	return Outcome{Kind: OutcomeConflict, Reason: reason, Version: version}
}

func Invalid(reason string, version ObjectVersion) Outcome {
	return Outcome{Kind: OutcomeInvalid, Reason: reason, Version: version}
}

func Refused(reason string, version ObjectVersion) Outcome {
	return Outcome{Kind: OutcomeRefused, Reason: reason, Version: version}
}
