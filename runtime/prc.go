// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package runtime

// Portable Restoration Continuity claim (specification revision draft2.2,
// profiles/portable-restoration-continuity.md). PRCDeclaration is this
// runtime's own machine-readable claim for PRC-CLAIM-001, PRC-CAP-001,
// PRC-EVID-001 and PRC-HANDOFF-001. The profile defines no declaration
// encoding; the JSON member names are this runtime's.

import (
	"math"
	"sort"
	"strconv"
)

const PRCProfile = "Portable Restoration Continuity"

// PRC roles (PRC-CLAIM-001).
const (
	PRCRoleExporter = "exporter"
	PRCRoleRestorer = "restorer"
)

// PRC-EVID-001 evidence levels.
const (
	EvidenceEffectEquivalent   = "effect-equivalent"
	EvidenceEvidencePreserving = "evidence-preserving"
)

// Provenance items a portable representation can carry: per history entry,
// and per relationship triple for the relationship items.
const (
	ProvenanceActor                  = "actor"
	ProvenanceAcceptedAt             = "accepted_at"
	ProvenanceAction                 = "action"
	ProvenanceSourceEventID          = "source_event_id"
	ProvenanceRelationshipTargetType = "relationship.target_type"
	ProvenanceRelationshipMetadata   = "relationship.metadata"
)

// HandoffOperatorManaged: an operator keeps a single accepting authority.
const HandoffOperatorManaged = "operator-managed"

type PRCDeclaration struct {
	Profile      string          `json:"profile"`
	Roles        []string        `json:"roles"`
	Export       PRCExport       `json:"export"`
	Capabilities PRCCapabilities `json:"capabilities"`
	Handoff      PRCHandoff      `json:"handoff"`
}

// PRCExport is the Exporter claim: the specification revision under which
// exported content is claimed (PRC-EXPORT-001).
type PRCExport struct {
	SpecRevision string `json:"spec_revision"`
}

// PRCCapabilities is the PRC-CAP-001 Restorer declaration.
//
// BaselineRelationships is false: native creation carries no relationships,
// so a creation baseline with relationships is refused, never rewritten as
// later additions. PRC-CAP-001 makes this a declared capability, not a
// Restorer obligation.
//
// AllOrNothing is request-wide: ImportBundle stages every object before any
// write, and store.CommitImport stores all of them or none.
type PRCCapabilities struct {
	SpecRevisions         []string               `json:"spec_revisions"`
	TypeBindings          []PRCTypeBinding       `json:"type_bindings"`
	ObjectVersionForms    []PRCObjectVersionForm `json:"object_version_forms"`
	BaselineRelationships bool                   `json:"baseline_relationships"`
	TimePrecision         PRCTimePrecision       `json:"time_precision"`
	RequiredProvenance    []string               `json:"required_provenance"`
	EvidenceLevel         string                 `json:"evidence_level"`
	ProvenanceRetained    []string               `json:"provenance_retained"`
	ProvenanceNotRetained []string               `json:"provenance_not_retained"`
	AllOrNothing          bool                   `json:"all_or_nothing"`
}

type PRCTypeBinding struct {
	TypeIdentity string `json:"type_identity"`
	TypeVersion  string `json:"type_version"`
}

// PRCObjectVersionForm is a representability constraint only: Object
// Versions stay opaque and are compared for equality, so a token's numeric
// value implies no order.
type PRCObjectVersionForm struct {
	Pattern  string `json:"pattern"`
	MaxValue string `json:"max_value"`
}

// PRCTimePrecision describes the accepted_at evidence retained. Finer
// fractions are refused, never rounded; so is the one instant that coincides
// with the native "not recorded" zero time.
type PRCTimePrecision struct {
	FractionDigits          int      `json:"fraction_digits"`
	FinerPrecision          string   `json:"finer_precision"`
	UnrepresentableInstants []string `json:"unrepresentable_instants"`
}

// PRCHandoff is the PRC-HANDOFF-001 declaration. It is an assumption of the
// claim; this runtime neither enforces nor verifies it.
type PRCHandoff struct {
	Model             string `json:"model"`
	Procedure         string `json:"procedure"`
	EnforcedByRuntime bool   `json:"enforced_by_runtime"`
	VerifiedByRuntime bool   `json:"verified_by_runtime"`
}

const handoffProcedure = "Before restoration, the operator retires the source or makes it read-only for every identity being restored, " +
	"so the source accepts no canonical change after the revision carried in the portable representation. " +
	"When this runtime is the source, export does not stop it accepting changes; the operator must stop them."

// PRCDeclaration returns this runtime's bounded PRC capability declaration,
// not a conformance claim. Bindings may be registered through RegisterType or
// RegisterPortableType, subject to current schema, behavior and exact support
// checks. This declaration neither transports executable rules nor establishes
// universal portability or certified conformance.
func (r *Runtime) PRCDeclaration() PRCDeclaration {
	r.mu.Lock()
	bindings := make([]PRCTypeBinding, 0, len(r.portable))
	for _, pt := range r.portable {
		bindings = append(bindings, PRCTypeBinding{TypeIdentity: string(pt.Identity), TypeVersion: string(pt.Version)})
	}
	r.mu.Unlock()
	sort.Slice(bindings, func(a, b int) bool {
		if bindings[a].TypeIdentity != bindings[b].TypeIdentity {
			return bindings[a].TypeIdentity < bindings[b].TypeIdentity
		}
		return bindings[a].TypeVersion < bindings[b].TypeVersion
	})
	return PRCDeclaration{
		Profile: PRCProfile,
		Roles:   []string{PRCRoleExporter, PRCRoleRestorer},
		Export:  PRCExport{SpecRevision: ClaimedSpecRevision},
		Capabilities: PRCCapabilities{
			SpecRevisions: RestoreSpecRevisions(),
			TypeBindings:  bindings,
			ObjectVersionForms: []PRCObjectVersionForm{{
				Pattern:  nativeToken.String(),
				MaxValue: strconv.FormatInt(math.MaxInt64, 10),
			}},
			BaselineRelationships: false,
			TimePrecision: PRCTimePrecision{
				FractionDigits:          acceptedAtFractionDigits,
				FinerPrecision:          "refused",
				UnrepresentableInstants: []string{notRecordedInstant},
			},
			RequiredProvenance: []string{},
			EvidenceLevel:      EvidenceEffectEquivalent,
			ProvenanceRetained: []string{ProvenanceActor, ProvenanceAcceptedAt},
			ProvenanceNotRetained: []string{
				ProvenanceAction, ProvenanceSourceEventID,
				ProvenanceRelationshipTargetType, ProvenanceRelationshipMetadata,
			},
			AllOrNothing: true,
		},
		Handoff: PRCHandoff{
			Model:             HandoffOperatorManaged,
			Procedure:         handoffProcedure,
			EnforcedByRuntime: false,
			VerifiedByRuntime: false,
		},
	}
}
