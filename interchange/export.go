// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

// Package interchange exports portable-type objects to the provisional
// artifact go-core-interchange-experiment/2 and decodes both that artifact and
// its predecessor go-core-interchange-experiment/1.
//
// EXPERIMENTAL. NON-NORMATIVE. NOT A GOVERNED OBJECT WIRE STANDARD.
// NOT A DRAFT 2.1 OR DRAFT 2.2 REQUIREMENT. Export; new-target import is
// decoded by DecodeArtifact and performed by runtime.ImportBundle. Artifact
// revisions exist only here; the runtime sees specification revisions.
//
// History comes only from ObjectRecord.CanonicalEvents, never AuditRecords.
// The position of an entry is its index in that per-object list plus one. The store-global
// CanonicalEvent.Sequence and timestamps are never used for order.
package interchange

import (
	"fmt"
	"maps"
	"sort"
	"strconv"
	"time"

	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/events"
	"github.com/governedobjects/governed-objects-go/replay"
	"github.com/governedobjects/governed-objects-go/runtime"
	"github.com/governedobjects/governed-objects-go/types"
)

// Artifact contracts. Each artifact revision carries exactly one
// specification revision and its own status marker.
const (
	ArtifactRevisionV1 = "go-core-interchange-experiment/1"
	ArtifactStatusV1   = "EXPERIMENTAL; NON-NORMATIVE; NOT A GOVERNED OBJECT WIRE STANDARD; NOT A DRAFT 2.1 REQUIREMENT"
	SpecRevisionV1     = runtime.SpecRevisionDraft21

	ArtifactRevisionV2 = "go-core-interchange-experiment/2"
	ArtifactStatusV2   = "EXPERIMENTAL; NON-NORMATIVE; NOT A GOVERNED OBJECT WIRE STANDARD; NOT A DRAFT 2.2 REQUIREMENT"
	SpecRevisionV2     = runtime.SpecRevisionDraft22
)

// The identity of every bundle Export produces: the artifact that carries the
// runtime's claimed specification revision.
const (
	ArtifactRevision = ArtifactRevisionV2
	ArtifactStatus   = ArtifactStatusV2
	SpecRevision     = runtime.ClaimedSpecRevision
)

const (
	HistoryCompleteness      = "complete-from-creation"
	HistoryPositionModel     = "explicit-per-object-contiguous-from-1"
	GovernanceReferenceModel = "type-scoped"

	ExportOrderIndeterminate    = "EXPORT_ORDER_INDETERMINATE"
	ExportHistoryUnclassifiable = "EXPORT_HISTORY_UNCLASSIFIABLE"
	UnsupportedSemanticFeature  = "UNSUPPORTED_SEMANTIC_FEATURE"
	AuthorizationDenied         = "AUTHORIZATION_DENIED"
	NotFound                    = "NOT_FOUND"
)

// Refusal is returned instead of a bundle; nothing is repaired.
type Refusal struct {
	Code     string
	Message  string
	Identity core.CanonicalIdentity
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("%s: %s (%s)", r.Code, r.Message, r.Identity)
}

type Relationship struct {
	Source string `json:"source"`
	Type   string `json:"type"`
	Target string `json:"target"`
}

type Entry struct {
	Position               int                `json:"position"`
	Effect                 string             `json:"effect"`
	TypeIdentity           string             `json:"type_identity"`
	TypeVersion            string             `json:"type_version"`
	ResultingObjectVersion string             `json:"resulting_object_version"`
	PostImage              *map[string]string `json:"post_image,omitempty"`
	Relationships          *[]Relationship    `json:"relationships,omitempty"`
	Relationship           *Relationship      `json:"relationship,omitempty"`
	Actor                  string             `json:"actor,omitempty"`
	AcceptedAt             string             `json:"accepted_at,omitempty"`
}

type Object struct {
	CanonicalIdentity    string            `json:"canonical_identity"`
	TypeIdentity         string            `json:"type_identity"`
	TypeVersion          string            `json:"type_version"`
	GovernanceReference  *string           `json:"governance_reference"`
	AcceptedState        map[string]string `json:"accepted_state"`
	Relationships        []Relationship    `json:"relationships"`
	CurrentObjectVersion string            `json:"current_object_version"`
	History              []Entry           `json:"history"`
}

type Binding struct {
	TypeIdentity string `json:"type_identity"`
	TypeVersion  string `json:"type_version"`
}

type Provenance struct {
	SourceImplementation string `json:"source_implementation,omitempty"`
	ExportedAt           string `json:"exported_at,omitempty"`
}

type Manifest struct {
	ArtifactStatus           string        `json:"artifact_status"`
	ArtifactRevision         string        `json:"artifact_revision"`
	SpecRevision             string        `json:"spec_revision"`
	HistoryCompleteness      string        `json:"history_completeness"`
	HistoryPositionModel     string        `json:"history_position_model"`
	GovernanceReferenceModel string        `json:"governance_reference_model"`
	Profiles                 []interface{} `json:"profiles"`
	Identities               []string      `json:"identities"`
	TypeBindings             []Binding     `json:"type_bindings"`
	GovernanceReferences     []string      `json:"governance_references"`
	Closed                   bool          `json:"closed"`
	Provenance               *Provenance   `json:"provenance,omitempty"`
}

type Bundle struct {
	Manifest Manifest `json:"manifest"`
	Objects  []Object `json:"objects"`
}

// Request selects the objects to export and the exporting actor.
type Request struct {
	Identities           []core.CanonicalIdentity
	Actor                core.Actor
	Closed               bool
	IncludeTimestamps    bool
	SourceImplementation string
	Now                  func() time.Time
}

// Token renders a native Object Version as the artifact string.
func Token(v core.ObjectVersion) string { return strconv.FormatInt(int64(v), 10) }

var effects = map[events.Kind]string{
	events.KindCreated:             "create",
	events.KindStateUpdated:        "state_change",
	events.KindLifecycleTransition: "lifecycle_transition",
	events.KindRelationshipAdded:   "relationship_add",
	events.KindRelationshipRemoved: "relationship_remove",
}

// Export builds a bundle from governed runtime reads.
func Export(rt *runtime.Runtime, req Request) (*Bundle, error) {
	// Snapshot exact opaque selections before any runtime read or callback.
	identities := append([]core.CanonicalIdentity(nil), req.Identities...)
	seen := make(map[core.CanonicalIdentity]bool, len(identities))
	for _, id := range identities {
		if seen[id] {
			return nil, &Refusal{Code: runtime.ImportDuplicateIdentityInBundle, Message: "export selection contains repeated identities"}
		}
		seen[id] = true
	}
	objects := make([]Object, 0, len(identities))
	for _, id := range identities {
		obj, err := exportObject(rt, id, req)
		if err != nil {
			return nil, err
		}
		objects = append(objects, obj)
	}
	m := Manifest{
		ArtifactStatus:           ArtifactStatus,
		ArtifactRevision:         ArtifactRevision,
		SpecRevision:             SpecRevision,
		HistoryCompleteness:      HistoryCompleteness,
		HistoryPositionModel:     HistoryPositionModel,
		GovernanceReferenceModel: GovernanceReferenceModel,
		Profiles:                 []interface{}{},
		Identities:               []string{},
		TypeBindings:             []Binding{},
		GovernanceReferences:     []string{},
		Closed:                   req.Closed,
	}
	seenBinding := map[Binding]bool{}
	seenRef := map[string]bool{}
	for _, o := range objects {
		m.Identities = append(m.Identities, o.CanonicalIdentity)
		b := Binding{o.TypeIdentity, o.TypeVersion}
		if !seenBinding[b] {
			seenBinding[b] = true
			m.TypeBindings = append(m.TypeBindings, b)
		}
		if o.GovernanceReference != nil && !seenRef[*o.GovernanceReference] {
			seenRef[*o.GovernanceReference] = true
			m.GovernanceReferences = append(m.GovernanceReferences, *o.GovernanceReference)
		}
	}
	prov := Provenance{SourceImplementation: req.SourceImplementation}
	if req.IncludeTimestamps {
		now := time.Now
		if req.Now != nil {
			now = req.Now
		}
		prov.ExportedAt = now().UTC().Format(time.RFC3339Nano)
	}
	if prov != (Provenance{}) {
		m.Provenance = &prov
	}
	return &Bundle{Manifest: m, Objects: objects}, nil
}

func exportObject(rt *runtime.Runtime, id core.CanonicalIdentity, req Request) (Object, error) {
	refuse := func(code, format string, args ...interface{}) (Object, error) {
		return Object{}, &Refusal{Code: code, Message: fmt.Sprintf(format, args...), Identity: id}
	}
	outcome, live := rt.Read(core.OperationContext{Actor: req.Actor, Action: core.ActionRead, Target: id}, id)
	switch outcome.Kind {
	case core.OutcomeAccepted:
	case core.OutcomeDenied:
		return refuse(AuthorizationDenied, "%s", outcome.Reason)
	default:
		return refuse(NotFound, "%s", outcome.Reason)
	}
	obj := live
	pt, behavior, ok := rt.ResolveType(types.Binding{Identity: obj.TypeIdentity, Version: obj.TypeVersion})
	if !ok {
		return refuse(UnsupportedSemanticFeature, "type %q is not a portable Core type", obj.TypeIdentity)
	}
	if pt.Version != obj.TypeVersion {
		return refuse(UnsupportedSemanticFeature, "object bound to %s@%s but the runtime supports @%s", obj.TypeIdentity, obj.TypeVersion, pt.Version)
	}
	if obj.GovernanceReference == "" {
		return refuse(UnsupportedSemanticFeature, "object has no stored portable governance reference")
	}
	folded, err := replay.Reconstruct(obj.CanonicalEvents, exportResolver{pt, behavior})
	if err != nil {
		return refuse(ExportHistoryUnclassifiable, "accepted history cannot be reconstructed")
	}
	if folded.CanonicalID != obj.CanonicalID || folded.TypeIdentity != obj.TypeIdentity || folded.TypeVersion != obj.TypeVersion || folded.ObjectVersion != obj.ObjectVersion || obj.Attributes == nil || !maps.Equal(folded.Attributes, obj.Attributes) || !sameRelationships(folded.Relationships, obj.Relationships) {
		return refuse(ExportHistoryUnclassifiable, "snapshot differs from accepted history")
	}

	history := make([]Entry, 0, len(obj.CanonicalEvents))
	seenVersions := map[core.ObjectVersion]int{}
	for i, evt := range obj.CanonicalEvents {
		pos := i + 1
		if evt.CanonicalID != obj.CanonicalID {
			return refuse(ExportHistoryUnclassifiable, "event at position %d belongs to %q", pos, evt.CanonicalID)
		}
		effect, ok := effects[evt.Kind]
		if !ok {
			return refuse(ExportHistoryUnclassifiable, "event kind %q at position %d", evt.Kind, pos)
		}
		if (pos == 1) != (evt.Kind == events.KindCreated) {
			return refuse(ExportHistoryUnclassifiable, "create must be exactly the first event (position %d is %q)", pos, evt.Kind)
		}
		// Tokens are opaque: only reuse is refused. A restored history may
		// carry versions that do not increase in position order.
		if prior, dup := seenVersions[evt.ResultingVersion]; dup {
			return refuse(ExportHistoryUnclassifiable, "Object Version at position %d reuses position %d's", pos, prior)
		}
		seenVersions[evt.ResultingVersion] = pos
		if evt.TypeIdentity == "" || evt.TypeVersion == "" {
			return refuse(ExportHistoryUnclassifiable, "event at position %d records no type binding", pos)
		}
		e := Entry{
			Position:               pos,
			Effect:                 effect,
			TypeIdentity:           string(evt.TypeIdentity),
			TypeVersion:            string(evt.TypeVersion),
			ResultingObjectVersion: Token(evt.ResultingVersion),
			Actor:                  string(evt.Actor),
		}
		switch evt.Kind {
		case events.KindCreated, events.KindStateUpdated, events.KindLifecycleTransition:
			if evt.PostImage == nil {
				return refuse(ExportHistoryUnclassifiable, "event at position %d records no post-image", pos)
			}
			img := copyMap(evt.PostImage)
			e.PostImage = &img
			if evt.Kind == events.KindCreated {
				baseline := []Relationship{}
				e.Relationships = &baseline
			}
		default:
			e.Relationship = &Relationship{
				Source: string(evt.CanonicalID),
				Type:   evt.Payload["relationship_type"],
				Target: evt.Payload["target"],
			}
		}
		// A zero timestamp is an imported event whose source recorded none.
		if req.IncludeTimestamps && !evt.Timestamp.IsZero() {
			e.AcceptedAt = evt.Timestamp.UTC().Format(time.RFC3339Nano)
		}
		history = append(history, e)
	}
	if len(history) == 0 {
		return refuse(ExportHistoryUnclassifiable, "object has no accepted history")
	}
	if last := obj.CanonicalEvents[len(obj.CanonicalEvents)-1].ResultingVersion; last != obj.ObjectVersion {
		return refuse(ExportHistoryUnclassifiable, "current Object Version %d is not the last accepted version %d", obj.ObjectVersion, last)
	}

	rels := make([]Relationship, 0, len(obj.Relationships))
	for _, r := range obj.Relationships {
		rels = append(rels, Relationship{Source: string(r.Source), Type: string(r.Type), Target: string(r.Target)})
	}
	sort.Slice(rels, func(a, b int) bool {
		if rels[a].Type != rels[b].Type {
			return rels[a].Type < rels[b].Type
		}
		return rels[a].Target < rels[b].Target
	})
	ref := string(obj.GovernanceReference)
	return Object{
		CanonicalIdentity:    string(obj.CanonicalID),
		TypeIdentity:         string(obj.TypeIdentity),
		TypeVersion:          string(obj.TypeVersion),
		GovernanceReference:  &ref,
		AcceptedState:        copyMap(obj.Attributes),
		Relationships:        rels,
		CurrentObjectVersion: Token(obj.ObjectVersion),
		History:              history,
	}, nil
}

// PortableTypeFromDefinition is a helper for adapters translating the
// fixture's types.json shape.
func PortableTypeFromDefinition(identity, version string, fields map[string]string, states []string, transitions [][2]string, relTypes []string, actions map[string]types.PortableAction) types.PortableType {
	f := make(map[string]types.FieldKind, len(fields))
	for k, v := range fields {
		f[k] = types.FieldKind(v)
	}
	return types.PortableType{
		Identity:          core.TypeIdentity(identity),
		Version:           core.TypeVersion(version),
		Fields:            f,
		LifecycleStates:   states,
		Transitions:       transitions,
		RelationshipTypes: relTypes,
		Actions:           actions,
	}
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

type exportResolver struct {
	t types.PortableType
	b types.Behavior
}

func (s exportResolver) ResolveType(binding types.Binding) (types.PortableType, types.Behavior, bool) {
	return s.t.Clone(), s.b, s.t.Binding() == binding
}
func sameRelationships(a, b []core.Relationship) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[core.Relationship]bool{}
	for _, r := range a {
		if seen[r] {
			return false
		}
		seen[r] = true
	}
	for _, r := range b {
		if !seen[r] {
			return false
		}
		delete(seen, r)
	}
	return len(seen) == 0
}
