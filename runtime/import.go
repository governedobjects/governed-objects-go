// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package runtime

// EXPERIMENTAL. NON-NORMATIVE.
// Privileged new-target import of accepted Core history.
//
// The input is a runtime-neutral semantic structure (ImportBundle), not
// artifact JSON; decoding the provisional artifact is the adapter's job
// (interchange.DecodeArtifact). ImportBundle:
//
//   - restores already-accepted history as history: no operation is re-run,
//     historical actors are not authorized, no Object Version is generated,
//     and no import event is appended to CanonicalEvents;
//   - resolves the declared governance reference against the local
//     SetGovernance configuration; a match selects local governance and
//     grants nothing;
//   - checks this runtime's receiver constraints (identity absent, exact
//     Type Identity and Type Version, representable Object Version tokens,
//     native encodability of each effect, representable evidence) and folds
//     the history in position order so the stored snapshot is the one the
//     history produces;
//   - commits every record with store.CommitImport, or nothing.
//
// CanonicalEvents are stored in portable-position order, so the exporter's
// position (index + 1) is the imported position. Import provenance is kept
// in the store's import records, outside every ObjectRecord.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/events"
	"github.com/governedobjects/governed-objects-go/internal/statefold"
	"github.com/governedobjects/governed-objects-go/store"
	"github.com/governedobjects/governed-objects-go/types"
)

// Specification revisions. ClaimedSpecRevision is the revision this runtime
// implements; content it exports is claimed under it.
const (
	SpecRevisionDraft21 = "v0alpha1/draft2.1"
	SpecRevisionDraft22 = "v0alpha1/draft2.2"
	ClaimedSpecRevision = SpecRevisionDraft22
)

// restoreSpecRevisions are the specification revisions ImportBundle restores,
// matched exactly. Draft 2.1 and Draft 2.2 content have the same Core content
// model here, and restored objects of either revision are governed under
// Draft 2.2.
var restoreSpecRevisions = []string{SpecRevisionDraft21, SpecRevisionDraft22}

// RestoreSpecRevisions returns every specification revision ImportBundle
// restores.
func RestoreSpecRevisions() []string { return slices.Clone(restoreSpecRevisions) }

// The semantic feature set this runtime imports.
const (
	// ImportSpecRevision is the only revision Go runtimes before the Draft 2.2
	// PRC successor restored, kept for adapters compiled against it. It is
	// still restored but is not the complete set: see RestoreSpecRevisions and
	// Runtime.PRCDeclaration.
	ImportSpecRevision             = SpecRevisionDraft21
	ImportHistoryCompleteness      = "complete-from-creation"
	ImportHistoryPositionModel     = "explicit-per-object-contiguous-from-1"
	ImportGovernanceReferenceModel = "type-scoped"
	ImportExperimentRevision       = "governed-objects-import-experiment/1"
	// NativeTokenGrammar is the portable Object Version form this runtime
	// holds exactly: the canonical base-10 form of a positive int64.
	NativeTokenGrammar = "^[1-9][0-9]*$ with value <= 9223372036854775807"
)

// Refusal codes: the EXPERIMENTAL taxonomy for new-target transfer,
// plus IDENTITY_ALREADY_EXISTS.
const (
	ImportAuthorizationDenied         = "AUTHORIZATION_DENIED"
	ImportIdentityAlreadyExists       = "IDENTITY_ALREADY_EXISTS"
	ImportUnsupportedSpecRevision     = "UNSUPPORTED_SPEC_REVISION"
	ImportMalformedArtifact           = "MALFORMED_ARTIFACT"
	ImportDuplicateIdentityInBundle   = "DUPLICATE_IDENTITY_IN_BUNDLE"
	ImportUnsupportedType             = "UNSUPPORTED_TYPE"
	ImportUnsupportedTypeVersion      = "UNSUPPORTED_TYPE_VERSION"
	ImportStateNotValidForType        = "STATE_NOT_VALID_FOR_TYPE"
	ImportHistoryNotValidForType      = "HISTORY_NOT_VALID_FOR_TYPE"
	ImportDuplicateRelationship       = "DUPLICATE_RELATIONSHIP"
	ImportMultisetHistory             = "MULTISET_HISTORY"
	ImportHistoryIncomplete           = "HISTORY_INCOMPLETE"
	ImportHistoryInconsistent         = "HISTORY_INCONSISTENT"
	ImportHistorySnapshotMismatch     = "HISTORY_SNAPSHOT_MISMATCH"
	ImportVersionTokenReuse           = "VERSION_TOKEN_REUSE"
	ImportUnsupportedVersionForm      = "UNSUPPORTED_OBJECT_VERSION_REPRESENTATION"
	ImportGovernanceReferenceMissing  = "GOVERNANCE_REFERENCE_MISSING"
	ImportUnresolvedGovernance        = "UNRESOLVED_GOVERNANCE_REFERENCE"
	ImportUnsupportedSemanticFeature  = "UNSUPPORTED_SEMANTIC_FEATURE"
	ImportBundleClosureViolated       = "BUNDLE_CLOSURE_VIOLATED"
	ImportUnsupportedArtifactRevision = "UNSUPPORTED_ARTIFACT_REVISION"
)

const (
	EffectCreate              = "create"
	EffectStateChange         = "state_change"
	EffectLifecycleTransition = "lifecycle_transition"
	EffectRelationshipAdd     = "relationship_add"
	EffectRelationshipRemove  = "relationship_remove"
)

// ImportRefusal is returned instead of importing; the store is unchanged.
type ImportRefusal struct {
	Code     string
	Message  string
	Identity string
	Position int
}

func (r *ImportRefusal) Error() string {
	where := r.Identity
	if r.Position > 0 {
		where = fmt.Sprintf("%s.history[position=%d]", r.Identity, r.Position)
	}
	if where != "" {
		return fmt.Sprintf("%s: %s: %s", r.Code, where, r.Message)
	}
	return fmt.Sprintf("%s: %s", r.Code, r.Message)
}

func refuse(code, identity string, position int, format string, args ...interface{}) *ImportRefusal {
	return &ImportRefusal{Code: code, Message: fmt.Sprintf(format, args...), Identity: identity, Position: position}
}

type ImportRelationship struct {
	Source, Type, Target string
	// HasEvidence marks OPTIONAL EVIDENCE (target type, metadata); it is
	// not retained natively.
	HasEvidence bool
}

func (r ImportRelationship) key() [3]string { return [3]string{r.Source, r.Type, r.Target} }

type ImportEvidence struct {
	Actor, AcceptedAt, Action, SourceEventID *string
}

type ImportEntry struct {
	Position               int
	Effect                 string
	TypeIdentity           string
	TypeVersion            string
	ResultingObjectVersion string
	PostImage              map[string]string // nil when absent
	BaselineRelationships  []ImportRelationship
	HasBaseline            bool
	Relationship           *ImportRelationship
	Evidence               ImportEvidence
}

type ImportObject struct {
	CanonicalIdentity    string
	TypeIdentity         string
	TypeVersion          string
	GovernanceReference  *string
	AcceptedState        map[string]string
	Relationships        []ImportRelationship
	CurrentObjectVersion string
	History              []ImportEntry
}

// ImportBundle is the semantic content of a portable bundle, independent of
// its encoding.
type ImportBundle struct {
	Objects                  []ImportObject
	Closed                   bool
	SpecRevision             *string
	HistoryCompleteness      string
	HistoryPositionModel     string
	GovernanceReferenceModel string
	ProfileCount             int
	SourceImplementation     string
}

// ImportProvenance is Operational Metadata about the transfer.
type ImportProvenance struct {
	ArtifactSHA256       string
	SourceImplementation string
	Adapter              string
}

type ImportResult struct {
	ImportID   string
	Identities []string
	// EvidenceNotes lists optional evidence this runtime could not retain
	// (only dimensions treated as informational or excluded); unrepresentable
	// actor or accepted_at evidence refuses.
	EvidenceNotes []string
}

var nativeToken = regexp.MustCompile(`^[1-9][0-9]*$`)

// NativeVersion parses a portable token into a native Object Version,
// refusing any token whose native value would not render back to the same
// string.
func NativeVersion(token, identity string, position int) (core.ObjectVersion, *ImportRefusal) {
	if !nativeToken.MatchString(token) {
		return 0, refuse(ImportUnsupportedVersionForm, identity, position,
			"token %q is not a canonical positive base-10 integer; the native Object Version is an int64 and the token would not survive exactly", token)
	}
	n, err := strconv.ParseInt(token, 10, 64)
	if err != nil {
		return 0, refuse(ImportUnsupportedVersionForm, identity, position,
			"token %q exceeds the native int64 Object Version range", token)
	}
	if strconv.FormatInt(n, 10) != token {
		return 0, refuse(ImportUnsupportedVersionForm, identity, position, "token %q does not round-trip", token)
	}
	return core.ObjectVersion(n), nil
}

var instantPattern = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$`)

// acceptedAtFractionDigits is the finest fraction of a second a native
// timestamp holds: time.Time has nanosecond resolution.
const acceptedAtFractionDigits = 9

// notRecordedInstant is the instant the native zero time.Time denotes; the
// runtime uses the zero value to mean "no timestamp recorded".
var notRecordedInstant = time.Time{}.UTC().Format(time.RFC3339Nano)

// NativeAcceptedAt parses native timestamp evidence into UTC. Its intentionally
// broader offset syntax is not the strict artifact RFC 3339 validation gate.
// It refuses instants not exactly representable at nanosecond precision and
// the zero time, which marks "not recorded".
func NativeAcceptedAt(text, identity string, position int) (time.Time, *ImportRefusal) {
	m := instantPattern.FindStringSubmatch(text)
	if m == nil {
		return time.Time{}, refuse(ImportMalformedArtifact, identity, position, "accepted_at is not an RFC 3339 instant")
	}
	num := func(s string) int { n, _ := strconv.Atoi(s); return n }
	year, month, day, hour, minute, second := num(m[1]), num(m[2]), num(m[3]), num(m[4]), num(m[5]), num(m[6])
	digits := strings.TrimPrefix(m[7], ".")
	if len(strings.TrimRight(digits, "0")) > acceptedAtFractionDigits {
		return time.Time{}, refuse(ImportUnsupportedSemanticFeature, identity, position,
			"accepted_at %q has sub-nanosecond precision; the native timestamp would not hold this instant exactly (evidence is never truncated)", text)
	}
	nanos := 0
	if digits != "" {
		nanos = num((digits + strings.Repeat("0", acceptedAtFractionDigits))[:acceptedAtFractionDigits])
	}
	loc := time.UTC
	if z := m[8]; z != "Z" && z != "z" {
		offset := num(z[1:3])*3600 + num(z[4:6])*60
		if z[0] == '-' {
			offset = -offset
		}
		loc = time.FixedZone("", offset)
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, nanos, loc)
	if t.Year() != year || int(t.Month()) != month || t.Day() != day || t.Hour() != hour || t.Minute() != minute || t.Second() != second {
		return time.Time{}, refuse(ImportMalformedArtifact, identity, position, "accepted_at %q is not a valid instant", text)
	}
	t = t.UTC()
	if t.IsZero() {
		return time.Time{}, refuse(ImportUnsupportedSemanticFeature, identity, position,
			"accepted_at %q coincides with the native 'not recorded' zero time", text)
	}
	return t, nil
}

// ImportBundle restores a bundle into this runtime. ctx.Action must be
// core.ActionImport and ctx.Actor must hold the import grant.
func (r *Runtime) ImportBundle(ctx core.OperationContext, b ImportBundle, prov ImportProvenance) (*ImportResult, *ImportRefusal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Action != core.ActionImport || !r.authorizer.Allowed(ctx.Actor, core.ActionImport, "") {
		return nil, refuse(ImportAuthorizationDenied, "", 0, "actor %q holds no import grant", ctx.Actor)
	}
	if ref := checkDeclarations(b); ref != nil {
		return nil, ref
	}
	if len(b.Objects) == 0 {
		return nil, refuse(ImportMalformedArtifact, "", 0, "bundle contains no objects")
	}
	seen := map[string]bool{}
	identities := make([]string, 0, len(b.Objects))
	for _, o := range b.Objects {
		if seen[o.CanonicalIdentity] {
			return nil, refuse(ImportDuplicateIdentityInBundle, o.CanonicalIdentity, 0, "appears more than once")
		}
		seen[o.CanonicalIdentity] = true
		identities = append(identities, o.CanonicalIdentity)
	}
	if b.Closed {
		for _, o := range b.Objects {
			for _, rel := range o.Relationships {
				if !seen[rel.Target] {
					return nil, refuse(ImportBundleClosureViolated, o.CanonicalIdentity, 0, "bundle declares closure but target %q is absent", rel.Target)
				}
			}
		}
	}
	var existing []string
	for _, id := range identities {
		if _, ok := r.store.Get(core.CanonicalIdentity(id)); ok {
			existing = append(existing, id)
		}
	}
	if len(existing) > 0 {
		return nil, refuse(ImportIdentityAlreadyExists, existing[0], 0,
			"identities already exist in this runtime: %v; new-target import never overwrites, merges, or skips", existing)
	}

	notes := []string{}
	records := make([]*store.ObjectRecord, 0, len(b.Objects))
	for _, o := range b.Objects {
		rec, ref := r.stageImport(o, &notes)
		if ref != nil {
			return nil, ref
		}
		records = append(records, rec)
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, refuse(ImportUnsupportedSemanticFeature, "", 0, "cannot allocate an import id: %v", err)
	}
	source := prov.SourceImplementation
	if source == "" {
		source = b.SourceImplementation
	}
	ids := make([]core.CanonicalIdentity, len(identities))
	for i, id := range identities {
		ids[i] = core.CanonicalIdentity(id)
	}
	rec := store.ImportRecord{
		ImportID:             hex.EncodeToString(idBytes),
		ImportedAt:           time.Now().UTC(),
		ImportingActor:       ctx.Actor,
		Identities:           ids,
		SourceImplementation: source,
		ArtifactSHA256:       prov.ArtifactSHA256,
		Adapter:              prov.Adapter,
		ExperimentRevision:   ImportExperimentRevision,
		EvidenceNotes:        append([]string(nil), notes...),
	}
	if err := r.store.CommitImport(records, rec); err != nil {
		if c, ok := err.(*store.IdentityCollision); ok {
			return nil, refuse(ImportIdentityAlreadyExists, string(c.Identities[0]), 0, "identities already exist in this runtime: %v", c.Identities)
		}
		return nil, refuse(ImportUnsupportedSemanticFeature, "", 0, "commit failed: %v", err)
	}
	return &ImportResult{ImportID: rec.ImportID, Identities: identities, EvidenceNotes: notes}, nil
}

// InterchangeImports returns the import provenance records (Operational
// Metadata).
func (r *Runtime) InterchangeImports() []store.ImportRecord { return r.store.Imports() }

func checkDeclarations(b ImportBundle) *ImportRefusal {
	if b.SpecRevision == nil || !slices.Contains(restoreSpecRevisions, *b.SpecRevision) {
		got := "<absent>"
		if b.SpecRevision != nil {
			got = *b.SpecRevision
		}
		return refuse(ImportUnsupportedSpecRevision, "", 0, "specification revision %q is not supported", got)
	}
	if b.HistoryCompleteness != ImportHistoryCompleteness {
		return refuse(ImportHistoryIncomplete, "", 0, "history completeness %q; only complete history is imported", b.HistoryCompleteness)
	}
	if b.HistoryPositionModel != ImportHistoryPositionModel {
		return refuse(ImportMalformedArtifact, "", 0, "history position model %q is not supported", b.HistoryPositionModel)
	}
	if b.GovernanceReferenceModel != ImportGovernanceReferenceModel {
		return refuse(ImportUnsupportedSemanticFeature, "", 0, "governance reference model %q is not supported", b.GovernanceReferenceModel)
	}
	if b.ProfileCount > 0 {
		return refuse(ImportUnsupportedSemanticFeature, "", 0, "profile data is not supported")
	}
	return nil
}

func (r *Runtime) stageImport(o ImportObject, notes *[]string) (*store.ObjectRecord, *ImportRefusal) {
	ident := o.CanonicalIdentity
	if ident == "" || o.TypeIdentity == "" || o.TypeVersion == "" || o.AcceptedState == nil {
		return nil, refuse(ImportMalformedArtifact, ident, 0, "identity, binding and accepted_state are required")
	}
	pt, ok := r.portable[core.TypeIdentity(o.TypeIdentity)]
	if !ok {
		return nil, refuse(ImportUnsupportedType, ident, 0, "Type Identity %q is not configured", o.TypeIdentity)
	}
	if string(pt.Version) != o.TypeVersion {
		return nil, refuse(ImportUnsupportedTypeVersion, ident, 0,
			"%s@%s is not supported; this runtime is configured with @%s (never upcast, downcast, or migrated)", o.TypeIdentity, o.TypeVersion, pt.Version)
	}
	behavior := r.behaviors[pt.Identity]
	if !statefold.Complete(behavior) {
		return nil, refuse(ImportUnsupportedType, ident, 0, "exact behavior is unavailable")
	}
	for _, e := range o.History {
		switch e.Effect {
		case EffectCreate:
			if e.PostImage == nil || !e.HasBaseline || e.Relationship != nil {
				return nil, refuse(ImportMalformedArtifact, ident, e.Position, "creation content is missing or contradictory")
			}
		case EffectStateChange, EffectLifecycleTransition:
			if e.PostImage == nil || e.HasBaseline || e.BaselineRelationships != nil || e.Relationship != nil {
				return nil, refuse(ImportMalformedArtifact, ident, e.Position, "state effect content is missing or contradictory")
			}
		case EffectRelationshipAdd, EffectRelationshipRemove:
			if e.PostImage != nil || e.HasBaseline || e.BaselineRelationships != nil || e.Relationship == nil {
				return nil, refuse(ImportMalformedArtifact, ident, e.Position, "relationship effect content is missing or contradictory")
			}
		default:
			return nil, refuse(ImportMalformedArtifact, ident, e.Position, "unknown effect")
		}
		if e.TypeIdentity != o.TypeIdentity {
			return nil, refuse(ImportHistoryInconsistent, ident, e.Position, "entry Type Identity %q differs from the object's", e.TypeIdentity)
		}
		if e.TypeVersion != o.TypeVersion {
			return nil, refuse(ImportHistoryInconsistent, ident, e.Position, "entry Type Version %q differs from the object's", e.TypeVersion)
		}
	}

	if o.GovernanceReference == nil || *o.GovernanceReference == "" {
		return nil, refuse(ImportGovernanceReferenceMissing, ident, 0, "object carries no governance reference")
	}
	local, ok := r.governance[pt.Binding()]
	if !ok || string(local) != *o.GovernanceReference {
		return nil, refuse(ImportUnresolvedGovernance, ident, 0,
			"%q does not resolve for %s@%s under local governance", *o.GovernanceReference, o.TypeIdentity, o.TypeVersion)
	}

	if err := statefold.ValidateState(pt, behavior, o.AcceptedState); err != nil {
		return nil, refuse(ImportStateNotValidForType, ident, 0, "accepted_state: %v", err)
	}
	for _, e := range o.History {
		if e.PostImage != nil {
			if err := statefold.ValidateState(pt, behavior, e.PostImage); err != nil {
				return nil, refuse(ImportStateNotValidForType, ident, e.Position, "post_image: %v", err)
			}
		}
	}

	type relList struct {
		where    string
		rels     []ImportRelationship
		position int
	}
	lists := []relList{{"relationships", o.Relationships, 0}}
	for _, e := range o.History {
		if e.HasBaseline {
			lists = append(lists, relList{"baseline relationships", e.BaselineRelationships, e.Position})
		}
	}
	evidence := false
	for _, l := range lists {
		keys := map[[3]string]bool{}
		for _, rel := range l.rels {
			if rel.Source != ident || rel.Type == "" || rel.Target == "" {
				return nil, refuse(ImportMalformedArtifact, ident, l.position, "%s: triple source %q is not the object", l.where, rel.Source)
			}
			if keys[rel.key()] {
				return nil, refuse(ImportDuplicateRelationship, ident, l.position, "%s: triple %v listed more than once", l.where, rel.key())
			}
			keys[rel.key()] = true
			evidence = evidence || rel.HasEvidence
		}
	}
	for _, e := range o.History {
		if e.Relationship != nil {
			if e.Relationship.Source != ident || e.Relationship.Type == "" || e.Relationship.Target == "" {
				return nil, refuse(ImportMalformedArtifact, ident, e.Position, "triple source is not the object")
			}
			evidence = evidence || e.Relationship.HasEvidence
		}
	}
	if evidence {
		*notes = append(*notes, ident+": relationship target-type/metadata evidence not retained (informational)")
	}

	current, ref := NativeVersion(o.CurrentObjectVersion, ident, 0)
	if ref != nil {
		return nil, ref
	}
	natives := map[core.ObjectVersion]string{}
	for _, e := range o.History {
		v, ref := NativeVersion(e.ResultingObjectVersion, ident, e.Position)
		if ref != nil {
			return nil, ref
		}
		if prior, dup := natives[v]; dup {
			return nil, refuse(ImportVersionTokenReuse, ident, e.Position,
				"resulting Object Version %q collides with %q natively; tokens are never merged or repaired", e.ResultingObjectVersion, prior)
		}
		natives[v] = e.ResultingObjectVersion
	}

	if len(o.History) == 0 {
		return nil, refuse(ImportHistoryIncomplete, ident, 0, "history is empty")
	}
	ordered := append([]ImportEntry(nil), o.History...)
	sort.SliceStable(ordered, func(a, b int) bool { return ordered[a].Position < ordered[b].Position })
	for i, e := range ordered {
		if e.Position != i+1 {
			positions := make([]int, len(ordered))
			for j, x := range ordered {
				positions[j] = x.Position
			}
			return nil, refuse(ImportHistoryInconsistent, ident, 0, "positions are not exactly 1..n: %v", positions)
		}
	}
	if ordered[0].Effect != EffectCreate {
		return nil, refuse(ImportHistoryIncomplete, ident, 1, "position 1 is not a creation baseline")
	}
	if last := ordered[len(ordered)-1].ResultingObjectVersion; last != o.CurrentObjectVersion {
		return nil, refuse(ImportHistoryInconsistent, ident, 0, "current Object Version %q is not the last entry's %q", o.CurrentObjectVersion, last)
	}

	lc := pt.LifecycleField()
	var state map[string]string
	var rels []core.Relationship
	evts := make([]events.CanonicalEvent, 0, len(ordered))
	for _, e := range ordered {
		priorState := copyMap(state)
		priorRels := slices.Clone(rels)
		evt := events.CanonicalEvent{
			CanonicalID:      core.CanonicalIdentity(ident),
			TypeIdentity:     pt.Identity,
			TypeVersion:      pt.Version,
			ResultingVersion: mustVersion(e.ResultingObjectVersion),
		}
		if a := e.Evidence.Actor; a != nil {
			if *a == "" {
				return nil, refuse(ImportUnsupportedSemanticFeature, ident, e.Position, "empty actor evidence is indistinguishable from absent evidence natively")
			}
			evt.Actor = core.Actor(*a)
		}
		if at := e.Evidence.AcceptedAt; at != nil {
			t, ref := NativeAcceptedAt(*at, ident, e.Position)
			if ref != nil {
				return nil, ref
			}
			evt.Timestamp = t
		}
		switch e.Effect {
		case EffectCreate:
			if e.Position != 1 {
				return nil, refuse(ImportHistoryInconsistent, ident, e.Position, "creation entry after position 1")
			}
			if len(e.BaselineRelationships) > 0 {
				return nil, refuse(ImportUnsupportedSemanticFeature, ident, e.Position,
					"creation baseline relationships are not representable: Go creation carries no relationships")
			}
			state = copyMap(e.PostImage)
			evt.Kind = events.KindCreated
			evt.PostImage = copyMap(state)
		case EffectStateChange:
			if lc != "" && e.PostImage[lc] != state[lc] {
				return nil, refuse(ImportHistoryNotValidForType, ident, e.Position,
					"state_change alters the lifecycle; lifecycle changes must be lifecycle_transition")
			}
			changed := map[string]string{}
			for k, v := range e.PostImage {
				if state[k] != v {
					changed[k] = v
				}
			}
			state = copyMap(e.PostImage)
			evt.Kind = events.KindStateUpdated
			evt.Payload = changed
			evt.PostImage = copyMap(state)
		case EffectLifecycleTransition:
			if lc == "" {
				return nil, refuse(ImportHistoryNotValidForType, ident, e.Position, "%s declares no lifecycle", o.TypeIdentity)
			}
			from, to := state[lc], e.PostImage[lc]
			if err := pt.ValidateLifecycleTransition(from, to); err != nil {
				return nil, refuse(ImportHistoryNotValidForType, ident, e.Position,
					"lifecycle transition %q -> %q is not permitted by %s@%s", from, to, o.TypeIdentity, o.TypeVersion)
			}
			state = copyMap(e.PostImage)
			evt.Kind = events.KindLifecycleTransition
			evt.Payload = map[string]string{"from": from, "to": to}
			evt.PostImage = copyMap(state)
		case EffectRelationshipAdd, EffectRelationshipRemove:
			rel := core.Relationship{
				Source: core.CanonicalIdentity(ident),
				Type:   core.RelationshipType(e.Relationship.Type),
				Target: core.CanonicalIdentity(e.Relationship.Target),
			}
			idx := relationshipIndex(rels, rel.Type, rel.Target)
			if e.Effect == EffectRelationshipAdd {
				if idx >= 0 {
					return nil, refuse(ImportMultisetHistory, ident, e.Position, "addition of already-present triple %v", e.Relationship.key())
				}
				rels = append(rels, rel)
				evt.Kind = events.KindRelationshipAdded
			} else {
				if idx < 0 {
					return nil, refuse(ImportHistoryInconsistent, ident, e.Position, "removal of absent triple %v", e.Relationship.key())
				}
				rels = append(rels[:idx:idx], rels[idx+1:]...)
				evt.Kind = events.KindRelationshipRemoved
			}
			evt.Payload = map[string]string{"relationship_type": e.Relationship.Type, "target": e.Relationship.Target}
		default:
			return nil, refuse(ImportMalformedArtifact, ident, e.Position, "unknown effect %q", e.Effect)
		}
		if evt.Kind == events.KindRelationshipAdded || evt.Kind == events.KindRelationshipRemoved {
			folded, err := statefold.Relationship(evt.CanonicalID, priorRels, evt)
			if err != nil {
				return nil, refuse(ImportHistoryInconsistent, ident, e.Position, "invalid relationship effect")
			}
			rels = folded
		} else {
			folded, err := statefold.State(pt, behavior, priorState, types.StateEffect{Kind: evt.Kind, Payload: evt.Payload, PostImage: evt.PostImage})
			if err != nil {
				return nil, refuse(ImportHistoryNotValidForType, ident, e.Position, "invalid exact state effect")
			}
			state = folded
		}
		if e.Evidence.Action != nil {
			*notes = append(*notes, fmt.Sprintf("%s@%d: action evidence %q not retained; the native event kind %q encodes the effect (informational)", ident, e.Position, *e.Evidence.Action, evt.Kind))
		}
		if e.Evidence.SourceEventID != nil {
			*notes = append(*notes, fmt.Sprintf("%s@%d: source_event_id evidence not retained (excluded dimension)", ident, e.Position))
		}
		evts = append(evts, evt)
	}

	if !equalMaps(state, o.AcceptedState) {
		return nil, refuse(ImportHistorySnapshotMismatch, ident, 0, "accepted_state is not the state the history produces")
	}
	declared := map[[3]string]bool{}
	for _, rel := range o.Relationships {
		declared[rel.key()] = true
	}
	if len(declared) != len(rels) {
		return nil, refuse(ImportHistorySnapshotMismatch, ident, 0, "relationship set is not the set the history produces")
	}
	for _, rel := range rels {
		if !declared[[3]string{string(rel.Source), string(rel.Type), string(rel.Target)}] {
			return nil, refuse(ImportHistorySnapshotMismatch, ident, 0, "relationship set is not the set the history produces")
		}
	}

	// Imported tokens need not be monotonic, so the current version alone
	// does not bound them.
	highWater := current
	for _, e := range evts {
		if e.ResultingVersion > highWater {
			highWater = e.ResultingVersion
		}
	}
	return &store.ObjectRecord{
		CanonicalID:         core.CanonicalIdentity(ident),
		TypeIdentity:        pt.Identity,
		TypeVersion:         pt.Version,
		ObjectVersion:       current,
		Relationships:       rels,
		CanonicalEvents:     evts,
		Attributes:          copyMap(o.AcceptedState),
		GovernanceReference: local,
		VersionHighWater:    highWater,
	}, nil
}

// mustVersion parses a token already checked by NativeVersion.
func mustVersion(token string) core.ObjectVersion {
	n, _ := strconv.ParseInt(token, 10, 64)
	return core.ObjectVersion(n)
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
