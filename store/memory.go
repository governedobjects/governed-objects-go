// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package store

import (
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/events"
)

// ObjectRecord holds semantic components of a Governed Object (CORE-STATE-001).
type ObjectRecord struct {
	CanonicalID     core.CanonicalIdentity
	TypeIdentity    core.TypeIdentity
	TypeVersion     core.TypeVersion
	ObjectVersion   core.ObjectVersion
	Relationships   []core.Relationship
	CanonicalEvents []events.CanonicalEvent
	AuditRecords    []events.AuditRecord
	// EXPERIMENTAL. Attributes is the Accepted
	// Canonical State of an object, always a nonnil complete map when admitted.
	// GovernanceReference is recorded at creation and never recomputed.
	Attributes          map[string]string
	GovernanceReference core.GovernanceReference
	// EXPERIMENTAL. VersionHighWater
	// is the highest Object Version ever issued for the object: allocation
	// metadata, never canonical state and never exported. Zero means "equal to
	// ObjectVersion", which holds for every object whose versions only increased.
	VersionHighWater core.ObjectVersion
}

// MemoryStore is an in-memory persistence layer (non-normative).
type MemoryStore struct {
	mu       sync.RWMutex
	objects  map[core.CanonicalIdentity]*ObjectRecord
	seq      int64
	auditSeq int64
	imports  []ImportRecord
}

// ImportRecord is Operational Metadata about one new-target interchange
// import (EXPERIMENTAL). It is kept
// outside every ObjectRecord and is never Canonical History.
type ImportRecord struct {
	ImportID             string                   `json:"import_id"`
	ImportedAt           time.Time                `json:"imported_at"`
	ImportingActor       core.Actor               `json:"importing_actor"`
	Identities           []core.CanonicalIdentity `json:"identities"`
	SourceImplementation string                   `json:"source_implementation,omitempty"`
	ArtifactSHA256       string                   `json:"artifact_sha256,omitempty"`
	Adapter              string                   `json:"adapter,omitempty"`
	ExperimentRevision   string                   `json:"experiment_revision"`
	EvidenceNotes        []string                 `json:"evidence_notes"`
}

// IdentityCollision refuses a commit whose identities already exist.
type IdentityCollision struct{ Identities []core.CanonicalIdentity }

func (e *IdentityCollision) Error() string {
	return fmt.Sprintf("identities already exist: %v", e.Identities)
}

// CommitImport stores fully validated restored records as one unit. Under a
// single lock it re-checks that every identity is absent, then assigns the
// store-global event sequence numbers and puts every record. Either all
// records and the import record are stored, or nothing (including the
// sequence counter) changes.
func (s *MemoryStore) CommitImport(records []*ObjectRecord, rec ImportRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var present []core.CanonicalIdentity
	owned := make([]*ObjectRecord, len(records))
	seen := make(map[core.CanonicalIdentity]bool, len(records))
	for i, r := range records {
		if r == nil || r.CanonicalID == "" {
			return fmt.Errorf("invalid import record")
		}
		if seen[r.CanonicalID] {
			return fmt.Errorf("duplicate import identity")
		}
		seen[r.CanonicalID] = true
		owned[i] = r.Clone()
		if _, ok := s.objects[r.CanonicalID]; ok {
			present = append(present, r.CanonicalID)
		}
	}
	if len(present) > 0 {
		return &IdentityCollision{Identities: present}
	}
	for _, r := range owned {
		for i := range r.CanonicalEvents {
			s.seq++
			r.CanonicalEvents[i].Sequence = s.seq
		}
	}
	for _, r := range owned {
		s.objects[r.CanonicalID] = r
	}
	rec.Identities = slices.Clone(rec.Identities)
	rec.EvidenceNotes = slices.Clone(rec.EvidenceNotes)
	s.imports = append(s.imports, rec)
	return nil
}

// Imports returns the import provenance records in commit order.
func (s *MemoryStore) Imports() []ImportRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ImportRecord, len(s.imports))
	copy(out, s.imports)
	for i := range out {
		out[i].Identities = slices.Clone(out[i].Identities)
		out[i].EvidenceNotes = slices.Clone(out[i].EvidenceNotes)
	}
	return out
}

// Counters returns the store-global event and audit sequence counters.
func (s *MemoryStore) Counters() (events, audit int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.seq, s.auditSeq
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		objects: make(map[core.CanonicalIdentity]*ObjectRecord),
	}
}

func (s *MemoryStore) Get(id core.CanonicalIdentity) (*ObjectRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	obj, ok := s.objects[id]
	return obj, ok
}

func (s *MemoryStore) Put(obj *ObjectRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[obj.CanonicalID] = obj
}

func (s *MemoryStore) NextEventSequence() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return s.seq
}

func (s *MemoryStore) NextAuditSequence() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditSeq++
	return s.auditSeq
}

func (s *MemoryStore) All() map[core.CanonicalIdentity]*ObjectRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[core.CanonicalIdentity]*ObjectRecord, len(s.objects))
	for k, v := range s.objects {
		out[k] = v
	}
	return out
}

func (s *MemoryStore) Snapshot(id core.CanonicalIdentity) (*ObjectRecord, error) {
	obj, ok := s.Get(id)
	if !ok {
		return nil, fmt.Errorf("object %q not found", id)
	}
	return obj.Clone(), nil
}

// Clone returns a deep copy of obj sharing no map or slice with it, or nil
// for a nil obj.
func (obj *ObjectRecord) Clone() *ObjectRecord {
	if obj == nil {
		return nil
	}
	copyRel := slices.Clone(obj.Relationships)
	copyEvents := slices.Clone(obj.CanonicalEvents)
	for i := range copyEvents {
		copyEvents[i].Payload = copyStrings(copyEvents[i].Payload)
		copyEvents[i].PostImage = copyStrings(copyEvents[i].PostImage)
	}
	copyAudit := slices.Clone(obj.AuditRecords)
	return &ObjectRecord{
		CanonicalID:         obj.CanonicalID,
		TypeIdentity:        obj.TypeIdentity,
		TypeVersion:         obj.TypeVersion,
		ObjectVersion:       obj.ObjectVersion,
		Relationships:       copyRel,
		CanonicalEvents:     copyEvents,
		AuditRecords:        copyAudit,
		Attributes:          copyStrings(obj.Attributes),
		GovernanceReference: obj.GovernanceReference,
		VersionHighWater:    obj.VersionHighWater,
	}
}

func copyStrings(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
