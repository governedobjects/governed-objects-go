// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package store_test

import (
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/events"
	"github.com/governedobjects/governed-objects-go/store"
	"reflect"
	"testing"
)

func TestCommitImportOwnsClonesAndFailureChangesNothing(t *testing.T) {
	s := store.NewMemoryStore()
	record := &store.ObjectRecord{CanonicalID: "one", Attributes: map[string]string{"value": "original"}, CanonicalEvents: []events.CanonicalEvent{{PostImage: map[string]string{"value": "original"}}}}
	meta := store.ImportRecord{Identities: []core.CanonicalIdentity{"one"}, EvidenceNotes: []string{"original"}}
	if err := s.CommitImport([]*store.ObjectRecord{record}, meta); err != nil {
		t.Fatal(err)
	}
	if record.CanonicalEvents[0].Sequence != 0 {
		t.Fatal("caller sequence changed")
	}
	record.Attributes["value"] = "forged"
	record.CanonicalEvents[0].PostImage["value"] = "forged"
	meta.Identities[0] = "forged"
	meta.EvidenceNotes[0] = "forged"
	owned, _ := s.Snapshot("one")
	if owned.Attributes["value"] != "original" || owned.CanonicalEvents[0].PostImage["value"] != "original" || owned.CanonicalEvents[0].Sequence != 1 || s.Imports()[0].Identities[0] != "one" || s.Imports()[0].EvidenceNotes[0] != "original" {
		t.Fatal("import caller alias")
	}
	before := s.Imports()
	seq, audit := s.Counters()
	if s.CommitImport([]*store.ObjectRecord{{CanonicalID: "new"}, {CanonicalID: "one"}}, meta) == nil {
		t.Fatal("collision accepted")
	}
	afterSeq, afterAudit := s.Counters()
	if seq != afterSeq || audit != afterAudit || !reflect.DeepEqual(before, s.Imports()) || len(s.All()) != 1 {
		t.Fatal("failed commit had effects")
	}
	if s.CommitImport([]*store.ObjectRecord{{CanonicalID: "two"}, {CanonicalID: "two"}}, meta) == nil {
		t.Fatal("duplicate batch identity")
	}
}

func TestClonePreservesPresence(t *testing.T) {
	for _, obj := range []*store.ObjectRecord{{}, {Attributes: map[string]string{}, Relationships: []core.Relationship{}, CanonicalEvents: []events.CanonicalEvent{}, AuditRecords: []events.AuditRecord{}}} {
		copy := obj.Clone()
		if !reflect.DeepEqual(obj, copy) {
			t.Fatal("nil/empty presence changed")
		}
	}
}
