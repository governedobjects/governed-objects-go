// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package interchange_test

import (
	"encoding/json"
	"github.com/governedobjects/governed-objects-go/auth"
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/interchange"
	"github.com/governedobjects/governed-objects-go/internal/testtypes"
	"github.com/governedobjects/governed-objects-go/runtime"
	"github.com/governedobjects/governed-objects-go/store"
	"github.com/governedobjects/governed-objects-go/types"
	"maps"
	"testing"
)

func ctx(action core.Action) core.OperationContext {
	return core.OperationContext{Actor: "operator", Action: action}
}
func destination(t *testing.T, custom *types.Behavior) (*runtime.Runtime, *store.MemoryStore) {
	t.Helper()
	s := store.NewMemoryStore()
	r := runtime.NewRuntime(s, auth.NewGrantAuthorizer(map[core.Actor][]auth.Capability{"operator": {auth.CapCreate, auth.CapRead, auth.CapUpdate, auth.CapTransition, auth.CapAddRelationship, auth.CapRemoveRelationship, auth.CapImport}}))
	p, b := testtypes.Probe()
	m, mb := testtypes.Marker()
	if custom != nil {
		b = *custom
	}
	if r.RegisterType(p, b) != nil || r.RegisterType(m, mb) != nil {
		t.Fatal("registration")
	}
	r.SetGovernance(map[types.Binding]core.GovernanceReference{p.Binding(): "opaque-frame-rules", m.Binding(): "opaque-marker-rules"})
	return r, s
}
func must(t *testing.T, out core.Outcome, _ *store.ObjectRecord) {
	t.Helper()
	if out.Kind != core.OutcomeAccepted {
		t.Fatal(out)
	}
}
func source(t *testing.T) (*runtime.Runtime, *store.MemoryStore, *interchange.Bundle) {
	t.Helper()
	r, s := destination(t, nil)
	p, _ := testtypes.Probe()
	m, _ := testtypes.Marker()
	check := func(o core.Outcome, obj *store.ObjectRecord) { must(t, o, obj) }
	check(r.CreateObject(ctx(core.ActionCreate), "frame", p.Binding(), map[string]string{"signal": "#start", "phase": "idle"}))
	check(r.UpdateState(ctx(core.ActionUpdate), "frame", p.Binding(), map[string]string{"signal": "#next"}))
	check(r.TransitionLifecycle(ctx(core.ActionTransition), "frame", p.Binding(), "sent"))
	rel := core.Relationship{Source: "frame", Type: "links", Target: "external"}
	check(r.AddRelationship(ctx(core.ActionAddRelationship), "frame", rel))
	check(r.UpdateState(ctx(core.ActionUpdate), "frame", p.Binding(), map[string]string{"signal": "#final"}))
	check(r.RemoveRelationship(ctx(core.ActionRemoveRelationship), "frame", rel))
	check(r.TransitionLifecycle(ctx(core.ActionTransition), "frame", p.Binding(), "sealed"))
	check(r.CreateObject(ctx(core.ActionCreate), "marker", m.Binding(), map[string]string{"label": "point", "value": "12.3400"}))
	b, err := interchange.Export(r, interchange.Request{Identities: []core.CanonicalIdentity{"frame", "marker"}, Actor: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	return r, s, b
}
func semantic(t *testing.T, b *interchange.Bundle) runtime.ImportBundle {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	decoded, ref := interchange.DecodeArtifact(raw)
	if ref != nil {
		t.Fatal(ref)
	}
	return *decoded
}
func dump(s *store.MemoryStore) string {
	seq, audit := s.Counters()
	value := struct {
		Objects         map[core.CanonicalIdentity]*store.ObjectRecord
		Imports         []store.ImportRecord
		Sequence, Audit int64
	}{s.All(), s.Imports(), seq, audit}
	b, _ := json.Marshal(value)
	return string(b)
}

func TestNativeExportSingleStateAndHistoryConsistency(t *testing.T) {
	r, s, b := source(t)
	if b.Objects[0].AcceptedState["signal"] != "#final" || len(b.Objects[0].History) != 7 || b.Objects[1].AcceptedState["value"] != "12.3400" {
		t.Fatal("canonical export")
	}
	b.Objects[0].AcceptedState["signal"] = "#forged"
	(*b.Objects[0].History[0].PostImage)["signal"] = "#forged"
	fresh, err := interchange.Export(r, interchange.Request{Actor: "operator", Identities: []core.CanonicalIdentity{"frame"}})
	if err != nil || fresh.Objects[0].AcceptedState["signal"] != "#final" || (*fresh.Objects[0].History[0].PostImage)["signal"] != "#start" {
		t.Fatal("export alias")
	}
	obj, _ := s.Get("frame")
	obj.Attributes["signal"] = "#cache-corrupt"
	if _, err = interchange.Export(r, interchange.Request{Actor: "operator", Identities: []core.CanonicalIdentity{"frame"}}); err == nil {
		t.Fatal("cached state exported without history agreement")
	}
	obj.Attributes = maps.Clone(fresh.Objects[0].AcceptedState)
	obj.CanonicalEvents[1].PostImage = nil
	if _, err = interchange.Export(r, interchange.Request{Actor: "operator", Identities: []core.CanonicalIdentity{"frame"}}); err == nil {
		t.Fatal("missing image exported")
	}
}
