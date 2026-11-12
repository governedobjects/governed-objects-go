// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package interchange_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/governedobjects/governed-objects-go/auth"
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/interchange"
	"github.com/governedobjects/governed-objects-go/runtime"
	"github.com/governedobjects/governed-objects-go/store"
	"github.com/governedobjects/governed-objects-go/types"
)

// Independent synthetic public API fixture; no private or internal test helpers.
type r3bPolicy struct {
	base   auth.Authorizer
	calls  int
	onRead func()
}

func (p *r3bPolicy) Allowed(a core.Actor, op core.Action, id core.TypeIdentity) bool {
	p.calls++
	if op == core.ActionRead && p.onRead != nil {
		p.onRead()
	}
	return p.base.Allowed(a, op, id)
}

type r3bFixture struct {
	r     *runtime.Runtime
	s     *store.MemoryStore
	a     *r3bPolicy
	hooks *int
	defs  []types.PortableType
}

func r3bNew(t *testing.T, pairs []interchange.Binding) r3bFixture {
	t.Helper()
	s := store.NewMemoryStore()
	a := &r3bPolicy{base: auth.NewGrantAuthorizer(map[core.Actor][]auth.Capability{"owner": {auth.CapCreate, auth.CapRead, auth.CapUpdate, auth.CapAddRelationship, auth.CapImport}})}
	r := runtime.NewRuntime(s, a)
	hooks := new(int)
	f := r3bFixture{r: r, s: s, a: a, hooks: hooks}
	gov := map[types.Binding]core.GovernanceReference{}
	for _, pair := range pairs {
		d := types.PortableType{Identity: core.TypeIdentity(pair.TypeIdentity), Version: core.TypeVersion(pair.TypeVersion), Fields: map[string]types.FieldKind{"v": types.FieldString}, RelationshipTypes: []string{"links"}}
		b, err := types.NewPortableBehavior(d)
		if err != nil {
			t.Fatal(err)
		}
		vs, vc, vu, vt, rd := b.ValidateState, b.ValidateCreate, b.ValidateUpdate, b.ValidateTransition, b.Reduce
		b.ValidateState = func(x map[string]string) error { *hooks++; return vs(x) }
		b.ValidateCreate = func(x map[string]string) error { *hooks++; return vc(x) }
		b.ValidateUpdate = func(x, y map[string]string) error { *hooks++; return vu(x, y) }
		b.ValidateTransition = func(x map[string]string, y string) error { *hooks++; return vt(x, y) }
		b.Reduce = func(x map[string]string, y types.StateEffect) (map[string]string, error) { *hooks++; return rd(x, y) }
		if err := r.RegisterType(d, b); err != nil {
			t.Fatal(err)
		}
		gov[d.Binding()] = core.GovernanceReference("rules/" + pair.TypeIdentity)
		f.defs = append(f.defs, d)
	}
	r.SetGovernance(gov)
	return f
}
func r3bPairs() []interchange.Binding {
	return []interchange.Binding{{TypeIdentity: "pair@left", TypeVersion: "right"}, {TypeIdentity: "pair", TypeVersion: "left@right"}}
}
func r3bContext(op core.Action) core.OperationContext {
	return core.OperationContext{Actor: "owner", Action: op}
}
func (f r3bFixture) create(t *testing.T, id core.CanonicalIdentity, which int) {
	t.Helper()
	out, _ := f.r.CreateObject(r3bContext(core.ActionCreate), id, f.defs[which].Binding(), map[string]string{"v": string(id)})
	if out.Kind != core.OutcomeAccepted {
		t.Fatal(out)
	}
}
func r3bDump(t *testing.T, s *store.MemoryStore) string {
	t.Helper()
	e, a := s.Counters()
	raw, err := json.Marshal(struct {
		All           map[core.CanonicalIdentity]*store.ObjectRecord
		Imports       []store.ImportRecord
		Events, Audit int64
	}{s.All(), s.Imports(), e, a})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
func r3bExport(t *testing.T, f r3bFixture, ids ...core.CanonicalIdentity) *interchange.Bundle {
	t.Helper()
	b, err := interchange.Export(f.r, interchange.Request{Actor: "owner", Identities: ids})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func r3bClone(t *testing.T, b *interchange.Bundle) *interchange.Bundle {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var c interchange.Bundle
	if err = json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}
func r3bDecode(t *testing.T, b *interchange.Bundle) (*runtime.ImportBundle, *runtime.ImportRefusal) {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return interchange.DecodeArtifact(raw)
}
func r3bRevision(b *interchange.Bundle, rev int) {
	if rev == 1 {
		b.Manifest.ArtifactRevision = interchange.ArtifactRevisionV1
		b.Manifest.ArtifactStatus = interchange.ArtifactStatusV1
		b.Manifest.SpecRevision = interchange.SpecRevisionV1
	}
}

func TestR3BRepeatedSelectionPreflight(t *testing.T) {
	for _, state := range []string{"present", "absent", "denied", "unsupported", "corrupt-cache", "missing-governance", "unclassifiable"} {
		for pattern := 0; pattern < 3; pattern++ {
			for _, closed := range []bool{false, true} {
				for _, times := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/pattern%d/closed%t/times%t", state, pattern, closed, times), func(t *testing.T) {
						f := r3bNew(t, r3bPairs())
						f.create(t, "a", 0)
						f.create(t, "b", 1)
						id := core.CanonicalIdentity("a")
						actor := core.Actor("owner")
						obj, _ := f.s.Get(id)
						switch state {
						case "absent":
							id = "absent"
						case "denied":
							actor = "outsider"
						case "unsupported":
							obj.TypeVersion = "unsupported"
						case "corrupt-cache":
							obj.Attributes["v"] = "corrupt"
						case "missing-governance":
							obj.GovernanceReference = ""
						case "unclassifiable":
							obj.CanonicalEvents[0].PostImage = nil
						}
						patterns := [][]core.CanonicalIdentity{{id, id}, {id, "b", id}, {id, "b", id, "b"}}
						ids := patterns[pattern]
						saved := append([]core.CanonicalIdentity(nil), ids...)
						before := r3bDump(t, f.s)
						f.a.calls = 0
						*f.hooks = 0
						now := 0
						b, err := interchange.Export(f.r, interchange.Request{Actor: actor, Identities: ids, Closed: closed, IncludeTimestamps: times, Now: func() time.Time { now++; return time.Unix(0, 0) }})
						ref, ok := err.(*interchange.Refusal)
						if b != nil || !ok || ref.Code != runtime.ImportDuplicateIdentityInBundle || ref.Message != "export selection contains repeated identities" || ref.Identity != "" {
							t.Fatalf("wrong refusal: %#v %v", b, err)
						}
						if f.a.calls != 0 || *f.hooks != 0 || now != 0 || r3bDump(t, f.s) != before || !reflect.DeepEqual(ids, saved) {
							t.Fatal("preflight had callbacks, state/provenance/counter/highwater effects or changed caller slice")
						}
					})
				}
			}
		}
	}
	t.Run("nil-runtime", func(t *testing.T) {
		b, err := interchange.Export(nil, interchange.Request{Identities: []core.CanonicalIdentity{"x", "x"}})
		if b != nil || err == nil {
			t.Fatal("nil runtime duplicate preflight")
		}
	})
}

func TestR3BUniqueSnapshotAndOptions(t *testing.T) {
	for _, closed := range []bool{false, true} {
		for _, times := range []bool{false, true} {
			t.Run(fmt.Sprintf("closed%t/times%t", closed, times), func(t *testing.T) {
				f := r3bNew(t, r3bPairs()[:1])
				ids := []core.CanonicalIdentity{"A", "a", " white ", "\u03bb@x", "x@y"}
				for _, id := range ids {
					f.create(t, id, 0)
				}
				now := 0
				before := r3bDump(t, f.s)
				b, err := interchange.Export(f.r, interchange.Request{Actor: "owner", Identities: ids, Closed: closed, IncludeTimestamps: times, SourceImplementation: "synthetic", Now: func() time.Time { now++; return time.Unix(0, 0) }})
				if err != nil || b.Manifest.Closed != closed || len(b.Objects) != len(ids) {
					t.Fatal(err)
				}
				for i, id := range ids {
					if b.Objects[i].CanonicalIdentity != string(id) || b.Manifest.Identities[i] != string(id) {
						t.Fatal("order/opaque identity changed")
					}
				}
				if b.Manifest.Provenance == nil || b.Manifest.Provenance.SourceImplementation != "synthetic" || times != (b.Manifest.Provenance.ExportedAt != "") || times != (b.Objects[0].History[0].AcceptedAt != "") || now != map[bool]int{false: 0, true: 1}[times] {
					t.Fatal("timestamp/provenance options")
				}
				if r3bDump(t, f.s) != before {
					t.Fatal("unique export effects")
				}
			})
		}
	}
	t.Run("callback-mutates-original-slice", func(t *testing.T) {
		f := r3bNew(t, r3bPairs()[:1])
		f.create(t, "a", 0)
		f.create(t, "b", 0)
		ids := []core.CanonicalIdentity{"a", "b"}
		f.a.onRead = func() { ids[1] = "absent" }
		b, err := interchange.Export(f.r, interchange.Request{Actor: "owner", Identities: ids})
		if err != nil || b.Objects[1].CanonicalIdentity != "b" || ids[1] != "absent" {
			t.Fatal("validated selection did not survive callback mutation", err)
		}
	})
	t.Run("unique-denial-still-governed", func(t *testing.T) {
		f := r3bNew(t, r3bPairs()[:1])
		f.create(t, "a", 0)
		b, err := interchange.Export(f.r, interchange.Request{Actor: "outsider", Identities: []core.CanonicalIdentity{"a"}})
		ref, ok := err.(*interchange.Refusal)
		if b != nil || !ok || ref.Code != interchange.AuthorizationDenied {
			t.Fatal(err)
		}
	})
	t.Run("empty-selection", func(t *testing.T) {
		f := r3bNew(t, r3bPairs()[:1])
		b := r3bExport(t, f)
		if len(b.Objects) != 0 || len(b.Manifest.Identities) != 0 || len(b.Manifest.TypeBindings) != 0 {
			t.Fatal("empty selection changed")
		}
		decoded, ref := r3bDecode(t, b)
		if ref != nil {
			t.Fatal(ref)
		}
		before := r3bDump(t, f.s)
		_, ref = f.r.ImportBundle(r3bContext(core.ActionImport), *decoded, runtime.ImportProvenance{})
		if ref == nil || ref.Code != runtime.ImportMalformedArtifact || ref.Message != "bundle contains no objects" || r3bDump(t, f.s) != before {
			t.Fatal("baseline empty native refusal", ref)
		}
	})
}

func TestR3BExactBindingDeclarations(t *testing.T) {
	for _, revision := range []int{1, 2} {
		for _, kind := range []string{"one", "two-colliding", "shared-actual", "missing", "extra", "swapped", "substitution", "duplicate", "malformed"} {
			t.Run(fmt.Sprintf("v%d/%s", revision, kind), func(t *testing.T) {
				pairs := r3bPairs()
				f := r3bNew(t, pairs)
				f.create(t, "a", 0)
				ids := []core.CanonicalIdentity{"a"}
				if kind != "one" && kind != "substitution" {
					which := 1
					if kind == "shared-actual" {
						which = 0
					}
					f.create(t, "b", which)
					ids = append(ids, "b")
				}
				b := r3bExport(t, f, ids...)
				r3bRevision(b, revision)
				switch kind {
				case "missing":
					b.Manifest.TypeBindings = b.Manifest.TypeBindings[:1]
				case "extra":
					b.Manifest.TypeBindings = append(b.Manifest.TypeBindings, interchange.Binding{TypeIdentity: "extra", TypeVersion: "v"})
				case "swapped":
					b.Manifest.TypeBindings = []interchange.Binding{{TypeIdentity: pairs[0].TypeIdentity, TypeVersion: pairs[1].TypeVersion}, {TypeIdentity: pairs[1].TypeIdentity, TypeVersion: pairs[0].TypeVersion}}
				case "substitution":
					b.Manifest.TypeBindings = []interchange.Binding{pairs[1]}
				case "duplicate":
					b.Manifest.TypeBindings = append(b.Manifest.TypeBindings, b.Manifest.TypeBindings[0])
				case "malformed":
					b.Manifest.TypeBindings[0].TypeVersion = ""
				}
				dest := r3bNew(t, pairs)
				before := r3bDump(t, dest.s)
				decoded, ref := r3bDecode(t, b)
				positive := kind == "one" || kind == "two-colliding" || kind == "shared-actual"
				if !positive {
					if ref == nil || decoded != nil || ref.Code != runtime.ImportMalformedArtifact || !strings.Contains(ref.Message, "type_bindings") || ref.Identity != "" || ref.Position != 0 {
						t.Fatalf("wrong declaration accepted/shaped: %#v", ref)
					}
					if r3bDump(t, dest.s) != before {
						t.Fatal("decode pipeline effects")
					}
					return
				}
				if ref != nil {
					t.Fatal(ref)
				}
				if _, ref = dest.r.ImportBundle(r3bContext(core.ActionImport), *decoded, runtime.ImportProvenance{}); ref != nil {
					t.Fatal(ref)
				}
				if len(dest.s.All()) != len(ids) || len(dest.s.Imports()) != 1 {
					t.Fatal("positive native import missing")
				}
				for _, id := range ids {
					got, _ := dest.s.Get(id)
					if got.Attributes["v"] != string(id) {
						t.Fatal("positive state")
					}
				}
			})
		}
	}
}

func TestR3BExistingNativePairAndClosureBoundaries(t *testing.T) {
	for _, rev := range []int{1, 2} {
		for _, kind := range []string{"history-identity", "history-version", "unsupported-actual", "closed-open-link", "timestamp-artifact"} {
			t.Run(fmt.Sprintf("v%d/%s", rev, kind), func(t *testing.T) {
				f := r3bNew(t, r3bPairs()[:1])
				f.create(t, "a", 0)
				if kind == "closed-open-link" {
					out, _ := f.r.AddRelationship(r3bContext(core.ActionAddRelationship), "a", core.Relationship{Source: "a", Type: "links", Target: "external"})
					if out.Kind != core.OutcomeAccepted {
						t.Fatal(out)
					}
				}
				b := r3bExport(t, f, "a")
				r3bRevision(b, rev)
				switch kind {
				case "history-identity":
					b.Objects[0].History[0].TypeIdentity = "pair"
				case "history-version":
					b.Objects[0].History[0].TypeVersion = "left@right"
				case "unsupported-actual":
					b.Manifest.TypeBindings[0].TypeVersion = "unsupported"
					b.Objects[0].TypeVersion = "unsupported"
					b.Objects[0].History[0].TypeVersion = "unsupported"
				case "closed-open-link":
					b.Manifest.Closed = true
				case "timestamp-artifact":
					b.Objects[0].History[0].AcceptedAt = "2026-01-01T00:00:00+24:00"
				}
				dest := r3bNew(t, r3bPairs()[:1])
				before := r3bDump(t, dest.s)
				decoded, ref := r3bDecode(t, b)
				if kind == "timestamp-artifact" {
					if ref == nil || ref.Code != runtime.ImportMalformedArtifact {
						t.Fatal("strict artifact timestamp", ref)
					}
					if _, ref = runtime.NativeAcceptedAt("2026-01-01T00:00:00+24:00", "a", 1); ref != nil {
						t.Fatal("native timestamp boundary changed", ref)
					}
					return
				}
				if ref != nil {
					t.Fatal("decoder should leave native check", ref)
				}
				if kind == "closed-open-link" {
					open := *decoded
					open.Closed = false
					openDest := r3bNew(t, r3bPairs()[:1])
					if _, r := openDest.r.ImportBundle(r3bContext(core.ActionImport), open, runtime.ImportProvenance{}); r != nil {
						t.Fatal("open export/import changed", r)
					}
				}
				_, ref = dest.r.ImportBundle(r3bContext(core.ActionImport), *decoded, runtime.ImportProvenance{})
				want := runtime.ImportHistoryInconsistent
				if kind == "unsupported-actual" {
					want = runtime.ImportUnsupportedTypeVersion
				}
				if kind == "closed-open-link" {
					want = runtime.ImportBundleClosureViolated
				}
				if ref == nil || ref.Code != want || r3bDump(t, dest.s) != before {
					t.Fatal("native refusal/effects", ref)
				}
			})
		}
	}
}
