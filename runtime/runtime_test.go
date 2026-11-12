// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package runtime_test

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"testing"

	"github.com/governedobjects/governed-objects-go/auth"
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/events"
	"github.com/governedobjects/governed-objects-go/internal/testtypes"
	"github.com/governedobjects/governed-objects-go/replay"
	"github.com/governedobjects/governed-objects-go/runtime"
	"github.com/governedobjects/governed-objects-go/store"
	"github.com/governedobjects/governed-objects-go/types"
)

type policy func(core.Actor, core.Action, core.TypeIdentity) bool

func (p policy) Allowed(a core.Actor, b core.Action, c core.TypeIdentity) bool { return p(a, b, c) }
func context(a core.Actor, action core.Action, expected ...int64) core.OperationContext {
	c := core.OperationContext{Actor: a, Action: action}
	if len(expected) > 0 {
		v := core.ObjectVersion(expected[0])
		c.ExpectedVersion = &v
	}
	return c
}
func setup(t *testing.T) (*runtime.Runtime, *store.MemoryStore, types.Binding, types.Binding) {
	t.Helper()
	s := store.NewMemoryStore()
	r := runtime.NewRuntime(s, auth.NewGrantAuthorizer(map[core.Actor][]auth.Capability{
		"operator": {auth.CapCreate, auth.CapRead, auth.CapUpdate, auth.CapTransition, auth.CapAddRelationship, auth.CapRemoveRelationship, auth.CapImport},
		"observer": {auth.CapRead}, "blind-writer": {auth.CapUpdate, auth.CapTransition, auth.CapAddRelationship, auth.CapRemoveRelationship},
	}))
	p, pb := testtypes.Probe()
	m, mb := testtypes.Marker()
	if err := r.RegisterType(p, pb); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterType(m, mb); err != nil {
		t.Fatal(err)
	}
	return r, s, p.Binding(), m.Binding()
}
func canonical(t *testing.T, s *store.MemoryStore, id core.CanonicalIdentity) string {
	t.Helper()
	obj, err := s.Snapshot(id)
	if err != nil {
		t.Fatal(err)
	}
	obj.AuditRecords = nil
	b, _ := json.Marshal(obj)
	return string(b)
}
func accepted(t *testing.T, out core.Outcome, obj *store.ObjectRecord) *store.ObjectRecord {
	t.Helper()
	if out.Kind != core.OutcomeAccepted || obj == nil {
		t.Fatalf("not accepted: %+v %v", out, obj)
	}
	return obj
}
func create(t *testing.T, r *runtime.Runtime, b types.Binding) *store.ObjectRecord {
	t.Helper()
	out, obj := r.CreateObject(context("operator", core.ActionCreate), "frame", b, map[string]string{"signal": "#first", "phase": "idle"})
	return accepted(t, out, obj)
}

func TestExplicitRegistrationAndDenyAll(t *testing.T) {
	s := store.NewMemoryStore()
	r := runtime.NewRuntime(s, auth.NewStaticAuthorizer())
	p, b := testtypes.Probe()
	for _, id := range []core.TypeIdentity{p.Identity, "example.work-item", "example.party"} {
		if _, ok := r.PortableType(id); ok {
			t.Fatal("implicit registration")
		}
	}
	for _, actor := range []core.Actor{"alice", "bob", "unknown"} {
		for _, action := range []core.Action{core.ActionCreate, core.ActionRead, core.ActionUpdate, core.ActionTransition, core.ActionAddRelationship, core.ActionRemoveRelationship, core.ActionImport} {
			if auth.NewStaticAuthorizer().Allowed(actor, action, p.Identity) {
				t.Fatal("implicit grants")
			}
		}
	}
	if err := r.RegisterType(p, b); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterType(p, b); err == nil {
		t.Fatal("same binding replaced")
	}
	changed := p.Clone()
	changed.Version = "other"
	if r.RegisterType(changed, b) == nil {
		t.Fatal("second version registered")
	}
	for i := 0; i < 5; i++ {
		q := p.Clone()
		q.Identity = core.TypeIdentity(fmt.Sprint("missing", i))
		missing := b
		switch i {
		case 0:
			missing.ValidateState = nil
		case 1:
			missing.ValidateCreate = nil
		case 2:
			missing.ValidateUpdate = nil
		case 3:
			missing.ValidateTransition = nil
		case 4:
			missing.Reduce = nil
		}
		if r.RegisterType(q, missing) == nil {
			t.Fatal("missing hook accepted")
		}
	}
	for _, id := range []core.TypeIdentity{"example.work-item", "example.party"} {
		q := types.PortableType{Identity: id, Version: "ordinary"}
		if r.RegisterPortableType(q) != nil {
			t.Fatal("identity reserved")
		}
	}
	out, obj := r.CreateObject(context("alice", core.ActionCreate), "denied", p.Binding(), map[string]string{"signal": "#x", "phase": "idle"})
	if out.Kind != core.OutcomeDenied || obj != nil || len(s.All()) != 0 {
		t.Fatal("deny-all bypass")
	}
}

func TestIndependentTypesAndExactRequests(t *testing.T) {
	r, s, p, m := setup(t)
	create(t, r, p)
	out, obj := r.CreateObject(context("operator", core.ActionCreate), "marker", m, map[string]string{"label": "point", "value": "12.3400"})
	obj = accepted(t, out, obj)
	if obj.Attributes["value"] != "12.3400" {
		t.Fatal("decimal normalized")
	}
	before := canonical(t, s, "frame")
	seq, _ := s.Counters()
	for name, run := range map[string]func() (core.Outcome, *store.ObjectRecord){
		"invalid-domain": func() (core.Outcome, *store.ObjectRecord) {
			return r.UpdateState(context("operator", core.ActionUpdate), "frame", p, map[string]string{"signal": "bad"})
		},
		"lifecycle-via-set": func() (core.Outcome, *store.ObjectRecord) {
			return r.UpdateState(context("operator", core.ActionUpdate), "frame", p, map[string]string{"phase": "sent"})
		},
		"wrong-binding": func() (core.Outcome, *store.ObjectRecord) {
			return r.UpdateState(context("operator", core.ActionUpdate), "frame", m, map[string]string{"signal": "#x"})
		},
		"stale": func() (core.Outcome, *store.ObjectRecord) {
			return r.UpdateState(context("operator", core.ActionUpdate, 99), "frame", p, map[string]string{"signal": "#x"})
		},
		"denied": func() (core.Outcome, *store.ObjectRecord) {
			return r.UpdateState(context("outsider", core.ActionUpdate, 1), "frame", p, map[string]string{"signal": "#x"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			out, _ := run()
			if out.Kind == core.OutcomeAccepted {
				t.Fatal("unexpected acceptance")
			}
			if canonical(t, s, "frame") != before {
				t.Fatal("rejection changed canonical data")
			}
			after, _ := s.Counters()
			if after != seq {
				t.Fatal("rejection allocated event")
			}
		})
	}
	q := types.Binding{Identity: p.Identity, Version: "unregistered"}
	out, _ = r.CreateObject(context("operator", core.ActionCreate), "unknown", q, map[string]string{"signal": "#x", "phase": "idle"})
	if out.Kind != core.OutcomeRefused {
		t.Fatal(out)
	}
	out, _ = r.UpdateState(context("operator", core.ActionUpdate), "frame", p, map[string]string{"signal": "#first"})
	if out.Version != 2 {
		t.Fatal("same-state revision lost")
	}
	out, _ = r.TransitionLifecycle(context("operator", core.ActionTransition), "frame", p, "idle")
	if out.Version != 3 {
		t.Fatal("self transition lost")
	}
	// No lifecycle is defined for the independent scalar type.
	out, _ = r.TransitionLifecycle(context("operator", core.ActionTransition), "marker", m, "sent")
	if out.Kind != core.OutcomeInvalid {
		t.Fatal(out)
	}
}

func TestUnsupportedReadAndSharedDisclosureFailClosed(t *testing.T) {
	allowRead := false
	s := store.NewMemoryStore()
	r := runtime.NewRuntime(s, policy(func(a core.Actor, action core.Action, _ core.TypeIdentity) bool {
		return action != core.ActionRead || a == "operator" || allowRead
	}))
	p, b := testtypes.Probe()
	if r.RegisterType(p, b) != nil {
		t.Fatal("registration")
	}
	create(t, r, p.Binding())
	denied, record := r.Read(context("requester", core.ActionRead), "frame")
	if denied.Kind != core.OutcomeDenied || denied.Version != 0 || record != nil {
		t.Fatal(denied)
	}
	stored, _ := s.Get("frame")
	stored.TypeVersion = "unsupported"
	allowRead = true
	before := canonical(t, s, "frame")
	for _, actor := range []core.Actor{"requester", "operator"} {
		out, obj := r.Read(context(actor, core.ActionRead), "frame")
		if out != denied || obj != nil {
			t.Fatalf("unsupported read differed: %+v %+v", out, denied)
		}
	}
	out, obj := r.UpdateState(context("requester", core.ActionUpdate, 99), "frame", p.Binding(), map[string]string{"signal": "#x"})
	if out.Kind != core.OutcomeRefused || out.Version != 0 || out.Reason != "refused" || obj != nil {
		t.Fatalf("shared disclosure leak: %+v %v", out, obj)
	}
	if canonical(t, s, "frame") != before {
		t.Fatal("unsupported access changed canonical data")
	}
	stored.TypeVersion = p.Version
	out, obj = r.Read(context("requester", core.ActionRead), "frame")
	accepted(t, out, obj)
	out, obj = r.UpdateState(context("requester", core.ActionUpdate, 99), "frame", p.Binding(), map[string]string{"signal": "#x"})
	if out.Kind != core.OutcomeConflict || out.Version != 1 || obj == nil {
		t.Fatal("supported diagnostics changed")
	}
	out, obj = runtime.NewRuntime(s, auth.NewGrantAuthorizer(map[core.Actor][]auth.Capability{"requester": {auth.CapRead}})).Read(context("requester", core.ActionRead), "frame")
	if out != denied || obj != nil {
		t.Fatal("missing definition disclosed")
	}
	out, _ = r.Read(context("requester", core.ActionRead), "absent")
	if out.Kind != core.OutcomeInvalid {
		t.Fatal("missing target classification changed")
	}
}

func TestLiveCallbackOwnershipPanicAndCapacity(t *testing.T) {
	for _, mode := range []string{"mutate", "error", "panic", "mismatch", "capacity"} {
		t.Run(mode, func(t *testing.T) {
			s := store.NewMemoryStore()
			r := runtime.NewRuntime(s, policy(func(core.Actor, core.Action, core.TypeIdentity) bool { return true }))
			p, b := testtypes.Probe()
			original := b.Reduce
			enabled := false
			var retained map[string]string
			b.Reduce = func(before map[string]string, e types.StateEffect) (map[string]string, error) {
				if !enabled {
					return original(before, e)
				}
				if before != nil {
					before["signal"] = "#vandalized"
				}
				e.Payload["signal"] = "#vandalized"
				switch mode {
				case "error":
					return nil, fmt.Errorf("private defect")
				case "panic":
					panic("trusted callback defect")
				case "mismatch":
					e.PostImage["signal"] = "#wrong"
				}
				retained = e.PostImage
				return e.PostImage, nil
			}
			if r.RegisterType(p, b) != nil {
				t.Fatal("registration")
			}
			create(t, r, p.Binding())
			enabled = true
			stored, _ := s.Get("frame")
			if mode == "capacity" {
				stored.VersionHighWater = math.MaxInt64
			}
			before := canonical(t, s, "frame")
			seq, _ := s.Counters()
			var out core.Outcome
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				out, _ = r.UpdateState(context("operator", core.ActionUpdate, 1), "frame", p.Binding(), map[string]string{"signal": "#next"})
			}()
			if panicked != (mode == "panic") {
				t.Fatal("panic contract")
			}
			if mode == "mutate" {
				if out.Kind != core.OutcomeAccepted {
					t.Fatal(out)
				}
				retained["signal"] = "#late"
				obj, _ := r.Inspect("frame")
				if obj.Attributes["signal"] != "#next" {
					t.Fatal("callback alias")
				}
			} else {
				if out.Kind == core.OutcomeAccepted {
					t.Fatal("defect accepted")
				}
				if canonical(t, s, "frame") != before {
					t.Fatal("partial canonical commit")
				}
				after, _ := s.Counters()
				if after != seq {
					t.Fatal("allocated event before acceptance")
				}
			}
			// Also proves deferred unlock on panic; no deliberately reentrant hook.
			r.Read(context("operator", core.ActionRead), "frame")
		})
	}
}

func TestExpectedVersionIsSnapshottedBeforeIntegrations(t *testing.T) {
	v := core.ObjectVersion(99)
	s := store.NewMemoryStore()
	r := runtime.NewRuntime(s, policy(func(_ core.Actor, action core.Action, _ core.TypeIdentity) bool {
		if action == core.ActionUpdate {
			v = 1
		}
		return true
	}))
	p, b := testtypes.Probe()
	if r.RegisterType(p, b) != nil {
		t.Fatal("registration")
	}
	create(t, r, p.Binding())
	before := canonical(t, s, "frame")
	c := context("operator", core.ActionUpdate)
	c.ExpectedVersion = &v
	out, _ := r.UpdateState(c, "frame", p.Binding(), map[string]string{"signal": "#next"})
	if out.Kind != core.OutcomeConflict || canonical(t, s, "frame") != before {
		t.Fatal("mutable expected version used")
	}
}

func TestPerTypeAuthorizerAndInputIsolation(t *testing.T) {
	p, b := testtypes.Probe()
	m, mb := testtypes.Marker()
	r := runtime.NewRuntime(store.NewMemoryStore(), policy(func(_ core.Actor, _ core.Action, id core.TypeIdentity) bool { return id == p.Identity }))
	original := p.Clone()
	if r.RegisterType(p, b) != nil || r.RegisterType(m, mb) != nil {
		t.Fatal("registration")
	}
	p.Fields["signal"] = types.FieldDecimal
	p.Actions["send"] = types.PortableAction{}
	p.LifecycleStates[0] = "changed"
	got, _ := r.PortableType(original.Identity)
	if !reflect.DeepEqual(got, original) {
		t.Fatal("registration input alias")
	}
	got.Fields["injected"] = types.FieldString
	input := map[string]string{"signal": "#input", "phase": "idle"}
	out, obj := r.CreateObject(context("operator", core.ActionCreate), "frame", original.Binding(), input)
	accepted(t, out, obj)
	input["signal"] = "#changed"
	obj.Attributes["signal"] = "#result"
	read, _ := r.Inspect("frame")
	if read.Attributes["signal"] != "#input" || read.CanonicalEvents[0].PostImage["signal"] != "#input" {
		t.Fatal("input/result alias")
	}
	out, obj = r.CreateObject(context("operator", core.ActionCreate), "marker", m.Binding(), map[string]string{"label": "x", "value": "1"})
	if out.Kind != core.OutcomeDenied || obj != nil {
		t.Fatal("type-specific denial ignored")
	}
}

func TestCreationPanicHasNoAllocationOrPartialRecord(t *testing.T) {
	for _, hook := range []string{"validate", "reduce"} {
		t.Run(hook, func(t *testing.T) {
			s := store.NewMemoryStore()
			r := runtime.NewRuntime(s, policy(func(core.Actor, core.Action, core.TypeIdentity) bool { return true }))
			p, b := testtypes.Probe()
			if hook == "validate" {
				b.ValidateCreate = func(map[string]string) error { panic("trusted defect") }
			} else {
				b.Reduce = func(map[string]string, types.StateEffect) (map[string]string, error) { panic("trusted defect") }
			}
			if r.RegisterType(p, b) != nil {
				t.Fatal("registration")
			}
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				r.CreateObject(context("operator", core.ActionCreate), "frame", p.Binding(), map[string]string{"signal": "#x", "phase": "idle"})
			}()
			seq, audit := s.Counters()
			if !panicked || len(s.All()) != 0 || seq != 0 || audit != 0 {
				t.Fatal("creation partial effects")
			}
			if _, ok := r.Inspect("frame"); ok {
				t.Fatal("panic left object")
			}
		})
	}
}

func TestLiveZeroFieldStateSurvivesNativeJSONAndReplay(t *testing.T) {
	r, _, _, _ := setup(t)
	zero := types.PortableType{Identity: "check.empty", Version: "z"}
	if r.RegisterPortableType(zero) != nil {
		t.Fatal("register empty type")
	}
	out, obj := r.CreateObject(context("operator", core.ActionCreate), "empty", zero.Binding(), map[string]string{})
	accepted(t, out, obj)
	raw, _ := json.Marshal(obj.CanonicalEvents)
	var h []events.CanonicalEvent
	if json.Unmarshal(raw, &h) != nil || h[0].PostImage == nil {
		t.Fatal("empty post-image lost")
	}
	result, err := replay.Reconstruct(h, r)
	if err != nil || result.Attributes == nil || len(result.Attributes) != 0 {
		t.Fatal("empty live reconstruction", err)
	}
}
