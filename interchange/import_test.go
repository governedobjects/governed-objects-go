// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package interchange_test

import (
	"fmt"
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/internal/testtypes"
	"github.com/governedobjects/governed-objects-go/runtime"
	"github.com/governedobjects/governed-objects-go/types"
	"testing"
)

func TestNativeImportSharedBehaviorAndLateFailureAtomicity(t *testing.T) {
	_, _, bundle := source(t)
	p, b := testtypes.Probe()
	reduce := b.Reduce
	b.Reduce = func(before map[string]string, e types.StateEffect) (map[string]string, error) {
		if e.PostImage["phase"] == "sealed" {
			return nil, fmt.Errorf("late reducer refusal")
		}
		return reduce(before, e)
	}
	r, s := destination(t, &b)
	before := dump(s)
	if _, ref := r.ImportBundle(ctx(core.ActionImport), semantic(t, bundle), runtime.ImportProvenance{}); ref == nil {
		t.Fatal("reducer bypassed")
	}
	if dump(s) != before {
		t.Fatal("late refusal committed")
	}
	_ = p
	good, gs := destination(t, nil)
	data := semantic(t, bundle)
	result, ref := good.ImportBundle(ctx(core.ActionImport), data, runtime.ImportProvenance{})
	if ref != nil || len(result.Identities) != 2 {
		t.Fatal("actual restore", ref)
	}
	data.Objects[0].AcceptedState["signal"] = "#vandal"
	data.Objects[0].History[0].PostImage["signal"] = "#vandal"
	result.Identities[0] = "vandal"
	obj, _ := gs.Snapshot("frame")
	if obj.Attributes["signal"] != "#final" || obj.CanonicalEvents[0].PostImage["signal"] != "#start" || gs.Imports()[0].Identities[0] != "frame" {
		t.Fatal("restore alias")
	}
	before = dump(gs)
	if _, ref = good.ImportBundle(ctx(core.ActionImport), semantic(t, bundle), runtime.ImportProvenance{}); ref == nil || dump(gs) != before {
		t.Fatal("collision effects")
	}
}

func TestNativeDirectSemanticShapesRefuseWithoutEffects(t *testing.T) {
	_, _, bundle := source(t)
	for _, name := range []string{"nil-state", "nil-create-image", "nil-relationship", "relationship-image", "unexpected-baseline", "empty-target", "unknown-effect"} {
		t.Run(name, func(t *testing.T) {
			r, s := destination(t, nil)
			data := semantic(t, bundle)
			o := &data.Objects[0]
			switch name {
			case "nil-state":
				o.AcceptedState = nil
			case "nil-create-image":
				o.History[0].PostImage = nil
			case "nil-relationship":
				o.History[3].Relationship = nil
			case "relationship-image":
				o.History[3].PostImage = map[string]string{}
			case "unexpected-baseline":
				o.History[1].HasBaseline = true
			case "empty-target":
				o.History[3].Relationship.Target = ""
			case "unknown-effect":
				o.History[1].Effect = "unknown"
			}
			before := dump(s)
			if _, ref := r.ImportBundle(ctx(core.ActionImport), data, runtime.ImportProvenance{}); ref == nil || dump(s) != before {
				t.Fatal("malformed direct bundle admitted or side effects")
			}
		})
	}
}

func TestNativeLateImportCallbackPanicIsAtomic(t *testing.T) {
	_, _, bundle := source(t)
	_, b := testtypes.Probe()
	reduce := b.Reduce
	b.Reduce = func(before map[string]string, e types.StateEffect) (map[string]string, error) {
		if e.PostImage["phase"] == "sealed" {
			panic("trusted extension defect")
		}
		return reduce(before, e)
	}
	r, s := destination(t, &b)
	before := dump(s)
	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		r.ImportBundle(ctx(core.ActionImport), semantic(t, bundle), runtime.ImportProvenance{})
	}()
	if !panicked || dump(s) != before {
		t.Fatal("late panic committed staged data or counters")
	}
	r.PortableType("check.signal-frame")
}
