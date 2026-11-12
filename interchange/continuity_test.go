// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package interchange_test

import (
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/internal/testtypes"
	"github.com/governedobjects/governed-objects-go/runtime"
	"math"
	"testing"
)

func TestNativeSparseRestorationAndCapacityRemainSeparateFromReplay(t *testing.T) {
	_, _, bundle := source(t)
	tokens := []string{"40", "77", "12", "97", "3", "58", "76"}
	for i := range bundle.Objects[0].History {
		bundle.Objects[0].History[i].ResultingObjectVersion = tokens[i]
	}
	bundle.Objects[0].CurrentObjectVersion = "76"
	r, s := destination(t, nil)
	if _, ref := r.ImportBundle(ctx(core.ActionImport), semantic(t, bundle), runtime.ImportProvenance{}); ref != nil {
		t.Fatal(ref)
	}
	p, _ := testtypes.Probe()
	v := core.ObjectVersion(76)
	c := ctx(core.ActionUpdate)
	c.ExpectedVersion = &v
	out, _ := r.UpdateState(c, "frame", p.Binding(), map[string]string{"signal": "#continuation"})
	if out.Kind != core.OutcomeAccepted || out.Version != 98 {
		t.Fatal("not high-water continuation", out)
	}
	obj, _ := s.Get("frame")
	obj.VersionHighWater = math.MaxInt64
	before := dump(s)
	out, _ = r.UpdateState(ctx(core.ActionUpdate), "frame", p.Binding(), map[string]string{"signal": "#no-capacity"})
	if out.Kind != core.OutcomeRefused || out.Reason != core.ReasonObjectVersionSpaceExhausted {
		t.Fatal(out)
	}
	// Audit is operational; ensure canonical history/state/token unchanged.
	check, _ := s.Snapshot("frame")
	if check.ObjectVersion != 98 || len(check.CanonicalEvents) != 8 || check.Attributes["signal"] != "#continuation" || dump(s) == before {
		t.Fatal("capacity or operational audit separation")
	}
}
