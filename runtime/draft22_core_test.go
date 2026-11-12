// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package runtime_test

import (
	"fmt"
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/store"
	"math"
	"sync"
	"testing"
)

func TestNativeOutcomeMatrixAndNoOpOrdering(t *testing.T) {
	r, s, p, _ := setup(t)
	create(t, r, p)
	rel := core.Relationship{Source: "frame", Type: "links", Target: "missing"}
	r.AddRelationship(context("operator", core.ActionAddRelationship), "frame", rel)
	mutations := map[string]func(core.OperationContext) (core.Outcome, *store.ObjectRecord){
		"state": func(c core.OperationContext) (core.Outcome, *store.ObjectRecord) {
			return r.UpdateState(c, "frame", p, map[string]string{"signal": "#next"})
		},
		"lifecycle": func(c core.OperationContext) (core.Outcome, *store.ObjectRecord) {
			return r.TransitionLifecycle(c, "frame", p, "sent")
		},
		"add-existing": func(c core.OperationContext) (core.Outcome, *store.ObjectRecord) {
			return r.AddRelationship(c, "frame", rel)
		},
		"remove-existing": func(c core.OperationContext) (core.Outcome, *store.ObjectRecord) {
			return r.RemoveRelationship(c, "frame", rel)
		},
	}
	for name, run := range mutations {
		t.Run(name, func(t *testing.T) {
			before := canonical(t, s, "frame")
			for _, actor := range []core.Actor{"outsider", "blind-writer", "observer", "operator"} {
				for _, token := range []int64{1, 99, math.MaxInt64} {
					out, obj := run(context(actor, core.ActionUpdate, token))
					want := core.OutcomeConflict
					if actor == "outsider" || actor == "observer" {
						want = core.OutcomeDenied
					}
					if out.Kind != want {
						t.Fatal(out)
					}
					if actor == "outsider" || actor == "blind-writer" {
						if out.Version != 0 || obj != nil {
							t.Fatal("protected rejection")
						}
					}
				}
			}
			if canonical(t, s, "frame") != before {
				t.Fatal("rejection effects")
			}
		})
	}
	stored, _ := s.Get("frame")
	stored.VersionHighWater = math.MaxInt64
	before := canonical(t, s, "frame")
	out, _ := r.AddRelationship(context("operator", core.ActionAddRelationship, 2), "frame", rel)
	if out.Kind != core.OutcomeAccepted || out.Version != 2 {
		t.Fatal("no-op at exhaustion")
	}
	out, _ = r.UpdateState(context("operator", core.ActionUpdate, 2), "frame", p, map[string]string{"signal": "#x"})
	if out.Kind != core.OutcomeRefused || canonical(t, s, "frame") != before {
		t.Fatal("capacity no-effect")
	}
}

func TestNativeConcurrentSingleRuntimeLineage(t *testing.T) {
	r, s, p, _ := setup(t)
	create(t, r, p)
	const n = 64
	var wg sync.WaitGroup
	tokens := make(chan core.ObjectVersion, 2*n)
	for i := 0; i < n; i++ {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			out, _ := r.UpdateState(context("operator", core.ActionUpdate), "frame", p, map[string]string{"signal": fmt.Sprint("#", i)})
			if out.Kind == core.OutcomeAccepted {
				tokens <- out.Version
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			out, _ := r.AddRelationship(context("operator", core.ActionAddRelationship), "frame", core.Relationship{Source: "frame", Type: "links", Target: core.CanonicalIdentity(fmt.Sprint(i))})
			if out.Kind == core.OutcomeAccepted {
				tokens <- out.Version
			}
		}(i)
		go func() { defer wg.Done(); r.Read(context("outsider", core.ActionRead), "frame") }()
	}
	wg.Wait()
	close(tokens)
	seen := map[core.ObjectVersion]bool{}
	for token := range tokens {
		if seen[token] {
			t.Fatal("reused token")
		}
		seen[token] = true
	}
	obj, _ := s.Snapshot("frame")
	if len(seen) != 2*n || len(obj.CanonicalEvents) != 1+2*n || obj.ObjectVersion != 1+2*n {
		t.Fatal("single lineage lost")
	}
}
