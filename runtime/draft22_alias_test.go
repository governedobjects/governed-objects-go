// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package runtime_test

import (
	"fmt"
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/store"
	"testing"
)

func TestNativeResultAliasMatrix(t *testing.T) {
	for source := 0; source < 14; source++ {
		for vandal := 0; vandal < 5; vandal++ {
			t.Run(fmt.Sprintf("source%d/group%d", source, vandal), func(t *testing.T) {
				r, s, p, m := setup(t)
				create(t, r, p)
				r.CreateObject(context("operator", core.ActionCreate), "marker", m, map[string]string{"label": "x", "value": "1"})
				rel := core.Relationship{Source: "frame", Type: "links", Target: "target"}
				r.AddRelationship(context("operator", core.ActionAddRelationship), "frame", rel)
				var obj *store.ObjectRecord
				id := core.CanonicalIdentity("frame")
				switch source {
				case 0, 2:
					_, obj = r.Read(context("operator", core.ActionRead), id)
				case 1:
					id = "marker"
					_, obj = r.Read(context("observer", core.ActionRead), id)
				case 3:
					id = "new"
					_, obj = r.CreateObject(context("operator", core.ActionCreate), id, p, map[string]string{"signal": "#new", "phase": "idle"})
				case 4:
					id = "other-marker"
					_, obj = r.CreateObject(context("operator", core.ActionCreate), id, m, map[string]string{"label": "m", "value": "2"})
				case 5:
					_, obj = r.UpdateState(context("operator", core.ActionUpdate), id, p, map[string]string{"signal": "#next"})
				case 7:
					id = "marker"
					_, obj = r.UpdateState(context("operator", core.ActionUpdate), id, m, map[string]string{"value": "2.3400"})
				case 6, 8:
					_, obj = r.TransitionLifecycle(context("operator", core.ActionTransition), id, p, "sent")
				case 9:
					_, obj = r.AddRelationship(context("operator", core.ActionAddRelationship), id, core.Relationship{Source: id, Type: "links", Target: "other"})
				case 10:
					_, obj = r.AddRelationship(context("operator", core.ActionAddRelationship), id, rel)
				case 11:
					_, obj = r.RemoveRelationship(context("operator", core.ActionRemoveRelationship), id, rel)
				case 12:
					_, obj = r.UpdateState(context("operator", core.ActionUpdate, 99), id, p, map[string]string{"signal": "#stale"})
				case 13:
					obj, _ = r.Inspect(id)
				}
				if obj == nil {
					t.Fatal("missing result")
				}
				before := canonical(t, s, id)
				switch vandal {
				case 0:
					obj.Attributes["injected"] = "changed"
					obj.TypeVersion = "changed"
					obj.GovernanceReference = "changed"
				case 1:
					for i := range obj.CanonicalEvents {
						for _, values := range []map[string]string{obj.CanonicalEvents[i].Payload, obj.CanonicalEvents[i].PostImage} {
							for k := range values {
								values[k] = "changed"
							}
						}
					}
				case 2:
					for i := range obj.Relationships {
						obj.Relationships[i].Target = "changed"
					}
					obj.Relationships = append(obj.Relationships, rel)
				case 3:
					for i := range obj.CanonicalEvents {
						obj.CanonicalEvents[i].Kind = "changed"
						obj.CanonicalEvents[i].ResultingVersion = 99
					}
					obj.CanonicalEvents = nil
				case 4:
					obj.ObjectVersion = 99
					obj.VersionHighWater = 99
				}
				if canonical(t, s, id) != before {
					t.Fatal("result aliases canonical storage")
				}
			})
		}
	}
}
