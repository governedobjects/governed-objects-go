// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package interchange_test

import (
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/interchange"
	"github.com/governedobjects/governed-objects-go/internal/testtypes"
	"testing"
)

func TestNativeExportDenialInvariantAcrossProtectedCorruption(t *testing.T) {
	r, s, _ := source(t)
	request := interchange.Request{Actor: "outsider", Identities: []core.CanonicalIdentity{"frame"}}
	_, first := interchange.Export(r, request)
	if first == nil {
		t.Fatal("outsider export")
	}
	obj, _ := s.Get("frame")
	obj.TypeVersion = "unsupported"
	obj.GovernanceReference = ""
	obj.CanonicalEvents[0].PostImage = nil
	_, second := interchange.Export(r, request)
	if second == nil || first.Error() != second.Error() {
		t.Fatal("outsider distinguishes corruption")
	}
	out, record := r.Read(ctx(core.ActionRead), "frame")
	if out.Kind != core.OutcomeDenied || out.Version != 0 || record != nil {
		t.Fatal("read grant discloses unsupported exact binding")
	}
	p, _ := testtypes.Probe()
	out, record = r.UpdateState(ctx(core.ActionUpdate), "frame", p.Binding(), map[string]string{"signal": "#x"})
	if out.Kind != core.OutcomeRefused || out.Version != 0 || record != nil {
		t.Fatal("unsupported rejection discloses details")
	}
}
