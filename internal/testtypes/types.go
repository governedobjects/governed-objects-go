// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

// Package testtypes contains synthetic definitions for native tests only.
// It never initializes a runtime, installs grants or registers types.
package testtypes

import (
	"fmt"
	"github.com/governedobjects/governed-objects-go/types"
	"strings"
)

func Probe() (types.PortableType, types.Behavior) {
	t := types.PortableType{Identity: "check.signal-frame", Version: "a1", Fields: map[string]types.FieldKind{"signal": types.FieldString, "phase": types.FieldLifecycle}, LifecycleStates: []string{"idle", "sent", "sealed"}, Transitions: [][2]string{{"idle", "sent"}, {"sent", "sealed"}, {"idle", "idle"}, {"sent", "sent"}, {"sealed", "sealed"}}, Actions: map[string]types.PortableAction{"send": {Kind: types.ActionKindLifecycle, From: []string{"idle"}, To: "sent"}}}
	b, _ := types.NewPortableBehavior(t)
	validate := func(s map[string]string) error {
		if s == nil {
			return fmt.Errorf("absent state")
		}
		if err := t.ValidateCreateState(s); err != nil {
			return err
		}
		if !strings.HasPrefix(s["signal"], "#") {
			return fmt.Errorf("signal requires marker")
		}
		return nil
	}
	b.ValidateState = validate
	b.ValidateCreate = func(s map[string]string) error {
		if err := validate(s); err != nil {
			return err
		}
		if s["phase"] != "idle" {
			return fmt.Errorf("initial phase must be idle")
		}
		return nil
	}
	b.ValidateUpdate = func(before, set map[string]string) error {
		if err := t.ValidateUpdate(set); err != nil {
			return err
		}
		if !strings.HasPrefix(set["signal"], "#") {
			return fmt.Errorf("signal requires marker")
		}
		return nil
	}
	return t.Clone(), b
}

func Marker() (types.PortableType, types.Behavior) {
	t := types.PortableType{Identity: "check.scalar-marker", Version: "b7", Fields: map[string]types.FieldKind{"label": types.FieldString, "value": types.FieldDecimal}}
	b, _ := types.NewPortableBehavior(t)
	validate := func(s map[string]string) error {
		if s == nil {
			return fmt.Errorf("absent state")
		}
		if err := t.ValidateCreateState(s); err != nil {
			return err
		}
		if s["label"] == "" || strings.HasPrefix(s["value"], "-") {
			return fmt.Errorf("marker requires label and nonnegative scalar")
		}
		return nil
	}
	b.ValidateState = validate
	b.ValidateCreate = validate
	return t.Clone(), b
}
