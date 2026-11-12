// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package runtime_test

import (
	"fmt"

	"github.com/governedobjects/governed-objects-go/auth"
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/runtime"
	"github.com/governedobjects/governed-objects-go/store"
	"github.com/governedobjects/governed-objects-go/types"
)

// ExampleRuntime_readme runs the README's example verbatim so it stays
// accurate; go test verifies the printed Output.
func ExampleRuntime_readme() {
	s := store.NewMemoryStore()
	r := runtime.NewRuntime(s, auth.NewGrantAuthorizer(map[core.Actor][]auth.Capability{
		"writer": {auth.CapCreate, auth.CapRead},
	}))

	widget := types.PortableType{
		Identity: "example.widget",
		Version:  "1",
		Fields:   map[string]types.FieldKind{"label": types.FieldString},
	}
	if err := r.RegisterPortableType(widget); err != nil {
		panic(err)
	}

	out, obj := r.CreateObject(
		core.OperationContext{Actor: "writer", Action: core.ActionCreate},
		"w-1", widget.Binding(), map[string]string{"label": "first"},
	)
	fmt.Println("accepted create:", out.Kind, obj.ObjectVersion)

	out, obj = r.CreateObject(
		core.OperationContext{Actor: "stranger", Action: core.ActionCreate},
		"w-2", widget.Binding(), map[string]string{"label": "second"},
	)
	fmt.Println("denied create:", out.Kind, obj)

	// Output:
	// accepted create: accepted 1
	// denied create: denied <nil>
}
