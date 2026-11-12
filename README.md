# governed-objects-go

Governed Objects is a policy-aware primitive for organizational assets: every
object has a declarative type, a canonical state, and an accepted-history
log, and every create/read/action goes through an explicit capability check
before it is accepted. This module (`governed-objects-go`) is the Go
reference runtime. See the
[specification](https://github.com/governedobjects/governed-objects-spec) and
the [conformance suite](https://github.com/governedobjects/governed-objects-conformance)
for the normative rules this runtime implements and tests against.

## Status

Experimental, version 0.1.0, `0.x`. This is not a production, formal
conformance, interoperability or security claim, and there is no implied
feature parity with the Python runtime. It targets specification revision
`draft2.2` and self-reports 74/2/2/0 (pass/not applicable/not executable/
fail) against the staged Core conformance suite for that revision; see the
conformance adapter below to reproduce that result yourself. The suite's own
claim text for that run:

> governed-objects-go 0.1.0 passes the Governed Objects Conformance Suite
> 0.1.0 for v0alpha1 draft2.2 Core (self-attested; not certified). Not
> executed by suite 0.1.0: D22-CON-001, D22-CS4-003. Conditional capabilities
> claimed: governance_reconfiguration, mutable_objects, relationship_add,
> relationship_remove, replay, restart, restoration,
> semantic_portability_view, type_version_exposed, unconditional_mutation.

## Install

```sh
go get github.com/governedobjects/governed-objects-go@v0.1.0
```

```go
import (
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/runtime"
)
```

The module version is `version.Version` in the `version` package. The module
declares Go 1.23 and uses only the standard library and local packages.

## Example

Defining a type, creating an actor and an object, and performing one accepted
and one denied operation:

```go
package main

import (
	"fmt"

	"github.com/governedobjects/governed-objects-go/auth"
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/runtime"
	"github.com/governedobjects/governed-objects-go/store"
	"github.com/governedobjects/governed-objects-go/types"
)

func main() {
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
	// accepted create: accepted 1

	out, obj = r.CreateObject(
		core.OperationContext{Actor: "stranger", Action: core.ActionCreate},
		"w-2", widget.Binding(), map[string]string{"label": "second"},
	)
	fmt.Println("denied create:", out.Kind, obj)
	// denied create: denied <nil>
}
```

`NewGrantAuthorizer` denies every actor not listed; there is no built-in
default grant.

## Running the tests and the conformance adapter

With a Go 1.23+ toolchain:

```sh
go test ./...
go vet ./...
```

No toolchain download, workspace configuration or new external dependency is
required. The conformance adapter under `conformance-adapter/` is a separate
module that builds against this module through a local `replace`; it speaks
the suite's adapter protocol on stdin/stdout. The runner is in the
[`governed-objects-conformance`](https://github.com/governedobjects/governed-objects-conformance)
repository. Run these commands from the root of that repository, with the
adapter path pointing into this checkout:

```sh
python -m runner --adapter-command "path/to/governed-objects-go/conformance-adapter/launch.sh" --output-dir results-go
python -m runner --verify-bundle results-go
```

Set `CONFORMANCE_GO_BIN` to a directory containing a `go` binary if none is
on `PATH`.

Tested on Linux. macOS is expected to work but is untested. On Windows, use
WSL. The adapters are `bash` scripts.

## Known limits

- Experimental, `0.x`: no production, conformance-certification,
  interoperability or security claim, and no feature parity with the Python
  runtime.
- `RegisterType` requires all five `Behavior` functions (`ValidateState`,
  `ValidateCreate`, `ValidateUpdate`, `ValidateTransition`, `Reduce`);
  `RegisterPortableType` is a schema-only shortcut over the same mechanism
  for flat string/decimal-string fields and declared lifecycle transitions.
  Only one registered version per type identity is supported.
- `interchange` and the runtime import/PRC paths are a provisional,
  representation-limited, non-normative experiment (artifact revisions
  `go-core-interchange-experiment/1` and `/2`), not an official wire
  standard. Import is privileged new-target restoration, staged and atomic;
  it is not ordinary replay.
- Hooks/Authorizer code and direct `store`/`Inspect`/`ResolveType`/
  `SetGovernance` access are trusted integration surfaces, not authenticated
  endpoints; hooks must be pure and must not reenter the `Runtime`. A
  `Runtime` serializes its own calls; multiple runtimes or external
  concurrent store mutation are outside that guarantee.
- Query/traversal/application/delegation/provider/agent features present in
  the Python runtime are not available here.

## License

This runtime is licensed under Apache 2.0; see `LICENSE`. `LICENSING.md`
explains the license model, and `NOTICE` carries attribution and trademark notes.
Contribution terms are in [CONTRIBUTING.md](CONTRIBUTING.md). Report security
issues as described in [SECURITY.md](SECURITY.md).
