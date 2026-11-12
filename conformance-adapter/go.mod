module github.com/governedobjects/governed-objects-go/conformance-adapter

go 1.23

require github.com/governedobjects/governed-objects-go v0.0.0

// launch.sh builds this adapter against the runtime module root that contains it
// (the replace directive below).
replace github.com/governedobjects/governed-objects-go => ..
