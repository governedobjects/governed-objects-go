// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package version_test

import (
	"regexp"
	"testing"

	"github.com/governedobjects/governed-objects-go/version"
)

func TestVersionIsSingleSourceSemver(t *testing.T) {
	if version.Name != "governed-objects-go" {
		t.Fatalf("implementation name %q", version.Name)
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(version.Version) {
		t.Fatalf("version %q is not MAJOR.MINOR.PATCH", version.Version)
	}
	if version.Version != "0.1.0" {
		t.Fatalf("first release version is 0.1.0, got %q", version.Version)
	}
}
