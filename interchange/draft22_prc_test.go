// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package interchange_test

import (
	"encoding/json"
	"github.com/governedobjects/governed-objects-go/interchange"
	"strings"
	"testing"
)

func TestNativeArtifactRevisionPairsAndLegacyRefusal(t *testing.T) {
	_, _, bundle := source(t)
	for _, revision := range []string{interchange.ArtifactRevisionV1, interchange.ArtifactRevisionV2} {
		for _, spec := range []string{interchange.SpecRevisionV1, interchange.SpecRevisionV2} {
			t.Run(revision+"/"+spec, func(t *testing.T) {
				copy := *bundle
				copy.Manifest = bundle.Manifest
				copy.Manifest.ArtifactRevision = revision
				copy.Manifest.SpecRevision = spec
				copy.Manifest.ArtifactStatus = interchange.ArtifactStatusV2
				if revision == interchange.ArtifactRevisionV1 {
					copy.Manifest.ArtifactStatus = interchange.ArtifactStatusV1
				}
				raw, _ := json.Marshal(copy)
				_, ref := interchange.DecodeArtifact(raw)
				valid := (revision == interchange.ArtifactRevisionV1 && spec == interchange.SpecRevisionV1) || (revision == interchange.ArtifactRevisionV2 && spec == interchange.SpecRevisionV2)
				if (ref == nil) != valid {
					t.Fatal("artifact/spec pair", ref)
				}
			})
		}
	}
	for _, raw := range []string{`{"format_label":"NON-NORMATIVE EXPERIMENTAL GO FIXTURE FORMAT","object":{}}`, `{"format_label":"NON-NORMATIVE EXPERIMENTAL GO FIXTURE FORMAT","events":[]}`} {
		if _, ref := interchange.DecodeArtifact([]byte(raw)); ref == nil {
			t.Fatal("legacy fixture admitted")
		}
	}
	raw, _ := json.Marshal(bundle)
	duplicate := strings.Replace(string(raw), `"manifest":{`, `"manifest":{"closed":false,`, 1)
	if _, ref := interchange.DecodeArtifact([]byte(duplicate)); ref == nil {
		t.Fatal("duplicate member accepted")
	}
}
