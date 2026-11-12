// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

package interchange

// EXPERIMENTAL. NON-NORMATIVE. NOT A WIRE STANDARD. DecodeArtifact turns the
// provisional artifacts go-core-interchange-experiment/1 and /2 into the
// runtime's semantic runtime.ImportBundle. It reads the artifact revision
// first and holds the bundle to that revision's contract: its status marker
// and its single specification revision. Otherwise it checks shape only and
// refuses, never repairs: duplicate members, unknown members, non-string
// tokens or state values, and a manifest that does not describe the contents
// are refused. Named out-of-scope content (policy, grants, credentials,
// provider bindings, ...) is refused as UNSUPPORTED_SEMANTIC_FEATURE.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/governedobjects/governed-objects-go/runtime"
)

var outOfScopeMembers = map[string]bool{
	"policy": true, "policy_content": true, "governance_policy": true, "grants": true,
	"capabilities": true, "permissions": true, "actors": true, "credentials": true,
	"secrets": true, "trust_roots": true, "provider_binding": true, "provider_bindings": true,
	"observations": true, "mandates": true, "application_registrations": true, "profile_data": true,
}

var (
	manifestRequired = []string{"artifact_status", "history_completeness", "history_position_model",
		"governance_reference_model", "profiles", "identities", "type_bindings", "governance_references", "closed"}
	manifestOptional = []string{"artifact_revision", "spec_revision", "provenance"}
	objectRequired   = []string{"canonical_identity", "type_identity", "type_version", "accepted_state",
		"relationships", "current_object_version", "history"}
	entryRequired = []string{"position", "effect", "type_identity", "type_version", "resulting_object_version"}
	entryContent  = []string{"post_image", "relationships", "relationship"}
	entryEvidence = []string{"actor", "accepted_at", "action", "source_event_id"}
	effectContent = map[string]map[string]bool{
		runtime.EffectCreate:              {"post_image": true, "relationships": true},
		runtime.EffectStateChange:         {"post_image": true},
		runtime.EffectLifecycleTransition: {"post_image": true},
		runtime.EffectRelationshipAdd:     {"relationship": true},
		runtime.EffectRelationshipRemove:  {"relationship": true},
	}
	jsonInteger = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	rfc3339     = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$`)
)

// replayBaselineCompleteness names a history that starts at a Replay
// Baseline; artifact /2 recognizes it and cannot carry it.
const replayBaselineCompleteness = "complete-from-replay-baseline"

type artifactContract struct {
	status       string
	specRevision string
	// Rules artifact /2 added: a Replay Baseline history is an unsupported
	// feature (not incomplete), and manifest.provenance.exported_at must be an
	// RFC 3339 instant.
	refuseReplayBaseline bool
	checkExportedAt      bool
}

var artifactContracts = map[string]artifactContract{
	ArtifactRevisionV1: {status: ArtifactStatusV1, specRevision: SpecRevisionV1},
	ArtifactRevisionV2: {status: ArtifactStatusV2, specRevision: SpecRevisionV2, refuseReplayBaseline: true, checkExportedAt: true},
}

// isInstant reports whether s is an RFC 3339 date-time (section 5.6 grammar,
// including offsets of at most 23:59, and section 5.7 day limits). Both
// artifact revisions carry accepted_at as an RFC 3339 string.
func isInstant(s string) bool {
	m := rfc3339.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	n := func(i int) int { v, _ := strconv.Atoi(m[i]); return v }
	if z := m[8]; z != "Z" && z != "z" {
		hours, _ := strconv.Atoi(z[1:3])
		minutes, _ := strconv.Atoi(z[4:6])
		if hours > 23 || minutes > 59 {
			return false
		}
	}
	t := time.Date(n(1), time.Month(n(2)), n(3), n(4), n(5), n(6), 0, time.UTC)
	return t.Year() == n(1) && int(t.Month()) == n(2) && t.Day() == n(3) && t.Hour() == n(4) && t.Minute() == n(5) && t.Second() == n(6)
}

type obj = map[string]interface{}

func malformed(identity string, position int, format string, args ...interface{}) *runtime.ImportRefusal {
	return &runtime.ImportRefusal{Code: runtime.ImportMalformedArtifact, Message: fmt.Sprintf(format, args...), Identity: identity, Position: position}
}

// checkDuplicateMembers walks the token stream and refuses any object with
// a repeated member name (encoding/json would silently keep the last).
func checkDuplicateMembers(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []*jsonFrame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var top *jsonFrame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.expect {
			key, ok := tok.(string)
			if !ok {
				if d, isDelim := tok.(json.Delim); isDelim && d == '}' {
					stack = stack[:len(stack)-1]
					markValueDone(stack)
					continue
				}
				return fmt.Errorf("unexpected token %v", tok)
			}
			if top.keys[key] {
				return fmt.Errorf("duplicate JSON member %q", key)
			}
			top.keys[key] = true
			top.expect = false
			continue
		}
		switch d := tok.(type) {
		case json.Delim:
			switch d {
			case '{':
				stack = append(stack, &jsonFrame{object: true, keys: map[string]bool{}, expect: true})
			case '[':
				stack = append(stack, &jsonFrame{})
			case '}', ']':
				stack = stack[:len(stack)-1]
				markValueDone(stack)
			}
		default:
			markValueDone(stack)
		}
	}
}

type jsonFrame struct {
	object bool
	keys   map[string]bool
	expect bool // the next token in this object is a member name
}

// markValueDone records that a member value finished in the enclosing object.
func markValueDone(stack []*jsonFrame) {
	if n := len(stack); n > 0 && stack[n-1].object {
		stack[n-1].expect = true
	}
}

func extras(raw obj, known []string, where, identity string, position int) *runtime.ImportRefusal {
	names := make([]string, 0, len(raw))
	for k := range raw {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		if contains(known, name) {
			continue
		}
		if outOfScopeMembers[name] {
			return &runtime.ImportRefusal{Code: runtime.ImportUnsupportedSemanticFeature, Message: fmt.Sprintf("%s: out-of-scope content %q", where, name), Identity: identity, Position: position}
		}
		return malformed(identity, position, "%s: unrecognized member %q", where, name)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func nonEmptyString(v interface{}, where, identity string, position int) (string, *runtime.ImportRefusal) {
	s, ok := v.(string)
	if !ok || s == "" {
		return "", malformed(identity, position, "%s must be a non-empty string", where)
	}
	return s, nil
}

func decodeRelationship(v interface{}, where, identity string, position int) (runtime.ImportRelationship, *runtime.ImportRefusal) {
	raw, ok := v.(obj)
	if !ok {
		return runtime.ImportRelationship{}, malformed(identity, position, "%s must be an object", where)
	}
	for _, k := range []string{"source", "type", "target"} {
		if _, ok := raw[k]; !ok {
			return runtime.ImportRelationship{}, malformed(identity, position, "%s must have members source, type, target", where)
		}
	}
	for k := range raw {
		if !contains([]string{"source", "type", "target", "target_type", "metadata"}, k) {
			return runtime.ImportRelationship{}, malformed(identity, position, "%s: member %q is not permitted (no edge IDs)", where, k)
		}
	}
	if tt, ok := raw["target_type"]; ok {
		if _, isStr := tt.(string); !isStr {
			return runtime.ImportRelationship{}, malformed(identity, position, "%s.target_type must be a string", where)
		}
	}
	if md, ok := raw["metadata"]; ok {
		if _, isObj := md.(obj); !isObj {
			return runtime.ImportRelationship{}, malformed(identity, position, "%s.metadata must be an object", where)
		}
	}
	var out runtime.ImportRelationship
	var ref *runtime.ImportRefusal
	if out.Source, ref = nonEmptyString(raw["source"], where+".source", identity, position); ref != nil {
		return out, ref
	}
	if out.Type, ref = nonEmptyString(raw["type"], where+".type", identity, position); ref != nil {
		return out, ref
	}
	if out.Target, ref = nonEmptyString(raw["target"], where+".target", identity, position); ref != nil {
		return out, ref
	}
	_, hasTT := raw["target_type"]
	_, hasMD := raw["metadata"]
	out.HasEvidence = hasTT || hasMD
	return out, nil
}

func decodeRelationships(v interface{}, where, identity string, position int) ([]runtime.ImportRelationship, *runtime.ImportRefusal) {
	list, ok := v.([]interface{})
	if !ok {
		return nil, malformed(identity, position, "%s must be a list", where)
	}
	out := make([]runtime.ImportRelationship, 0, len(list))
	for i, r := range list {
		rel, ref := decodeRelationship(r, fmt.Sprintf("%s[%d]", where, i), identity, position)
		if ref != nil {
			return nil, ref
		}
		out = append(out, rel)
	}
	return out, nil
}

func decodeState(v interface{}, where, identity string, position int) (map[string]string, *runtime.ImportRefusal) {
	raw, ok := v.(obj)
	if !ok {
		return nil, malformed(identity, position, "%s must be an object", where)
	}
	out := make(map[string]string, len(raw))
	for k, val := range raw {
		s, ok := val.(string)
		if !ok {
			return nil, &runtime.ImportRefusal{Code: runtime.ImportStateNotValidForType, Message: fmt.Sprintf("%s.%s must be a string (never coerced)", where, k), Identity: identity, Position: position}
		}
		out[k] = s
	}
	return out, nil
}

func decodeToken(v interface{}, where, identity string, position int) (string, *runtime.ImportRefusal) {
	s, ok := v.(string)
	if !ok || s == "" {
		return "", malformed(identity, position, "%s %v is not an opaque string token (never coerced)", where, v)
	}
	return s, nil
}

func decodeEntry(v interface{}, identity string, index int) (runtime.ImportEntry, *runtime.ImportRefusal) {
	where := fmt.Sprintf("history[%d]", index)
	raw, ok := v.(obj)
	if !ok {
		return runtime.ImportEntry{}, malformed(identity, 0, "%s must be an object", where)
	}
	for _, k := range entryRequired {
		if _, ok := raw[k]; !ok {
			return runtime.ImportEntry{}, malformed(identity, 0, "%s: required member %q missing", where, k)
		}
	}
	num, ok := raw["position"].(json.Number)
	if !ok || !jsonInteger.MatchString(num.String()) {
		return runtime.ImportEntry{}, malformed(identity, 0, "%s.position must be a JSON integer", where)
	}
	position, err := strconv.Atoi(num.String())
	if err != nil {
		return runtime.ImportEntry{}, malformed(identity, 0, "%s.position %s is out of range", where, num)
	}
	effect, _ := raw["effect"].(string)
	want, known := effectContent[effect]
	if !known {
		return runtime.ImportEntry{}, malformed(identity, position, "%s.effect %v is not a known effect kind", where, raw["effect"])
	}
	for _, k := range entryContent {
		_, has := raw[k]
		if has != want[k] {
			return runtime.ImportEntry{}, malformed(identity, position, "%s: effect %q has the wrong content members", where, effect)
		}
	}
	if ref := extras(raw, append(append(append([]string{}, entryRequired...), entryContent...), entryEvidence...), where, identity, position); ref != nil {
		return runtime.ImportEntry{}, ref
	}
	e := runtime.ImportEntry{Position: position, Effect: effect}
	var ref *runtime.ImportRefusal
	if e.TypeIdentity, ref = nonEmptyString(raw["type_identity"], where+".type_identity", identity, position); ref != nil {
		return e, ref
	}
	if e.TypeVersion, ref = nonEmptyString(raw["type_version"], where+".type_version", identity, position); ref != nil {
		return e, ref
	}
	if e.ResultingObjectVersion, ref = decodeToken(raw["resulting_object_version"], where+".resulting_object_version", identity, position); ref != nil {
		return e, ref
	}
	for _, k := range entryEvidence {
		if val, ok := raw[k]; ok {
			s, isStr := val.(string)
			if !isStr {
				return e, malformed(identity, position, "%s.%s must be a string when present", where, k)
			}
			switch k {
			case "actor":
				e.Evidence.Actor = &s
			case "accepted_at":
				if !isInstant(s) {
					return e, malformed(identity, position, "%s.accepted_at is not an RFC 3339 instant", where)
				}
				e.Evidence.AcceptedAt = &s
			case "action":
				e.Evidence.Action = &s
			case "source_event_id":
				e.Evidence.SourceEventID = &s
			}
		}
	}
	if pi, ok := raw["post_image"]; ok {
		if e.PostImage, ref = decodeState(pi, where+".post_image", identity, position); ref != nil {
			return e, ref
		}
	}
	if rels, ok := raw["relationships"]; ok {
		e.HasBaseline = true
		if e.BaselineRelationships, ref = decodeRelationships(rels, where+".relationships", identity, position); ref != nil {
			return e, ref
		}
	}
	if rel, ok := raw["relationship"]; ok {
		r, ref := decodeRelationship(rel, where+".relationship", identity, position)
		if ref != nil {
			return e, ref
		}
		e.Relationship = &r
	}
	return e, nil
}

func decodeObject(v interface{}, index int) (runtime.ImportObject, *runtime.ImportRefusal) {
	where := fmt.Sprintf("objects[%d]", index)
	raw, ok := v.(obj)
	if !ok {
		return runtime.ImportObject{}, malformed("", 0, "%s must be an object", where)
	}
	for _, k := range objectRequired {
		if _, ok := raw[k]; !ok {
			return runtime.ImportObject{}, malformed("", 0, "%s: required member %q missing", where, k)
		}
	}
	ident, ref := nonEmptyString(raw["canonical_identity"], where+".canonical_identity", "", 0)
	if ref != nil {
		return runtime.ImportObject{}, ref
	}
	if ref := extras(raw, append(append([]string{}, objectRequired...), "governance_reference"), "object", ident, 0); ref != nil {
		return runtime.ImportObject{}, ref
	}
	o := runtime.ImportObject{CanonicalIdentity: ident}
	if g, ok := raw["governance_reference"]; ok && g != nil {
		s, isStr := g.(string)
		if !isStr {
			return o, malformed(ident, 0, "governance_reference must be an opaque string")
		}
		o.GovernanceReference = &s
	}
	if o.TypeIdentity, ref = nonEmptyString(raw["type_identity"], "type_identity", ident, 0); ref != nil {
		return o, ref
	}
	if o.TypeVersion, ref = nonEmptyString(raw["type_version"], "type_version", ident, 0); ref != nil {
		return o, ref
	}
	if o.AcceptedState, ref = decodeState(raw["accepted_state"], "accepted_state", ident, 0); ref != nil {
		return o, ref
	}
	if o.Relationships, ref = decodeRelationships(raw["relationships"], "relationships", ident, 0); ref != nil {
		return o, ref
	}
	if o.CurrentObjectVersion, ref = decodeToken(raw["current_object_version"], "current_object_version", ident, 0); ref != nil {
		return o, ref
	}
	history, ok := raw["history"].([]interface{})
	if !ok {
		return o, malformed(ident, 0, "history must be a list")
	}
	for i, h := range history {
		e, ref := decodeEntry(h, ident, i)
		if ref != nil {
			return o, ref
		}
		o.History = append(o.History, e)
	}
	return o, nil
}

func stringList(v interface{}, where string) ([]string, *runtime.ImportRefusal) {
	list, ok := v.([]interface{})
	if !ok {
		return nil, malformed("", 0, "manifest.%s must be a list", where)
	}
	out := make([]string, 0, len(list))
	for _, x := range list {
		s, ref := nonEmptyString(x, "manifest."+where+"[]", "", 0)
		if ref != nil {
			return nil, ref
		}
		out = append(out, s)
	}
	return out, nil
}

func sameSet[K comparable](declared []K, actual map[K]bool) bool {
	seen := map[K]bool{}
	for _, d := range declared {
		if seen[d] || !actual[d] {
			return false
		}
		seen[d] = true
	}
	return len(seen) == len(actual)
}

// DecodeArtifact decodes artifact JSON text into a semantic import bundle.
func DecodeArtifact(data []byte) (*runtime.ImportBundle, *runtime.ImportRefusal) {
	if err := checkDuplicateMembers(data); err != nil {
		return nil, malformed("", 0, "unparseable JSON: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc interface{}
	if err := dec.Decode(&doc); err != nil {
		return nil, malformed("", 0, "unparseable JSON: %v", err)
	}
	if dec.More() {
		return nil, malformed("", 0, "unparseable JSON: trailing content")
	}
	top, _ := doc.(obj)
	manifest, _ := top["manifest"].(obj)
	rev, _ := manifest["artifact_revision"].(string)
	contract, known := artifactContracts[rev]
	if manifest == nil || !known {
		return nil, &runtime.ImportRefusal{Code: runtime.ImportUnsupportedArtifactRevision, Message: fmt.Sprintf("artifact revision %v is not %q or %q", manifest["artifact_revision"], ArtifactRevisionV1, ArtifactRevisionV2)}
	}
	if _, ok := top["objects"]; !ok {
		return nil, malformed("", 0, "bundle: required member 'objects' missing")
	}
	if ref := extras(top, []string{"manifest", "objects"}, "bundle", "", 0); ref != nil {
		return nil, ref
	}
	for _, k := range manifestRequired {
		if _, ok := manifest[k]; !ok {
			return nil, malformed("", 0, "manifest: required member %q missing", k)
		}
	}
	if ref := extras(manifest, append(append([]string{}, manifestRequired...), manifestOptional...), "manifest", "", 0); ref != nil {
		return nil, ref
	}
	if manifest["artifact_status"] != contract.status {
		return nil, malformed("", 0, "manifest.artifact_status is not the %s status marker", rev)
	}
	b := &runtime.ImportBundle{}
	sr, ok := manifest["spec_revision"]
	if ok {
		s, isStr := sr.(string)
		if !isStr {
			return nil, malformed("", 0, "manifest.spec_revision must be a string")
		}
		b.SpecRevision = &s
	}
	if !ok || *b.SpecRevision != contract.specRevision {
		return nil, &runtime.ImportRefusal{Code: runtime.ImportUnsupportedSpecRevision,
			Message: fmt.Sprintf("specification revision %v is not %q, the only revision %s carries", sr, contract.specRevision, rev)}
	}
	var ref *runtime.ImportRefusal
	if b.HistoryCompleteness, ref = nonEmptyString(manifest["history_completeness"], "manifest.history_completeness", "", 0); ref != nil {
		return nil, ref
	}
	if contract.refuseReplayBaseline && b.HistoryCompleteness == replayBaselineCompleteness {
		return nil, &runtime.ImportRefusal{Code: runtime.ImportUnsupportedSemanticFeature,
			Message: fmt.Sprintf("history declared %q; %s carries only %q history", replayBaselineCompleteness, rev, HistoryCompleteness)}
	}
	if b.HistoryPositionModel, ref = nonEmptyString(manifest["history_position_model"], "manifest.history_position_model", "", 0); ref != nil {
		return nil, ref
	}
	if b.GovernanceReferenceModel, ref = nonEmptyString(manifest["governance_reference_model"], "manifest.governance_reference_model", "", 0); ref != nil {
		return nil, ref
	}
	profiles, ok := manifest["profiles"].([]interface{})
	if !ok {
		return nil, malformed("", 0, "manifest.profiles must be a list")
	}
	b.ProfileCount = len(profiles)
	closed, ok := manifest["closed"].(bool)
	if !ok {
		return nil, malformed("", 0, "manifest.closed must be a boolean")
	}
	b.Closed = closed
	if p, ok := manifest["provenance"]; ok {
		pm, isObj := p.(obj)
		if !isObj {
			return nil, malformed("", 0, "manifest.provenance must be an object")
		}
		for k, v := range pm {
			s, isStr := v.(string)
			if !isStr || (k != "source_implementation" && k != "exported_at") {
				return nil, malformed("", 0, "manifest.provenance may contain only source_implementation and exported_at strings")
			}
			if k == "source_implementation" {
				b.SourceImplementation = s
			}
			if k == "exported_at" && contract.checkExportedAt && !isInstant(s) {
				return nil, malformed("", 0, "manifest.provenance.exported_at is not an RFC 3339 instant")
			}
		}
	}
	identities, ref := stringList(manifest["identities"], "identities")
	if ref != nil {
		return nil, ref
	}
	references, ref := stringList(manifest["governance_references"], "governance_references")
	if ref != nil {
		return nil, ref
	}
	bindingsRaw, ok := manifest["type_bindings"].([]interface{})
	if !ok {
		return nil, malformed("", 0, "manifest.type_bindings must be a list")
	}
	bindings := make([]Binding, 0, len(bindingsRaw))
	for i, x := range bindingsRaw {
		m, isObj := x.(obj)
		ti, tiOK := m["type_identity"].(string)
		tv, tvOK := m["type_version"].(string)
		if !isObj || len(m) != 2 || !tiOK || !tvOK || ti == "" || tv == "" {
			return nil, malformed("", 0, "manifest.type_bindings[%d] must be {type_identity, type_version}", i)
		}
		bindings = append(bindings, Binding{TypeIdentity: ti, TypeVersion: tv})
	}

	objectsRaw, ok := top["objects"].([]interface{})
	if !ok {
		return nil, malformed("", 0, "objects must be a list")
	}
	actualIDs, actualBindings, actualRefs := map[string]bool{}, map[Binding]bool{}, map[string]bool{}
	for i, raw := range objectsRaw {
		o, ref := decodeObject(raw, i)
		if ref != nil {
			return nil, ref
		}
		b.Objects = append(b.Objects, o)
		actualIDs[o.CanonicalIdentity] = true
		actualBindings[Binding{TypeIdentity: o.TypeIdentity, TypeVersion: o.TypeVersion}] = true
		if o.GovernanceReference != nil && *o.GovernanceReference != "" {
			actualRefs[*o.GovernanceReference] = true
		}
	}
	if !sameSet(bindings, actualBindings) {
		return nil, malformed("", 0, "manifest.type_bindings does not describe the bundle contents")
	}
	for name, pair := range map[string]struct {
		declared []string
		actual   map[string]bool
	}{
		"identities":            {identities, actualIDs},
		"governance_references": {references, actualRefs},
	} {
		if !sameSet(pair.declared, pair.actual) {
			return nil, malformed("", 0, "manifest.%s does not describe the bundle contents", name)
		}
	}
	return b, nil
}
