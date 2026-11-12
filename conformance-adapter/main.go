// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Brafford Labs, LLC

// Conformance adapter for the Go runtime. NON-NORMATIVE test
// infrastructure. See ../../python/conformance-adapter/ADAPTER-AUDIT.md.
//
// Two channels are kept apart:
//
//   - caller_result is the exact value the governed runtime API returned to the
//     requester (core.Outcome and the returned *store.ObjectRecord, or nil),
//     serialized with encoding/json and nothing removed, added, or renamed.
//   - semantic_view / canonical_history are administrative observations made
//     with Runtime.Inspect after the step. They are never caller-visible and
//     are used only to check canonical effects.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/governedobjects/governed-objects-go/auth"
	"github.com/governedobjects/governed-objects-go/core"
	"github.com/governedobjects/governed-objects-go/events"
	"github.com/governedobjects/governed-objects-go/replay"
	"github.com/governedobjects/governed-objects-go/runtime"
	"github.com/governedobjects/governed-objects-go/store"
	"github.com/governedobjects/governed-objects-go/types"
	"github.com/governedobjects/governed-objects-go/version"
)

const (
	workItemFixture = "conformance.work-item"
	recordFixture   = "conformance.record"
	governanceRef   = "conformance-governance/1"
)

type restoreRelationship struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

type restoreEntry struct {
	Position              int                   `json:"position"`
	Effect                string                `json:"effect"`
	ResultingVersion      string                `json:"resulting_object_version"`
	PostImage             map[string]string     `json:"post_image"`
	BaselineRelationships []restoreRelationship `json:"baseline_relationships"`
	Relationship          *restoreRelationship  `json:"relationship"`
	Actor                 *string               `json:"actor"`
	AcceptedAt            *string               `json:"accepted_at"`
}

type restoreObject struct {
	CanonicalIdentity    string                `json:"canonical_identity"`
	TypeIdentity         string                `json:"type_identity"`
	TypeVersion          string                `json:"type_version"`
	AcceptedState        map[string]string     `json:"accepted_state"`
	Relationships        []restoreRelationship `json:"relationships"`
	CurrentObjectVersion string                `json:"current_object_version"`
	History              []restoreEntry        `json:"history"`
}

type request struct {
	ID              string                 `json:"id"`
	Op              string                 `json:"op"`
	Actor           string                 `json:"actor"`
	ObjectID        string                 `json:"object_id"`
	Type            string                 `json:"type"`
	InitialState    map[string]interface{} `json:"initial_state"`
	Changes         map[string]interface{} `json:"changes"`
	To              string                 `json:"to"`
	ExpectedVersion json.RawMessage        `json:"expected_version"`
	Relationship    map[string]string      `json:"relationship"`
	Relationships   []map[string]string    `json:"relationships"`
	Objects         []restoreObject        `json:"objects"`
	Revoke          []string               `json:"revoke"`
	Fixtures        json.RawMessage        `json:"fixtures"`
	FixturesSHA256  string                 `json:"fixtures_sha256"`
}

type response struct {
	ID               string                   `json:"id"`
	Ok               bool                     `json:"ok"`
	Outcome          string                   `json:"outcome"`
	OutcomeNative    string                   `json:"outcome_native,omitempty"`
	OutcomeDetail    string                   `json:"outcome_detail,omitempty"`
	Unmappable       bool                     `json:"unmappable"`
	CallerResult     map[string]interface{}   `json:"caller_result,omitempty"`
	SemanticView     map[string]interface{}   `json:"semantic_view,omitempty"`
	Capabilities     map[string]interface{}   `json:"capabilities,omitempty"`
	CanonicalHistory []map[string]interface{} `json:"canonical_history,omitempty"`
	AuditHistory     []map[string]interface{} `json:"audit_history,omitempty"`
	Error            *string                  `json:"error"`
	FixturesSHA256   string                   `json:"fixtures_sha256,omitempty"`
	TypesDefined     []string                 `json:"types_defined,omitempty"`
}

type session struct {
	rt      *runtime.Runtime
	st      *store.MemoryStore
	revoked map[string]bool
	fx      *fixtureSet // suite-owned fixture definitions; nil until define_fixture_types
	fxSHA   string
}

func (s *session) grants() map[core.Actor][]auth.Capability {
	out := map[core.Actor][]auth.Capability{}
	if s.fx == nil {
		return out
	}
	for actor, perms := range s.fx.Actors {
		if s.revoked[actor] {
			continue
		}
		caps := []auth.Capability{}
		for _, p := range perms {
			caps = append(caps, permissionCapability[p])
		}
		out[core.Actor(actor)] = caps
	}
	return out
}

// start builds a Runtime over the session store. Runtime-local configuration
// (grants, portable types, governance references) is supplied again on every
// start from the suite's fixture definitions; the store survives a restart.
func (s *session) start() error {
	s.rt = runtime.NewRuntime(s.st, auth.NewGrantAuthorizer(s.grants()))
	if s.fx == nil {
		return nil
	}
	refs := map[types.Binding]core.GovernanceReference{}
	for _, id := range s.fx.typeIDs() {
		t := s.fx.Types[id]
		if err := t.register(s.rt, id); err != nil {
			return fmt.Errorf("fixture %s: %v", id, err)
		}
		refs[t.portable(id).Binding()] = governanceRef
	}
	s.rt.SetGovernance(refs)
	return nil
}

// reset discards objects and revocations; the received fixture definitions are kept.
func (s *session) reset() error {
	s.st = store.NewMemoryStore()
	s.revoked = map[string]bool{}
	return s.start()
}

func (s *session) define(raw json.RawMessage, sha string) error {
	fx, err := parseFixtures(raw)
	if err != nil {
		return err
	}
	s.fx, s.fxSHA = fx, sha
	return s.start()
}

func buildInfo() map[string]interface{} {
	info := map[string]interface{}{}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	info["go_version"] = bi.GoVersion
	info["main_module"] = bi.Main.Path
	for _, dep := range bi.Deps {
		if dep.Path != "github.com/governedobjects/governed-objects-go" {
			continue
		}
		info["runtime_module"] = dep.Path
		if dep.Replace != nil {
			info["runtime_replace_dir"] = dep.Replace.Path
		}
	}
	settings := map[string]string{}
	for _, kv := range bi.Settings {
		settings[kv.Key] = kv.Value
	}
	info["settings"] = settings
	return info
}

func (s *session) capabilities() map[string]interface{} {
	actors := []string{}
	if s.fx != nil {
		actors = s.fx.actorNames()
	}
	return map[string]interface{}{
		"protocol":                   "draft2.2",
		"implementation":             map[string]string{"name": version.Name, "version": version.Version},
		"spec_version":               "v0alpha1",
		"spec_revision":              "draft2.2",
		"core_claimed":               true,
		"profiles_claimed":           []string{},
		"replay":                     true,
		"replay_types":               []string{workItemFixture, recordFixture},
		"mutable_objects":            true,
		"expected_version_required":  false,
		"unconditional_mutation":     true,
		"relationship_add":           true,
		"relationship_remove":        true,
		"type_version_exposed":       true,
		"semantic_portability_view":  true,
		"replay_baseline":            "creation_event_plus_history",
		"caller_result":              "exact core.Outcome and returned *store.ObjectRecord (encoding/json)",
		"observer_channel":           "Runtime.Inspect (administrative, unaudited deep copy)",
		"actors":                     actors,
		"restart":                    true,
		"governance_reconfiguration": true,
		"harness_clock":              false,
		"restoration":                true,
		"restoration_api":            "Runtime.ImportBundle",
		"restorable_types":           []string{recordFixture},
		"create_with_relationships":  false,
		"operational_metadata_ops":   []string{},
		"version_token_grammar":      runtime.NativeTokenGrammar,
		"version_request_encoding":   "decimal-integer",
		"object_version_ceiling":     strconv.FormatInt(math.MaxInt64, 10),
		"declared_refusals":          []string{core.ReasonObjectVersionSpaceExhausted},
		"concurrent_invocation":      false,
		"build":                      buildInfo(),
		"notes": []string{
			"conformance.work-item, conformance.record and conformance.party are portable types registered through Runtime.RegisterPortableType",
			"no clock hook: event timestamps come from time.Now in the runtime",
		},
	}
}

func mapOutcome(o core.Outcome) (string, bool) {
	switch o.Kind {
	case core.OutcomeAccepted:
		return "ACCEPTED", false
	case core.OutcomeDenied:
		return "AUTHORIZATION_DENIED", false
	case core.OutcomeInvalid:
		return "SEMANTICALLY_INVALID", false
	case core.OutcomeConflict:
		return "CONFLICT", false
	case core.OutcomeRefused:
		return "REFUSED", false
	default:
		return "UNMAPPABLE", true
	}
}

func fixtureTypeIdentity(t core.TypeIdentity) string { return string(t) }

// bindingFor returns the type binding the caller names for an operation, taken from
// the suite's fixture definitions. An absent type means the work-item fixture.
func (s *session) bindingFor(req request) (types.Binding, error) {
	identity := req.Type
	if identity == "" {
		identity = workItemFixture
	}
	if s.fx == nil {
		return types.Binding{}, fmt.Errorf("fixture definitions not received (define_fixture_types)")
	}
	t, ok := s.fx.Types[identity]
	if !ok {
		return types.Binding{}, fmt.Errorf("type %q is not a suite fixture", identity)
	}
	return t.portable(identity).Binding(), nil
}

// parseExpectedVersion distinguishes an absent or null precondition from a
// token. A value that is not a decimal integer is a request error, never a
// silent unconditional mutation.
func parseExpectedVersion(raw json.RawMessage) (*core.ObjectVersion, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" {
		return nil, nil
	}
	if strings.HasPrefix(text, "\"") {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		text = s
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("expected_version %s is not a native Object Version: %v", string(raw), err)
	}
	v := core.ObjectVersion(n)
	return &v, nil
}

// stringState passes string values through unchanged. The portable-type API
// takes map[string]string, so a non-string value is not expressible and is a
// request error rather than something to coerce.
func stringState(m map[string]interface{}) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range m {
		text, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("field %q value %v is not a string; not expressible on the Go portable-type API", k, v)
		}
		out[k] = text
	}
	return out, nil
}

func historyEntry(evt events.CanonicalEvent) map[string]interface{} {
	entry := map[string]interface{}{
		"effect":             string(evt.Kind),
		"canonical_identity": evt.CanonicalID,
		"type_identity":      fixtureTypeIdentity(evt.TypeIdentity),
		"type_version":       evt.TypeVersion,
		"object_version":     evt.ResultingVersion,
		"actor":              string(evt.Actor),
	}
	if !evt.Timestamp.IsZero() {
		entry["accepted_at"] = evt.Timestamp.UTC().Format(time.RFC3339Nano)
	}
	if evt.Payload != nil {
		if relType, ok := evt.Payload["relationship_type"]; ok {
			entry["relationship_type"] = relType
		}
		if target, ok := evt.Payload["target"]; ok {
			entry["relationship_target"] = target
		}
	}
	return entry
}

func acceptedState(attrs map[string]string) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range attrs {
		out[k] = v
	}
	return out
}

func relationshipList(rels []core.Relationship) []map[string]string {
	out := make([]map[string]string, 0, len(rels))
	for _, rel := range rels {
		out = append(out, map[string]string{"source": string(rel.Source), "type": string(rel.Type), "target": string(rel.Target)})
	}
	return out
}

// observe is the administrative observer channel (not caller-visible).
func (s *session) observe(id core.CanonicalIdentity) map[string]interface{} {
	obj, ok := s.rt.Inspect(id)
	if !ok {
		return nil
	}
	history := make([]map[string]interface{}, 0, len(obj.CanonicalEvents))
	for _, evt := range obj.CanonicalEvents {
		history = append(history, historyEntry(evt))
	}
	return map[string]interface{}{
		"channel":                   "observer",
		"canonical_identity":        string(obj.CanonicalID),
		"type_identity":             fixtureTypeIdentity(obj.TypeIdentity),
		"type_version":              string(obj.TypeVersion),
		"object_version":            obj.ObjectVersion,
		"accepted_state":            acceptedState(obj.Attributes),
		"relationships":             relationshipList(obj.Relationships),
		"canonical_history_summary": history,
	}
}

func callerResult(out core.Outcome, obj *store.ObjectRecord) map[string]interface{} {
	return map[string]interface{}{"api": "(core.Outcome, *store.ObjectRecord)", "outcome": out, "record": obj}
}

func (s *session) governed(resp *response, id core.CanonicalIdentity, out core.Outcome, obj *store.ObjectRecord) response {
	outcome, unm := mapOutcome(out)
	resp.Outcome = outcome
	resp.OutcomeNative = string(out.Kind)
	resp.Unmappable = unm
	resp.OutcomeDetail = out.Reason
	resp.CallerResult = callerResult(out, obj)
	resp.SemanticView = s.observe(id)
	return *resp
}

func requestError(resp *response, err error) response {
	msg := err.Error()
	resp.Ok = false
	resp.Error = &msg
	resp.Outcome = "UNMAPPABLE"
	resp.Unmappable = true
	return *resp
}

func unmappable(resp *response, detail string) response {
	resp.Outcome = "UNMAPPABLE"
	resp.Unmappable = true
	resp.OutcomeDetail = detail
	return *resp
}

func (s *session) ctx(req request, action core.Action) (core.OperationContext, error) {
	ev, err := parseExpectedVersion(req.ExpectedVersion)
	if err != nil {
		return core.OperationContext{}, err
	}
	return core.OperationContext{
		Actor:           core.Actor(req.Actor),
		Action:          action,
		Target:          core.CanonicalIdentity(req.ObjectID),
		ExpectedVersion: ev,
	}, nil
}

func (s *session) restore(resp *response, req request) response {
	b := runtime.ImportBundle{
		Closed:                   false,
		HistoryCompleteness:      runtime.ImportHistoryCompleteness,
		HistoryPositionModel:     runtime.ImportHistoryPositionModel,
		GovernanceReferenceModel: runtime.ImportGovernanceReferenceModel,
		SourceImplementation:     "conformance-harness",
	}
	rev := runtime.ImportSpecRevision
	b.SpecRevision = &rev
	for _, o := range req.Objects {
		ref := governanceRef
		obj := runtime.ImportObject{
			CanonicalIdentity:    o.CanonicalIdentity,
			TypeIdentity:         o.TypeIdentity,
			TypeVersion:          o.TypeVersion,
			GovernanceReference:  &ref,
			AcceptedState:        o.AcceptedState,
			CurrentObjectVersion: o.CurrentObjectVersion,
		}
		for _, r := range o.Relationships {
			obj.Relationships = append(obj.Relationships, runtime.ImportRelationship{Source: o.CanonicalIdentity, Type: r.Type, Target: r.Target})
		}
		for _, e := range o.History {
			entry := runtime.ImportEntry{
				Position:               e.Position,
				Effect:                 e.Effect,
				TypeIdentity:           o.TypeIdentity,
				TypeVersion:            o.TypeVersion,
				ResultingObjectVersion: e.ResultingVersion,
				PostImage:              e.PostImage,
				Evidence:               runtime.ImportEvidence{Actor: e.Actor, AcceptedAt: e.AcceptedAt},
			}
			if e.BaselineRelationships != nil {
				entry.HasBaseline = true
				for _, r := range e.BaselineRelationships {
					entry.BaselineRelationships = append(entry.BaselineRelationships, runtime.ImportRelationship{Source: o.CanonicalIdentity, Type: r.Type, Target: r.Target})
				}
			}
			if e.Relationship != nil {
				entry.Relationship = &runtime.ImportRelationship{Source: o.CanonicalIdentity, Type: e.Relationship.Type, Target: e.Relationship.Target}
			}
			obj.History = append(obj.History, entry)
		}
		b.Objects = append(b.Objects, obj)
	}
	ctx := core.OperationContext{Actor: core.Actor(req.Actor), Action: core.ActionImport}
	res, refusal := s.rt.ImportBundle(ctx, b, runtime.ImportProvenance{SourceImplementation: "conformance-harness", Adapter: "conformance-adapter-draft22"})
	resp.CallerResult = map[string]interface{}{"api": "(*runtime.ImportResult, *runtime.ImportRefusal)", "result": res, "refusal": refusal}
	if refusal != nil {
		resp.OutcomeNative = refusal.Code
		resp.OutcomeDetail = refusal.Error()
		if refusal.Code == runtime.ImportAuthorizationDenied {
			resp.Outcome = "AUTHORIZATION_DENIED"
		} else {
			resp.Outcome = "REFUSED"
		}
	} else {
		resp.Outcome = "ACCEPTED"
		resp.OutcomeNative = "imported"
	}
	if len(req.Objects) == 1 {
		resp.SemanticView = s.observe(core.CanonicalIdentity(req.Objects[0].CanonicalIdentity))
	}
	return *resp
}

func (s *session) handle(req request) response {
	resp := response{ID: req.ID, Ok: true, Error: nil}
	id := core.CanonicalIdentity(req.ObjectID)
	switch req.Op {
	case "capabilities":
		resp.Outcome = "ACCEPTED"
		resp.Capabilities = s.capabilities()
		return resp
	case "reset":
		if err := s.reset(); err != nil {
			return requestError(&resp, err)
		}
		resp.Outcome = "ACCEPTED"
		return resp
	case "define_fixture_types":
		if err := s.define(req.Fixtures, req.FixturesSHA256); err != nil {
			return requestError(&resp, err)
		}
		resp.Outcome = "ACCEPTED"
		resp.FixturesSHA256 = s.fxSHA
		resp.TypesDefined = s.fx.typeIDs()
		return resp
	case "restart":
		for _, a := range req.Revoke {
			if s.fx == nil || s.fx.Actors[a] == nil {
				return requestError(&resp, fmt.Errorf("unknown actor %q", a))
			}
			s.revoked[a] = true
		}
		if err := s.start(); err != nil {
			return requestError(&resp, err)
		}
		resp.Outcome = "ACCEPTED"
		return resp
	case "create":
		ctx := core.OperationContext{Actor: core.Actor(req.Actor), Action: core.ActionCreate, Target: id}
		if len(req.Relationships) > 0 {
			return unmappable(&resp, "Go runtime creation API carries no relationships (create_with_relationships=false)")
		}
		binding, err := s.bindingFor(req)
		if err != nil {
			return requestError(&resp, err)
		}
		state, err := stringState(req.InitialState)
		if err != nil {
			return requestError(&resp, err)
		}
		state = s.fx.Types[string(binding.Identity)].withDefaults(state)
		out, obj := s.rt.CreateObject(ctx, id, binding, state)
		return s.governed(&resp, id, out, obj)
	case "read":
		ctx := core.OperationContext{Actor: core.Actor(req.Actor), Action: core.ActionRead, Target: id}
		out, obj := s.rt.Read(ctx, id)
		return s.governed(&resp, id, out, obj)
	case "mutate":
		ctx, err := s.ctx(req, core.ActionUpdate)
		if err != nil {
			return requestError(&resp, err)
		}
		changes, err := stringState(req.Changes)
		if err != nil {
			return requestError(&resp, err)
		}
		binding, err := s.bindingFor(req)
		if err != nil {
			return requestError(&resp, err)
		}
		out, obj := s.rt.UpdateState(ctx, id, binding, changes)
		return s.governed(&resp, id, out, obj)
	case "transition":
		ctx, err := s.ctx(req, core.ActionTransition)
		if err != nil {
			return requestError(&resp, err)
		}
		binding, err := s.bindingFor(req)
		if err != nil {
			return requestError(&resp, err)
		}
		out, obj := s.rt.TransitionLifecycle(ctx, id, binding, req.To)
		return s.governed(&resp, id, out, obj)
	case "add_relationship", "remove_relationship":
		action := core.ActionAddRelationship
		if req.Op == "remove_relationship" {
			action = core.ActionRemoveRelationship
		}
		ctx, err := s.ctx(req, action)
		if err != nil {
			return requestError(&resp, err)
		}
		rel := core.Relationship{Source: id, Type: core.RelationshipType(req.Relationship["type"]), Target: core.CanonicalIdentity(req.Relationship["target"])}
		var out core.Outcome
		var obj *store.ObjectRecord
		if req.Op == "add_relationship" {
			out, obj = s.rt.AddRelationship(ctx, id, rel)
		} else {
			out, obj = s.rt.RemoveRelationship(ctx, id, rel)
		}
		return s.governed(&resp, id, out, obj)
	case "restore":
		return s.restore(&resp, req)
	case "get_history":
		obj, ok := s.rt.Inspect(id)
		if !ok {
			resp.Outcome = "SEMANTICALLY_INVALID"
			return resp
		}
		canonical := make([]map[string]interface{}, 0)
		audit := make([]map[string]interface{}, 0)
		for _, evt := range obj.CanonicalEvents {
			canonical = append(canonical, historyEntry(evt))
		}
		for _, rec := range obj.AuditRecords {
			audit = append(audit, map[string]interface{}{"kind": rec.Kind})
		}
		resp.Outcome = "ACCEPTED"
		resp.SemanticView = s.observe(id)
		resp.CanonicalHistory = canonical
		resp.AuditHistory = audit
		return resp
	case "replay":
		obj, ok := s.rt.Inspect(id)
		if !ok {
			resp.Outcome = "SEMANTICALLY_INVALID"
			return resp
		}
		reconstructed, err := replay.Reconstruct(obj.CanonicalEvents, s.rt)
		if err != nil {
			resp.Outcome = "SEMANTICALLY_INVALID"
			resp.OutcomeDetail = err.Error()
			return resp
		}
		history := make([]map[string]interface{}, 0, len(reconstructed.CanonicalEvents))
		for _, evt := range reconstructed.CanonicalEvents {
			history = append(history, historyEntry(evt))
		}
		resp.Outcome = "ACCEPTED"
		resp.SemanticView = map[string]interface{}{
			"channel":                   "replay",
			"canonical_identity":        string(reconstructed.CanonicalID),
			"type_identity":             fixtureTypeIdentity(reconstructed.TypeIdentity),
			"type_version":              string(reconstructed.TypeVersion),
			"object_version":            reconstructed.ObjectVersion,
			"accepted_state":            acceptedState(reconstructed.Attributes),
			"relationships":             relationshipList(reconstructed.Relationships),
			"canonical_history_summary": history,
		}
		return resp
	case "semantic_view":
		view := s.observe(id)
		if view == nil {
			resp.Outcome = "SEMANTICALLY_INVALID"
			return resp
		}
		resp.Outcome = "ACCEPTED"
		resp.SemanticView = view
		return resp
	case "set_clock":
		return unmappable(&resp, "Go runtime exposes no clock hook (harness_clock=false)")
	case "detach":
		return unmappable(&resp, "Go runtime exposes no operational-metadata-only operation")
	default:
		return requestError(&resp, fmt.Errorf("unknown op %s", req.Op))
	}
}

func main() {
	s := &session{}
	if err := s.reset(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	enc := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			msg := err.Error()
			_ = enc.Encode(response{Ok: false, Error: &msg, Outcome: "UNMAPPABLE", Unmappable: true})
			continue
		}
		_ = enc.Encode(s.handle(req))
	}
}
