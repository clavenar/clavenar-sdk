# clavenar-sdk — endpoint reference

Per-client method → HTTP route → return type. One table per client,
ordered against the source: `src/client.rs`, `src/ledger.rs`,
`src/agents.rs`, `src/policies.rs`, `src/brain.rs`, `src/sim.rs`,
`src/hil.rs`.

Every method returns `Result<T, ClavenarError>`; the **Returns** column
names the `Ok` type `T`. Routes are relative to each client's
`base_url`, which `parse_base_url` (`src/http.rs`) normalizes to a
trailing slash before `Url::join`. Path segments shown as `{…}` are
percent-encoded (`percent_encode`, `src/http.rs`); query values built
from operator input are encoded the same way. Each call snapshots the
`reqwest::Client` per request via `HttpProvider::client()`.

Status dispatch differs per client and is noted under each table. The
shared `decode_response` (`src/http.rs`) maps `200`/`201` → typed `T`,
`401` → `Unauthorized`, `400` → `BadRequest`, and every other non-2xx →
`Server { status, body }`.

For the call-by-call walkthroughs (veto parse, optimistic-concurrency
conflict, typed-error lift), see [`SEQUENCES.md`](./SEQUENCES.md).

---

## `ClavenarClient` — proxy `POST /mcp` (`src/client.rs`)

| Method | HTTP route | Returns |
|---|---|---|
| `call_tool(name, arguments)` | `POST /mcp` — JSON-RPC `tools/call` body | `serde_json::Value` |
| `authorize_prepared_tool(&prepared)` / `authorize_prepared_tool_batch(&prepared)` | validate a serializable, pre-network stable UUID and send `POST /mcp` with the side-effect-free decision selector | `SignedAuthorization` |
| `authorize_tool(idempotency_id, name, arguments)` | `POST /mcp` with the `clavenar.decision/v1` selector; side-effect-free and no server-execution fallback | `SignedAuthorization` |
| `execute_prepared_tool(&prepared)` / `execute_prepared_tool_batch(&prepared)` | validate and reuse the retained UUID, authorize, invoke the registered executor, and record a receipt | actual-result `ExecutionOutcome` |
| `execute_tool(idempotency_id, name, arguments)` | authorize exact payload, invoke the builder-registered executor, `POST /execution-receipts` | actual-result `ExecutionOutcome` without executable authorization bytes |
| `flush_execution_receipt_outbox(limit)` | load bounded pending signed receipts from `DurableExecutionStore`, `POST /execution-receipts`, and mark only confirmed entries delivered; performs no tool authorization or execution | delivered receipt count |
| `send_jsonrpc(method, params)` | `POST /mcp` — arbitrary JSON-RPC body | `serde_json::Value` |

Owns its own dispatch (not `decode_response`): `200` → `Value`, `403` →
`Veto` via `parse_veto` (structured fields or `raw` verbatim), `401` →
`Unauthorized`, `400` → `BadRequest`, else `Server`. Sends
`Authorization: Bearer` when built with `Auth::Bearer`.

---

## `LedgerClient` — audit / verify / analytics / cases (`src/ledger.rs`)

| Method | HTTP route | Returns |
|---|---|---|
| `audit_correlation(correlation_id)` | `GET /audit/correlation/{id}` | `Vec<LedgerEntry>` |
| `audit_agent(agent_id)` | `GET /audit/{agent_id}` | `Vec<LedgerEntry>` |
| `audit_agent_paged(agent_id, limit, offset)` | `GET /audit/{agent_id}?limit=&offset=` | `Vec<LedgerEntry>` |
| `audit_agent_paged_before(agent_id, limit, before_seq)` | `GET /audit/{agent_id}?limit=&before=` | `Vec<LedgerEntry>` |
| `audit_agent_paged_after(agent_id, limit, after_seq)` | `GET /audit/{agent_id}?limit=&after=` | `Vec<LedgerEntry>` |
| `audit_agent_paged_since(agent_id, limit, offset, since)` / `audit_agent_paged_since_for_tenant(..., tenant)` | `GET /audit/{agent_id}?limit=&offset=&since=[&tenant=]` | `Vec<LedgerEntry>` |
| `audit_agent_paged_before_since(agent_id, limit, before_seq, since)` | `GET /audit/{agent_id}?limit=&before=&since=` | `Vec<LedgerEntry>` |
| `audit_agent_paged_after_since(agent_id, limit, after_seq, since)` | `GET /audit/{agent_id}?limit=&after=&since=` | `Vec<LedgerEntry>` |
| `audit_agent_count(agent_id)` | `GET /audit/{agent_id}/count` | `usize` (unwraps `{ count }`) |
| `list_agents()` | `GET /agents` | `Vec<String>` (unwraps `{ agents }`) |
| `lifecycle_for_agent(tenant, agent_id)` | `GET /audit/agent/{tenant}/{agent_id}/lifecycle` | `Vec<LifecycleRow>` |
| `masked_params_for_entry(entry_id)` | `GET /audit/entry/{entry_id}/masked-params` | `Option<serde_json::Value>` (unwraps `{ masked_params }`) |
| `replay_corpus(params)` | `GET /audit/replay/corpus?since=&limit=[&until=&agent_id=&tool_type=]` | `ReplayCorpus` |
| `verify()` | `GET /verify` | `VerifyResult` |
| `list_exports()` | `GET /exports` | `Vec<ExportRecord>` |
| `trigger_export()` | `POST /export` | `ExportOutcome` |
| `envelope_analysis(agent_id, window_days)` / `envelope_analysis_for_tenant(..., tenant)` | `GET /analysis/agent-envelope-recommendations?agent_id=&window_days=[&tenant=]` | `EnvelopeAnalysis` |
| `behavioral_baseline(agent_id, baseline_days, recent_days)` / `behavioral_baseline_for_tenant(..., tenant)` | `GET /analysis/agent-behavioral-baseline?agent_id=&baseline_days=&recent_days=[&tenant=]` | `BehavioralBaseline` |
| `silent_agents(since_hours)` / `silent_agents_for_tenant(..., tenant)` | `GET /analysis/silent-agents?since_hours=[&tenant=]` | `SilentAgentsReport` |
| `fleet_behavioral_diff(baseline_days, recent_days, limit)` / `fleet_behavioral_diff_for_tenant(..., tenant)` | `GET /analysis/fleet-behavioral-diff?baseline_days=&recent_days=&limit=[&tenant=]` | `FleetBehavioralDiff` |
| `model_upgrade_canary_for_tenant(cutover, window_hours, tenant)` / `model_upgrade_canary_scoped(..., scope)` | `GET /analysis/model-upgrade-canary?window_hours=[&cutover=][&tenant=][&demo_session_token=]` | `ModelUpgradeCanary` |
| `hunt(params)` | `GET /audit/hunt?limit=[&method=&signal=&authorized=&from=&to=&tenant=&demo_session_token=]` | `HuntResult` |
| `finops_spend(window, tenant, limit)` | `GET /finops/spend?limit=[&window=&tenant=]` | `SpendRollup` (`tenant` `None` → deployment-wide rollup) |
| `compliance_evidence(from, to)` | `POST /compliance/evidence?from=&to=` | `ComplianceRegister` |
| `regulatory_export(from, to, opts)` | `POST /export/regulatory?from=&to=[&include_exports=true][&include_compliance=true]` | `Vec<u8>` (raw `.tar.gz` bytes) |
| `create_case(title, agent_ids, correlation_ids, actor)` | `POST /cases` | `CaseRecord` |
| `list_cases(status, limit)` | `GET /cases?limit=[&status=]` | `Vec<CaseRecord>` |
| `get_case(id)` | `GET /cases/{id}` | `CaseDetail` |
| `append_case_timeline(id, ev)` | `POST /cases/{id}/timeline` | `()` |
| `set_case_status(id, status)` | `POST /cases/{id}/status` | `()` |
| `classify_case(id, severity)` | `POST /cases/{id}/classify` | `(String, String)` — `(severity, regulatory_deadline)` |
| `attach_case(id, agent_ids, correlation_ids)` | `POST /cases/{id}/attach` | `()` |
| `tombstone_tenant(tenant, reason)` | `POST /admin/tenants/{tenant}/tombstone` | `i64` (rows tombstoned; unwraps `{ tombstoned }`) |

`HuntResult.agents[]` includes `latest_correlation_id` when the newest
matching ledger row for that agent carried a correlation ID. Clients can use
it to seed incident cases from the rollup without fetching every row first.

No bearer. `get_json` accepts only `200` (else `Server`); `post_json`
accepts any 2xx and treats an empty body as `()` via a `null` fallback;
`regulatory_export` streams raw bytes on 2xx and maps non-2xx to
`Server` (`400` inverted window, `413` oversize readme, `503` signing
unavailable). The `since`/`from`/`to`/`cutover` instants serialize as
RFC 3339.

---

## `AgentsClient` — identity `/agents` lifecycle (`src/agents.rs`)

| Method | HTTP route | Returns |
|---|---|---|
| `list(tenant, filter)` | `GET /agents?tenant=[&state=&owner_team=]` | `Vec<AgentRecord>` |
| `list_orphans(tenant)` | `GET /agents/orphans?tenant=` | `Vec<OrphanWorkload>` |
| `get(id, tenant)` | `GET /agents/{id}?tenant=` | `AgentRecord` |
| `list_active_grants(tenant, agent_name)` | `GET /grants?tenant=&agent_name=&active=true` | `Vec<GrantConsumption>` (unwraps `{ grants }`) |
| `find_by_name(tenant, agent_name)` | client-side filter over `GET /agents?tenant=` | `Option<AgentRecord>` |
| `create(req)` | `POST /agents` | `AgentCreated` |
| `suspend(id, tenant, reason)` | `POST /agents/{id}/suspend?tenant=` | `LifecycleResponse` |
| `unsuspend(id, tenant, reason)` | `POST /agents/{id}/unsuspend?tenant=` | `LifecycleResponse` |
| `decommission(id, tenant, reason)` | `POST /agents/{id}/decommission?tenant=` | `LifecycleResponse` |
| `envelope_narrow(id, tenant, envelope)` | `POST /agents/{id}/envelope/narrow?tenant=` | `AgentRecord` |
| `envelope_widen(id, tenant, envelope)` | `POST /agents/{id}/envelope/widen?tenant=` | `AgentRecord` |
| `attestation_kinds(id, tenant, kinds)` | `POST /agents/{id}/attestation-kinds?tenant=` | `AgentRecord` |
| `transfer_owner_team(id, tenant, new_team)` | `POST /agents/{id}/owner-team?tenant=` | `AgentRecord` |
| `record_certification(id, tenant, req)` | `POST /agents/{id}/certification?tenant=` | `SignedCertificate` |
| `set_description(id, tenant, text)` | `POST /agents/{id}/description?tenant=` | `AgentRecord` |
| `get_budget(tenant)` | `GET /tenants/{tenant}/budget` | `TenantBudget` (per-tenant monthly micro-USD ceiling; `budget_micros` `None` when unset) |
| `set_budget(tenant, budget_micros)` | `POST /tenants/{tenant}/budget` | `TenantBudget` |
| `offboard_tenant(tenant, confirm, reason)` | `POST /tenants/{tenant}/offboard` | `TenantOffboardResult` (`confirm` must equal `tenant`) |

Sends `Authorization: Bearer` when set via `with_bearer`; decodes via
`decode_response` (`create` returns `201`). `get`/`list` elide
cross-tenant existence by returning `404` → `Server`, not `403`.
`find_by_name` issues no dedicated route — it lists the tenant and
filters on `agent_name` in-process. `create_request_matches(req,
record) -> bool` (`src/agents.rs`) is a pure idempotency helper, no
network call.

---

## `PoliciesClient` — policy-engine `/policies` (`src/policies.rs`)

| Method | HTTP route | Returns |
|---|---|---|
| `list(include_deleted)` | `GET /policies?include_deleted=` | `Vec<PolicyRow>` (unwraps `{ policies }`) |
| `get(name)` | `GET /policies/{name}` | `PolicyDetail` |
| `list_versions(name)` | `GET /policies/{name}/versions` | `Vec<PolicyVersionRow>` (unwraps `{ versions }`) |
| `get_version(name, version)` | `GET /policies/{name}/versions/{n}` | `PolicyVersionRow` |
| `diff(name, from, to)` | `GET /policies/{name}/diff?from=&to=` | `DiffResponse` |
| `create(req)` | `POST /policies` | `MutationResponse` |
| `validate(req)` | `POST /policies/validate` | `ValidatePolicyResponse` |
| `update(name, req)` | `PUT /policies/{name}` | `MutationResponse` |
| `activate(name, req)` | `POST /policies/{name}/activate` | `MutationResponse` |
| `deactivate(name, req)` | `POST /policies/{name}/deactivate` | `MutationResponse` |
| `activate_category(domain, req)` | `POST /policies/categories/{domain}/activate` | `BatchMutationResponse` |
| `deactivate_category(domain, req)` | `POST /policies/categories/{domain}/deactivate` | `BatchMutationResponse` |
| `delete(name, req)` | `DELETE /policies/{name}` | `MutationResponse` (soft delete) |
| `evaluate_batch(req)` | `POST /policies/evaluate-batch` | `EvaluateBatchResponse` |
| `mine(req)` | `POST /policies/mine` | `MineResponse` |
| `list_templates()` | `GET /policies/templates` | `Vec<PolicyTemplate>` |
| `get_template(name)` | `GET /policies/templates/{name}` | `PolicyTemplateDetail` |
| `install_template(name, req)` | `POST /policies/templates/{name}/install` | `MutationResponse` |
| `lab_template(name, req)` | `POST /policies/templates/{name}/lab` | `EvaluateBatchResponse` |
| `rollback(name, version, req)` | `POST /policies/{name}/rollback/{version}` | `MutationResponse` |

Sends `Authorization: Bearer` when set; decodes via `decode_response`.
`409` (optimistic-concurrency conflict on `update`/`activate`/
`deactivate`/`delete`/`install_template`, or duplicate name on
`create`) lands in `Server { status: 409, body }` rather than a typed
variant. Lift the typed envelopes out of `Server.body` with these pure
parsers (no network call):

| Helper | Parses | Returns |
|---|---|---|
| `PoliciesClient::parse_conflict(body)` | `409` conflict body | `Option<ConflictResponse>` |
| `parse_batch_error(body)` (free fn) | `evaluate_batch` / `lab_template` `400` body | `Option<EvaluateBatchError>` |
| `parse_mine_error(body)` (free fn) | `mine` `400` body | `Option<MineError>` |

---

## `BrainClient` — `POST /explain-pattern` (`src/brain.rs`)

| Method | HTTP route | Returns |
|---|---|---|
| `explain_pattern(req)` | `POST /explain-pattern` | `ExplainPatternResponse` |

This is a loopback local/test compatibility client. In TLS production,
`/explain-pattern` lives on Brain's mTLS application port and accepts only the
exact `spiffe://clavenar.local/service/policy-engine` caller. The optional
bearer header does not authorize that route, and the generic SDK does not
acquire the policy-engine identity; production enrichment uses the
policy-engine's internal workload-identity client. Responses decode via
`decode_response`. The brain's `/inspect` hot-path surface is deliberately not
exposed — drive it through the proxy.

---

## `SimClient` — simulator admin surface (`src/sim.rs`)

| Method | HTTP route | Returns |
|---|---|---|
| `status()` | `GET /status` | `SimStatus` |
| `set_multiplier(multiplier)` | `POST /multiplier` | `SimStatus` |
| `set_multiplier_as(operator, multiplier)` | `POST /multiplier` | `SimStatus` |
| `set_running(running)` | `POST /running` | `SimStatus` |
| `set_running_as(operator, running)` | `POST /running` | `SimStatus` |
| `set_auto_decide(enabled)` | `POST /auto-decide` | `SimStatus` |
| `set_auto_decide_as(operator, enabled)` | `POST /auto-decide` | `SimStatus` |
| `add_agents(persona, count)` | `POST /agents` | `Vec<String>` (unwraps `{ spawned }`) |
| `add_agents_as(operator, persona, count)` | `POST /agents` | `Vec<String>` (unwraps `{ spawned }`) |

Outside local fixtures, inject an mTLS-capable `HttpProvider` whose workload
identity the simulator authorizes; network placement alone is not
authorization. Responses decode via `decode_response`;
`set_auto_decide` returns `409` → `Server` when the simulator booted
without `--hil-url`. The `_as` methods attach a bounded
`X-Clavenar-Operator` audit value without changing transport authorization.
Every request has a twenty-second deadline by default; callers can set a
different positive duration with `with_request_timeout`.

---

## `HilClient` — human-in-the-loop `/pending` + `/decide` (`src/hil.rs`)

| Method | HTTP route | Returns |
|---|---|---|
| `create_pending(body)` | `POST /pending` | `PendingRequest` |
| `list_pending()` / `list_pending_scoped(jwt)` | `GET /pending?status=pending` | `Vec<PendingRequest>` |
| `list_auto_approved()` / `list_auto_approved_scoped(jwt)` | `GET /pending?status=approved`, filtered to `decided_by = system:policy-tier` | `Vec<PendingRequest>` |
| `get_pending(id)` | `GET /pending/{id}` | `Option<PendingRequest>` (`404` → `None`) |
| `verify_decision_link(token)` | `POST /decision-link/verify` | `DecisionLinkVerify` |
| `patch_incident_summary(id, summary)` | `PATCH /pending/{id}/incident` | `PendingRequest` |
| `assign(id, assigned_to, pool)` | `POST /pending/{id}/assign` | `PendingRequest` |
| `notifications_config()` | `GET /notifications/config` | `ChannelStatus` |
| `notifications_test()` | `POST /notifications/test` | `ChannelStatus` |
| `get_pending_by_correlation(cid)` | `GET /pending/by-correlation/{cid}` | `Option<PendingRequest>` (`404` → `None`) |
| `approvals_stats(window)` / `approvals_stats_scoped(window, jwt)` | `GET /approvals/stats?window=` | `ApprovalStats` |
| `stream_pending()` / `stream_pending_scoped(jwt)` | `GET /pending/stream` (SSE) | raw `reqwest::Response` |
| `decide(id, decision, decided_by, reason, modified_payload, approver_assertion, credential, decided_via)` | `POST /decide/{id}` | `PendingRequest` |
| `auth_proxy_post(sub_path, body, hil_cookie)` | `POST /auth/{sub_path}` | `AuthProxyResponse` (opaque body + `Set-Cookie` values) |
| `identities_upsert(bearer, oidc_sub, slack, teams)` | `POST /identities/upsert` | `UserIdentities` |
| `identities_get(bearer, oidc_sub)` | `GET /identities/{oidc_sub}` | `Option<UserIdentities>` (`404` → `None`) |
| `identities_unlink_slack(bearer, oidc_sub)` / `identities_unlink_teams(...)` | `DELETE /identities/{oidc_sub}/{channel}` | `bool` (unwraps `{ cleared }`) |

Does **not** use `decode_response`: every non-2xx surfaces as
`Server { status, body }` so callers can branch per status (404 "no
longer pending", 409 "already decided", 422 "action invalid in this
state"). `_scoped` variants forward a demo-session JWT as the
`clavenar_demo_session` cookie; `with_tenant` sends the authenticated
`X-Clavenar-Tenant-Scope` header on scoped reads and mutations. HIL accepts
that header only from exact Console mTLS and independently matches it to the
typed decision principal. `decide`'s credential is a `HilDecideCredential` —
WebAuthn session cookie, trusted-caller bearer plus
`X-Clavenar-Decision-Principal`, or demo-session JWT.

---

_Re-verify against `src/client.rs`, `src/ledger.rs`, `src/agents.rs`,
`src/policies.rs`, `src/brain.rs`, `src/sim.rs`, `src/hil.rs`, and the
shared `decode_response` / `percent_encode` / `parse_base_url` in
`src/http.rs`._
