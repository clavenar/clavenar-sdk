# warden-sdk sequence diagrams

Typed async client for Agent Warden's HTTP surfaces. Every diagram
below traces one call through the SDK's status-dispatch + error
projection layer, ordered against the actual source: `src/client.rs`,
`src/ledger.rs`, `src/agents.rs`, `src/policies.rs`, `src/brain.rs`,
`src/http.rs`, `src/error.rs`.

## Lifelines

| Lifeline | Role | Source |
|---|---|---|
| Caller | External application, `warden-console`, or `wardenctl`. | — |
| WardenC | `WardenClient` — `POST /mcp` wrapper. | `src/client.rs` |
| LedgerC | `LedgerClient` — `/audit/*`, `/verify`, `/exports`, `/audit/replay/corpus`. | `src/ledger.rs` |
| AgentsC | `AgentsClient` — `/agents` + `/agents/{id}/<verb>` lifecycle. | `src/agents.rs` |
| PoliciesC | `PoliciesClient` — `/policies/*`, `/policies/evaluate-batch`, `/policies/mine`, `/policies/templates*`. | `src/policies.rs` |
| BrainC | `BrainClient` — single-endpoint client for `POST /explain-pattern`. | `src/brain.rs` |
| HttpP | `HttpProvider` — per-request `reqwest::Client` source. `StaticHttpClient` wraps one Client; hot-reload integrators return a fresh one per call. | `src/http.rs::HttpProvider`, `StaticHttpClient` |
| Decoder | `decode_response` + `parse_veto` — status-code dispatch to `WardenError` arms. | `src/http.rs`, `src/client.rs` |
| Server | The warden service the client targets — proxy / ledger / identity / policy-engine / brain. | external |

Every per-service client follows the same shape — `new(base_url)` →
`with_http_client` / `with_http_provider` → method calls that route
through `HttpProvider::client()` per request. The status dispatch
diagram (the flowchart at the end) captures the common decode
path; the five sequence diagrams below show what's distinct per
surface.

---

## 1. `WardenClient::call_tool` — proxy `POST /mcp` with veto parse

The headline use case. Wraps the JSON-RPC `tools/call` shape,
attaches bearer auth, dispatches on HTTP status, projects the
structured 403 into `WardenError::Veto` with a verbatim `raw`
fallback so callers do not have to special-case the proxy edition.

```mermaid
sequenceDiagram
    autonumber
    participant Caller
    participant WardenC as WardenClient::call_tool
    participant HttpP
    participant Server as warden-proxy / warden-lite
    participant ParseVeto as parse_veto

    Caller->>WardenC: call_tool("search", arguments)

    WardenC-->>WardenC: id = next_id.fetch_add(1, Relaxed). build JSON-RPC body. join base_url + "mcp".

    WardenC->>HttpP: client()
    HttpP-->>WardenC: Arc(reqwest::Client) snapshot. one Arc::clone per call. no rebuild on hot path.

    alt Auth::Bearer(token)
        WardenC-->>WardenC: req.bearer_auth(token)
    end

    WardenC->>Server: POST {base_url}/mcp with JSON body
    Server-->>WardenC: status + raw body text

    alt 200 OK
        WardenC-->>WardenC: serde_json::from_str(raw)
        alt parse fails
            WardenC--xCaller: WardenError::Decode (unexpected from a real proxy. transport bug.)
        else parse ok
            WardenC-->>Caller: Value (upstream JSON-RPC response)
        end
    else 403 Forbidden
        WardenC->>ParseVeto: parse_veto(raw)
        alt body is structured DenyResponse JSON
            ParseVeto-->>WardenC: Veto with intent_category + reasons + review_reasons + raw
        else body is plain text (full-edition proxy today)
            ParseVeto-->>WardenC: Veto with empty structured fields + raw verbatim
        end
        WardenC--xCaller: WardenError::Veto (callers branch on intent_category)
    else 401 Unauthorized
        WardenC--xCaller: WardenError::Unauthorized(raw)
    else 400 BadRequest
        WardenC--xCaller: WardenError::BadRequest(raw)
    else other (5xx, 503, 429, etc.)
        WardenC--xCaller: WardenError::Server with status + body
    end
```

**Non-obvious behaviour.**

- The 403 path **never** returns `WardenError::Decode`. A
  full-edition proxy that returns plain text falls into the
  `Veto with raw verbatim` branch — callers can match on
  `WardenError::Veto { raw, .. }` without knowing which proxy
  edition served them. This is the load-bearing edition-agnostic
  property of the SDK.
- `id` is an atomic monotonic counter. Concurrent `call_tool`
  calls from one client get distinct JSON-RPC ids without a
  mutex. `Ordering::Relaxed` is fine — uniqueness is the only
  invariant, not cross-thread happens-before.
- `Auth::None` is the warden-lite "open access" default. The
  builder defaults to it; callers opt into `Auth::Bearer`
  explicitly. mTLS / OIDC / SPIFFE are reserved by
  `#[non_exhaustive]` so adding them later is not a breaking
  change.
- `parse_base_url` forces a trailing slash before
  `Url::join("mcp")`. Without it,
  `http://h/api`.join("mcp") becomes `http://h/mcp` (RFC 3986
  replaces the last segment) and silently drops the prefix.
  Every per-service client routes through `parse_base_url`.

---

## 2. `LedgerClient` — audit fetch and verify

Six-endpoint read surface against `warden-ledger`. All paths
funnel through `get_json` + `HttpProvider::client()`. The diagram
shows the common operator workflow — pull a correlation join,
page through an agent's history, run a chain verify — to surface
the per-call hot-reload semantics.

```mermaid
sequenceDiagram
    autonumber
    participant Caller as Caller (console / ctl)
    participant LedgerC
    participant HttpP
    participant Ledger as warden-ledger

    Caller->>LedgerC: audit_correlation(uuid)
    LedgerC-->>LedgerC: percent_encode(correlation_id). join base_url with audit/correlation/{enc}.
    LedgerC->>HttpP: client()
    HttpP-->>LedgerC: Arc(reqwest::Client) snapshot
    LedgerC->>Ledger: GET /audit/correlation/{id}
    Ledger-->>LedgerC: 200 application/json. Vec of LedgerEntry.
    LedgerC-->>Caller: Vec of LedgerEntry (oldest first. empty vec on unknown id.)

    Caller->>LedgerC: audit_agent_paged(cn, limit, offset)
    LedgerC-->>LedgerC: percent_encode(cn). build url.query_pairs_mut. append limit + offset.
    LedgerC->>HttpP: client()
    Note over HttpP: hot-reload provider would hand back a fresh client here. Old in-flight requests keep their connection pool intact.
    HttpP-->>LedgerC: current Arc(Client)
    LedgerC->>Ledger: GET /audit/{cn}?limit=N&offset=M
    Ledger-->>LedgerC: 200. Vec of LedgerEntry newest first.
    LedgerC-->>Caller: page slice

    Caller->>LedgerC: verify()
    LedgerC->>HttpP: client()
    HttpP-->>LedgerC: Arc(Client)
    LedgerC->>Ledger: GET /verify
    Ledger-->>LedgerC: 200 VerifyResult (valid, entries_checked, first_invalid_seq, unsupported_chain_version)
    LedgerC-->>Caller: VerifyResult (valid flag drives the console banner)
```

**Non-obvious behaviour.**

- `audit_agent_paged` exists alongside `audit_agent` (full-chain)
  so UI callers can scale memory with `per_page` instead of chain
  depth. `audit_agent_count` pairs with it to drive
  total-pages math without a row read.
- `percent_encode` is the SDK's tiny RFC 3986 encoder.
  `Url::join` does **not** percent-encode path segments — a
  correlation_id with a `/` or `?` in it would reroute the
  request otherwise. UUIDs are hex-only so the encode is a no-op
  in the common case but defensive in general.
- `base_url()` and `http_client()` are exposed for callers that
  need SSE-streaming responses (`warden-console`'s live-tail
  proxy is the first such caller). The SDK still owns canonical
  request shaping; a streaming response cannot ride through the
  JSON-decode pipeline.
- `verify()` returns three distinct "valid=false" reasons:
  chain-hash tamper (`first_invalid_seq` set), unknown chain
  version (`unsupported_chain_version` set), and stale JWKS
  (also unsupported_chain_version so a caller that only checks
  `valid` still notices). The mapping is server-side — the SDK
  passes the typed envelope through unchanged.

---

## 3. `AgentsClient` lifecycle — bearer-authenticated CRUD

Mirrors `warden-identity`'s nine-endpoint lifecycle surface. Each
call carries `Authorization: Bearer <oidc_id_token>`; the server
validates against the per-tenant JWKS and resolves IdP groups to
capability strings. Diagram shows the suspend path; the other
seven `/agents/{id}/<verb>` endpoints are shape variants.

```mermaid
sequenceDiagram
    autonumber
    participant Caller as Caller (console / ctl)
    participant AgentsC
    participant HttpP
    participant Identity as warden-identity
    participant Decoder as decode_response

    Caller->>AgentsC: with_bearer(id_token). suspend(agent_uuid, LifecycleRequest)
    AgentsC-->>AgentsC: percent_encode(agent_uuid). join base_url with agents/{enc}/suspend.

    AgentsC->>HttpP: client()
    HttpP-->>AgentsC: Arc(Client)
    AgentsC-->>AgentsC: request.bearer_auth(id_token). json(req body).

    AgentsC->>Identity: POST /agents/{id}/suspend
    Identity-->>Identity: capability resolver. OIDC verify + tenant mismatch check + agents:suspend cap.
    Identity-->>Identity: prepare_lifecycle_emission. Vault Transit sign. Open SQLite tx. UPDATE agents row + INSERT outbox row + COMMIT.
    Identity-->>Identity: best-effort publish to warden.forensic. if NATS down, leave outbox row for sweeper.

    Identity-->>AgentsC: status + body
    AgentsC->>Decoder: decode_response(status, body)
    alt 200 OK or 201 Created
        Decoder-->>AgentsC: serde_json::from_str -> LifecycleResponse
        AgentsC-->>Caller: LifecycleResponse (new state, new envelope, chain row id)
    else 401 Unauthorized
        Decoder-->>AgentsC: WardenError::Unauthorized(body) (bad bearer)
        AgentsC--xCaller: Unauthorized
    else 400 BadRequest
        Decoder-->>AgentsC: WardenError::BadRequest(body) (validation)
        AgentsC--xCaller: BadRequest
    else 403 / 404 / 409 / 503
        Decoder-->>AgentsC: WardenError::Server with status + body
        AgentsC--xCaller: Server. caller branches on status code.
    end
```

**Non-obvious behaviour.**

- The SDK does NOT lift a tenant-mismatch 404 into a typed error.
  The server returns 404 (not 403) for cross-tenant reads to
  avoid leaking row existence; the SDK passes that through as
  `WardenError::Server` and lets callers branch.
- `create_request_matches` is exposed at the crate root for
  `wardenctl agents create --if-absent` idempotent IaC patterns.
  Callers compare a `CreateAgentRequest` against an existing
  `AgentRecord` to decide whether to skip the POST.
- The bearer token is per-`AgentsClient`-instance, not per-call.
  Multi-tenant callers build one client per tenant — the SDK does
  not hold a token map.
- `MIGRATION_ACTOR_SUB_PREFIX` is exposed so callers minting their
  own actor_sub for migration tooling do not collide with the
  reserved prefix the server uses to tag system-driven lifecycle
  rows.

---

## 4. `PoliciesClient::update` — optimistic concurrency with conflict

The mutation surface (`create`, `update`, `activate`, `deactivate`,
`delete`, `rollback`, `install_template`) all carry
`expected_current_version` and round-trip 409 with a typed
`ConflictResponse` body. The console renders the conflict as a
"reload the editor?" modal.

```mermaid
sequenceDiagram
    autonumber
    participant Caller as Caller (console Admin)
    participant PoliciesC
    participant HttpP
    participant Policy as warden-policy-engine
    participant Decoder as decode_response

    Caller->>PoliciesC: update(name, UpdatePolicyRequest with expected_current_version)
    PoliciesC-->>PoliciesC: percent_encode(name). build url.

    PoliciesC->>HttpP: client()
    HttpP-->>PoliciesC: Arc(Client)
    PoliciesC->>Policy: PUT /policies/{name} with body

    Policy-->>Policy: require_reason + require_content_type + validate (rego compile).
    Policy-->>Policy: SELECT PolicyRow. check current_version == expected_current_version.

    alt mismatch
        Policy-->>PoliciesC: 409 with ConflictResponse JSON
        PoliciesC->>Decoder: decode_response(409, body)
        Decoder-->>PoliciesC: WardenError::Server with status=409 + body (raw ConflictResponse JSON)
        PoliciesC--xCaller: Server. Caller may parse body into ConflictResponse to render the diff modal.
    else version match
        Policy-->>Policy: build candidate Engine outside live mutex. BEGIN tx. INSERT version + outbox row. COMMIT. swap live engine atomically.
        Policy-->>PoliciesC: 200 MutationResponse
        PoliciesC->>Decoder: decode_response(200, body)
        Decoder-->>PoliciesC: MutationResponse
        PoliciesC-->>Caller: MutationResponse (version, body_sha256, current_version, active, event_kind)
    else regorus compile error
        Policy-->>PoliciesC: 400 with error message
        Decoder-->>PoliciesC: WardenError::BadRequest(body)
        PoliciesC--xCaller: BadRequest
    end
```

**Non-obvious behaviour.**

- The 409 body **is** a `ConflictResponse` (typed). The SDK
  surfaces it as `WardenError::Server { status: 409, body }`
  rather than projecting it into a typed variant — callers that
  care parse the body via `serde_json::from_str::<ConflictResponse>(&body)`.
  The asymmetry with `Veto` is deliberate: 403 has one shape
  (security veto) per spec; 409 from the policy surface has
  multiple potential shapes as the surface grows, and the SDK
  does not commit to one.
- `decode_response` routes `409` (and `422`, `5xx`) all into the
  `Server` arm. Only `200`/`201`, `401`, and `400` get typed
  treatment in the shared decode helper. `WardenClient` keeps its
  own dispatcher because of the 403 → `Veto` parse step that the
  shared helper does not cover.
- `delete` is **soft** delete. The handler stamps `deleted_at`
  on the row; the policy stays visible at `GET /policies?include_deleted=true`.
  Callers that want hard-delete semantics do not have an SDK
  affordance — they would have to truncate the SQLite store
  directly, which the SDK refuses by surface area.

---

## 5. Lab and Miner — typed-error lift via `parse_batch_error` / `parse_mine_error`

Two adjacent endpoints with different 400 shapes. The SDK ships
free functions to lift the typed envelope out of
`WardenError::Server.body` so callers can render a structured
error (compile line/column for Lab; corpus-shape message for
Miner) without re-implementing the parse.

```mermaid
sequenceDiagram
    autonumber
    participant Caller as Caller (console Admin)
    participant PoliciesC
    participant HttpP
    participant Policy as warden-policy-engine
    participant ParseLab as parse_batch_error
    participant ParseMine as parse_mine_error

    rect rgb(245, 245, 245)
    Note over Caller, Policy: Policy Lab
    Caller->>PoliciesC: evaluate_batch(EvaluateBatchRequest with candidate_rego + corpus)
    PoliciesC->>HttpP: client()
    PoliciesC->>Policy: POST /policies/evaluate-batch
    Policy-->>Policy: rebuild before-engine and after-engine from active set. evaluate_one per input.

    alt candidate compile error
        Policy-->>PoliciesC: 400 with EvaluateBatchError JSON (active_compile_ok + candidate_compile_ok + compile_error with line + column)
        PoliciesC--xCaller: WardenError::Server status=400 body=raw
        Caller->>ParseLab: parse_batch_error(body)
        ParseLab-->>Caller: Some(EvaluateBatchError) (render line + column in editor gutter)
    else ok
        Policy-->>PoliciesC: 200 EvaluateBatchResponse (per-input verdict diff)
        PoliciesC-->>Caller: EvaluateBatchResponse (render result pane)
    end
    end

    rect rgb(245, 250, 245)
    Note over Caller, Policy: Self-Learn miner
    Caller->>PoliciesC: mine(MineRequest with corpus + max_candidates + ask_brain)
    PoliciesC->>HttpP: client()
    PoliciesC->>Policy: POST /policies/mine
    Policy-->>Policy: detectors. render Rego per pattern. compile-check. lab-diff per candidate. truncate. optional Brain enrichment.

    alt malformed request (empty corpus, too large)
        Policy-->>PoliciesC: 400 with MineError JSON (message)
        PoliciesC--xCaller: WardenError::Server status=400 body=raw
        Caller->>ParseMine: parse_mine_error(body)
        ParseMine-->>Caller: Some(MineError) (surface as toast)
    else ok
        Policy-->>PoliciesC: 200 MineResponse with ranked candidates
        PoliciesC-->>Caller: MineResponse (render candidate cards)
    end
    end
```

**Non-obvious behaviour.**

- Both `parse_batch_error` and `parse_mine_error` return
  `Option`, not `Result`. A `None` means the 400 body did not
  match the typed envelope shape — most likely a future server
  version emitting a different envelope. Callers fall through to
  rendering `WardenError::Server.body` raw, which keeps the SDK
  forward-compatible without breaking call sites.
- `EvaluateBatchError` carries `active_compile_ok` and
  `candidate_compile_ok` as separate flags. The Lab UI uses
  them to disambiguate "your candidate broke" from "the active
  bundle broke" (a genuinely catastrophic state — but possible
  if the operator was mid-edit on a separate session).
- `MineRequest::ask_brain` is opt-in. When `false` (the default),
  the policy-engine skips the Brain enrichment step and returns
  candidates with template one-liners. The SDK does not enforce
  this — `ask_brain=true` against an unconfigured Brain produces
  candidates that silently fall back to the template, which is
  the documented contract.
- The Miner's accepted candidates are NOT auto-installed. The
  operator clicks Accept in the console; the console POSTs
  `MineCandidate.rego_body` as a normal `CreatePolicyRequest`
  with `active=false`, landing it as a draft. The miner endpoint
  itself is stateless — no DB writes happen there.

---

## HttpProvider dispatch + status code routing

```mermaid
flowchart LR
    subgraph build[client construction]
        new["new(base_url)<br/>or builder(base_url)"] --> parseURL["parse_base_url<br/>force trailing slash"]
        parseURL --> ctor["AppClient struct<br/>holds Arc(HttpProvider)"]
        ctor -- "no override" --> defStatic["default_provider()<br/>StaticHttpClient wrapping<br/>reqwest::Client::builder().build()"]
        ctor -- "with_http_client(reqwest)" --> wrap["StaticHttpClient::new"]
        ctor -- "with_http_provider(custom)" --> custom["caller-supplied dyn HttpProvider<br/>e.g. ArcSwap-backed SVID refresh"]
    end

    subgraph call[per-request hot path]
        method["per-method call<br/>(call_tool, list, decide, ...)"] --> provider["http.client()"]
        provider -- "StaticHttpClient" --> arc["Arc::clone of stored Client"]
        provider -- "hot-reload provider" --> fresh["snapshot of current Client<br/>(rotates without disturbing in-flight)"]
        arc --> wire["POST/GET to Server"]
        fresh --> wire
        wire --> status{{"HTTP status?"}}
        status -- "200 / 201" --> ok["serde_json::from_str -> typed value"]
        status -- "401" --> unauth["WardenError::Unauthorized(body)"]
        status -- "400" --> bad["WardenError::BadRequest(body)"]
        status -- "403 (WardenClient only)" --> veto["parse_veto -> WardenError::Veto<br/>structured fields OR raw verbatim"]
        status -- "any other (5xx, 409, 422, 503...)" --> server["WardenError::Server (status + body)"]
        ok --> caller["typed result to Caller"]
    end
```

**Invariants.**

- Every per-service client snapshots the `reqwest::Client` via
  `HttpProvider::client()` **per request**. Implementors never
  cache the `Arc<Client>` across requests — the whole point of
  the indirection is to let credential-rotation machinery swap
  TLS identities between calls without disturbing in-flight
  requests. reqwest's connection pool retains the old identity
  for any connection that has not idled out.
- 403 dispatch is **WardenClient-only**. `parse_veto` lives in
  `client.rs` because only `POST /mcp` produces a security veto.
  Other surfaces' 403s (e.g. capability denied on
  `/agents/{id}/suspend`) fall through to `WardenError::Server`
  with status 403 — no false projection into `Veto`.
- The status dispatch table is the SDK's stability contract. New
  status codes the SDK does not understand land in `Server` so
  callers can branch on the raw status — the alternative would
  be silent breakage when a server adds a new error shape.

---

## Source pointers

- Proxy hot path: `src/client.rs::WardenClient` (`builder`,
  `call_tool`, `send_jsonrpc`, `send_raw`, `parse_veto`)
- Auth + non-exhaustive enum: `src/client.rs::Auth`
- Ledger reads: `src/ledger.rs::LedgerClient`
  (`audit_correlation`, `audit_agent`, `audit_agent_paged`,
  `audit_agent_count`, `verify`, `list_exports`,
  `replay_corpus`, `regulatory_export`)
- Agent lifecycle: `src/agents.rs::AgentsClient` (`list`, `get`,
  `find_by_name`, `create`, `suspend`, `unsuspend`,
  `decommission`, `envelope_narrow`, `envelope_widen`,
  `attestation_kinds`, `transfer_owner_team`, `set_description`)
- Policy management: `src/policies.rs::PoliciesClient`
  (`list`, `get`, `list_versions`, `get_version`, `diff`,
  `create`, `update`, `activate`, `deactivate`, `delete`,
  `rollback`, `evaluate_batch`, `mine`, `list_templates`,
  `get_template`, `install_template`, `lab_template`)
- Typed error lifters: `src/policies.rs::parse_batch_error`,
  `parse_mine_error`
- Brain explain-pattern: `src/brain.rs::BrainClient::explain_pattern`
- Simulator control: `src/sim.rs::SimClient`
- HTTP plumbing: `src/http.rs` (`HttpProvider`,
  `StaticHttpClient`, `default_provider`, `parse_base_url`,
  `decode_response`, `percent_encode`)
- Error envelope: `src/error.rs::WardenError`
