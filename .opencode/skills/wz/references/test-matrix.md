# Website test matrix

Use this matrix as a coverage index, not a payload list. Mark every applicable row complete,
not applicable with reason, blocked, or approval required.

| Area | Coverage questions |
|---|---|
| Scope and ownership | Are aliases, redirects, subdomains, APIs, vendors, CDNs, and cloud assets classified before active use? |
| DNS and TLS | Are wildcard DNS, dangling records, certificate names, protocol versions, ciphers, hostname validation, HSTS, and renewal issues reviewed? |
| HTTP behavior | Are methods, redirects, host handling, proxy headers, cache keys, compression, content types, error pages, and security headers reviewed? |
| Exposure | Are backups, source maps, debug pages, admin consoles, metrics, health endpoints, documentation, directory listings, and metadata checked? |
| Mapping | Are routes, parameters, forms, JavaScript endpoints, APIs, GraphQL, WebSockets, webhooks, uploads, downloads, and background jobs inventoried? |
| Authentication | Are registration, login, logout, lockout, MFA, recovery, remember-me, password policy, federation, and account enumeration tested? |
| Session | Are cookie flags, token storage, rotation, fixation, expiry, revocation, concurrent sessions, device binding, replay, JWT validation, and refresh flows tested? |
| Authorization | Are object-level, function-level, role, tenant, field-level, mass-assignment, hidden function, direct URL, and workflow boundaries tested? |
| CSRF and CORS | Are state changes protected, origins validated, credentials constrained, preflight behavior correct, and sensitive responses non-cacheable? |
| Input and injection | Are server/client validation, SQL/NoSQL/LDAP/XPath/OS/template/header injection, request smuggling signals, and canonicalization reviewed? |
| Server-side fetch and parsers | Are URL fetches, redirects, DNS rebinding constraints, XML/entity behavior, archive extraction, image/document parsers, and deserialization surfaces reviewed? |
| File handling | Are extension, MIME, magic bytes, filename/path, overwrite, storage location, retrieval authorization, malware controls, quotas, and cleanup tested? |
| Client side | Are output contexts, DOM sinks, postMessage, storage, service workers, source maps, third-party scripts, clickjacking, and open redirects reviewed? |
| API | Are schemas, undocumented versions, methods, content types, object/field authorization, pagination, filtering, rate limits, errors, and batch behavior tested? |
| GraphQL | Are introspection, field authorization, aliases, batching, depth/complexity, error leakage, subscriptions, and object references reviewed? |
| WebSocket and realtime | Are handshake auth, origin, channel/topic authorization, message validation, replay, rate, and disconnect/session behavior tested? |
| Business logic | Are state transitions, order of operations, replay, duplicate submission, concurrency, limits, approvals, prices, credits, coupons, inventory, and entitlements tested? |
| Multi-tenant | Are tenant selection, invite/join, switching, exports, search, shared resources, administration, and support functions isolated? |
| Privacy and data | Are unnecessary fields, identifiers, search leakage, exports, logs, analytics, caches, deletion, retention, and error disclosures reviewed without retaining data? |
| Infrastructure | Are origin exposure, reverse-proxy trust, default services, cloud storage, secrets, container/orchestrator metadata, WAF boundaries, and management planes reviewed? |
| Availability controls | Are rate limits, quotas, expensive queries, upload sizes, job creation, and resource exhaustion assessed only within approved non-disruptive bounds? |
| Supply chain | Are dependencies, packages, build artifacts, CI/CD exposure, third-party scripts, webhooks, plugins, and shared providers classified and scoped? |
| Logging and detection | Are security events recorded appropriately without secret leakage, and are alerting/incident contacts tested only when agreed? |

## Role and state dimensions

Repeat applicable tests across anonymous, normal user, privileged user, tenant administrator, platform
administrator, disabled account, expired session, invited-but-not-active account, and cross-tenant pairs.
Use only roles and accounts authorized for the engagement.

Repeat applicable tests across create, read, update, delete, export, approve, cancel, refund, share,
invite, recover, and administrative transitions. For unsafe writes, document the untested branch or use
approved disposable data with an explicit cleanup plan.

## Application mapping subphases (applicability first)

The `application_mapping` phase is audited through five subphases. Each writes its artifact under
`artifacts/application-map/`, and every artifact row carries at least the seven contract fields
(`applicable`, `status`, `source`, `asset`, `endpoint_or_surface`, `reason`, `evidence_ref`):

| Subphase | Artifact | Applicability questions |
|---|---|---|
| `graphql_mapping` | `graphql-manifest.json` | Are GraphQL endpoints or operations discoverable (introspection, schema files, JS references, captured traffic)? |
| `websocket_mapping` | `websocket-inventory.csv` | Are WebSocket/SSE/realtime channels discoverable from JS, traffic, or docs? |
| `file_surface_mapping` | `file-surface-inventory.csv` | Are upload, download, preview, import, and export file surfaces discoverable? |
| `auth_surface_mapping` | `auth-surface-inventory.csv` | Are login, logout, registration, recovery, MFA, and token-refresh surfaces discoverable? |
| `webhook_mapping` | `webhook-inventory.csv` | Are outbound webhook configurations or inbound callback endpoints discoverable? |

Answer the five applicability questions (surface exists? known inputs? authorized material? low-risk
check allowed? successful response available?) before claiming `applicable`; only applicable surfaces
enter testing. Record `not_applicable` with a reason instead of skipping silently. A `tested` row needs
an `evidence_ref` resolving inside the workspace. A subphase that cannot proceed is `blocked`,
`approval_required`, `needs_manual_validation`, or `inconclusive` in the phase's `substatuses` map —
never dropped; the mapping phase is complete only when all five substatuses are recorded and provable.

## Result discipline

- `tested_no_issue`: executed with an adequate negative control and no boundary failure observed.
- `candidate`: signal exists but impact is not established.
- `confirmed`: repeatable boundary failure and impact are evidenced.
- `not_applicable`: feature or surface does not exist; record evidence.
- `blocked`: required dependency is unavailable; record exactly what is missing.
- `approval_required`: the next validating action exceeds current permission.
