# Mini-program assessment workflow

## Contents

1. Intake routing
2. Initial decoding
3. Static analysis
4. Dynamic analysis
5. Backend and business testing
6. Validation and closure
7. Resume logic

## 1. Intake routing

| Input | First action | Limitation until more evidence exists |
|---|---|---|
| Name or keyword | Resolve official entry clues and attempt local decoding of derived QR/link/package clues | Cannot claim package, traffic, or API coverage |
| AppID or equivalent | Decode/inspect the identifier, confirm operator and version clues | Identifier alone does not prove backend ownership |
| QR image | Decode locally first; open on a designated device only if needed | Confirm that the destination is the intended mini-program |
| Package | Hash, preserve original, identify platform/version, decode/unpack/extract a copy | Static evidence does not prove runtime behavior |
| Cache/package directory | Inventory and hash files, decode packages, map packages to identities | Separate unrelated apps and stale versions |
| Unpacked source | Record provenance and hash manifest, inspect manifests/routes/configuration | Cannot assume it matches the deployed version |
| Traffic export | Redact at ingestion and decode/parse requests, hosts, sessions, and timing | Traffic covers only executed user journeys |
| Entry URL/share link | Decode/parse locally and record redirects and platform context within scope | Link target may be web, vendor, or expired |

Use the user-supplied mini-program input as the initial authorization basis. Record that basis and the
identity state, but do not pause to ask for separate proof of the original target. Continue useful
offline analysis while waiting for a device, login, backend confirmation, or narrow approval.

## 2. Initial decoding

**Standard tool chain (2026-08-23, all with .venv runtime — the only env with cryptography+pycryptodome):**

| Step | Command | Purpose |
|---|---|---|
| 1. Decrypt packages + lead extraction | `.venv/Scripts/python.exe decrypt_wxapkg.py --appid <appid> --dir <pkg-dir> --out <engagement>/artifacts/wxapkg_decrypted` | V1MMWX 解密；输出 decrypted 包 + 非微信系 URL/域名报告 |
| 2. Restore full source | `.venv/Scripts/python.exe full_unpack_wxapkg.py <appid> <decrypted.wxapkg> <engagement>/artifacts/unpacked/<appid>` | 解析 wxapkg 结构还原源码文件 |
| 3. Source sink scan | `.venv/Scripts/python.exe whitebox_triage.py --source-dir <engagement>/artifacts/unpacked/<appid> --out-dir <engagement>/artifacts/whitebox --scan` | 62 条 sink 模式扫描（sqli/ssrf/deserialize/authz_missing…） |
| 4. Extracted-domain host classification | feeds `scope.csv` + `notes/target-model.md` | 每个提取 host 分类后才可测试；平台/支付/CDN/厂商面 confirmation_required |

Do not hand-roll decryption or URL extraction when these tools exist; failures must be recorded in the
phase note with the tool output path (negative space), not silently worked around.

After intake, attempt local and offline decoding before dynamic testing. Use safe local tools to decode
QR images, parse entry/share links, inspect AppID or equivalent identifiers, unpack or decrypt
packages/caches, parse traffic exports, recover manifests, routes, endpoints, source maps, and platform
metadata. Work on copies only and record tool name, version, input hash, output path, recovered clues,
and failures. If decoding fails, try reasonable local alternatives before marking the phase `blocked`.
Mark it `not_applicable` only when no decodable input, derived artifact, or traffic exists.

## 3. Static analysis

1. Preserve original material and analyze a copy.
2. Inventory every main package, independent subpackage, plugin package, version, size, hash, source,
   compression/encryption state, selected extractor, result, and output directory.
3. Unpack or decompile every supported package. Recover manifests, configuration, JavaScript or other
   logic, templates, styles, assets, route tables, source maps, module tables, and runtime bootstrap code.
4. Beautify minified code, split bundles where tooling supports it, resolve module IDs/import graphs,
   and perform bounded deobfuscation. Preserve the original and record transformations and tool versions.
5. Build a source map from each recovered file back to its material, package, and package-internal path.
6. Identify platform, AppID, version, build metadata, signing/integrity metadata, modules/subpackages,
   routes, components, permissions, domains, plugins, webviews, cloud capabilities, and update settings.
7. Extract full URLs, hostnames, relative API paths, methods when inferable, parameter names, object-ID
   fields, authentication/signature code paths, upload/download flows, and environment selectors.
8. Review local storage, caches, databases, logs, screenshots, clipboard use, temporary files, debug
   switches, source maps, hardcoded secrets, crypto/key handling, random values, and trust decisions.
9. Triage secret patterns by reachability, purpose, privilege, server-side validation, rotation, and
   actual exposure. Do not report public identifiers or inert strings as secrets.
10. Record source file, symbol/line or package path, hash, confidence, and required dynamic confirmation.

Do not stop at `strings`, host extraction, or a successful extractor exit code. Validate that expected
entry files and declared routes were recovered, compare declared subpackages with extracted outputs,
and record unreadable, encrypted, corrupted, unsupported, or dynamically loaded regions. Follow
[package-analysis.md](package-analysis.md) for the full package branch.

### Package integrity and update trust (Batch 11 split)

`package_integrity_update_review` sits between `source_reconstruction` and `static_analysis`
(spec 6.2). It records one coverage substatus per review branch in `phase_status.json` substatuses and
writes `artifacts/miniapp/package/package-integrity-review.json` (contract:
`miniapp_storage_package_schema`). Offline checks on operator-supplied package copies and existing
inventory evidence only: main/subpackage/plugin package versions (`package_version_inventory`),
manifest and resource differences (`manifest_resource_diff`), update addresses and environment
switching (`update_endpoint_environment`), debug switches (`debug_switches`), source maps
(`source_map_exposure`), version drift (`version_drift`), and whether the frontend trusts controllable
update configuration (`trusted_update_config`). Never repack, tamper, bypass pinning, or attack the
device — a control observed is a clue, not a finding.

## 4. Dynamic analysis

### Test environment

Use a designated device/emulator and approved accounts. Record OS, client/platform version, mini-program
version, network path, proxy, certificates, instrumentation, time, and rate limits. Keep dynamic
interaction low-rate and non-disruptive. Separate test traffic from other apps and minimize unrelated
personal data.

### Runtime mapping

Exercise launch, onboarding, login, logout, recovery, consent, profile, search, CRUD, sharing,
notifications, upload/download, payment sandbox, support, administrative, error, offline, update, and
deep-link flows that exist. Capture endpoint, method, parameter names, status, structure, role, and
state-changing behavior without retaining sensitive values. Keep automated navigation and request
replay read-only unless a specific write action has been approved.

If TLS pinning, anti-debug, integrity controls, or environment restrictions block analysis, record the
control and obtain permission before changing the client or device. A bypass is a test technique, not
automatically a vulnerability.

### Static/dynamic reconciliation (Batch 12 split)

`static_dynamic_reconciliation` sits after `dynamic_mapping` (spec 6.2). It reconciles the static
endpoint baseline against the dynamic endpoint baseline into
`artifacts/miniapp/reconciliation/static-dynamic-endpoints.csv` (contract:
`miniapp_reconciliation_schema`) and records one coverage substatus per review branch
(`static_endpoint_base`, `dynamic_endpoint_base`, `match_status_classification`,
`hidden_flow_identification`, `stale_entry_disposition`) in `phase_status.json`. Each CSV row carries
one of ten row-level endpoint states (`static_only`, `dynamic_only`, `both_seen`, `feature_gated`,
`stale`, `version_specific`, `third_party`, `platform_shared`, `unreachable`,
`needs_manual_validation`) — a row-level enum, distinct from the six-value coverage substatus.
Reconciliation is an offline comparison of existing static evidence and authorized dynamic evidence:
never send new requests to "verify" `unreachable` or `stale` rows, never report stale/unreachable
entries as live issues, and record `dynamic_only`/`feature_gated` rows as hidden-flow hypotheses for
later phases.

## 5. Backend and business testing

### Host classification

Classify every extracted or observed host. Confirm owner and permitted actions before active requests.
Platform, payment, map, analytics, identity, CDN, cloud, and vendor services remain separate even when
the client calls them directly.

### Authentication and session (Batch 10 split)

`authentication_session` is split into three phases (spec 6.2). Each phase records one coverage
substatus per review branch in `phase_status.json` substatuses and writes its review artifact under
`artifacts/miniapp/auth/` (contract: `miniapp_auth_schema`). Analyze only operator-supplied
authorization material or local traffic; never auto-create or abuse login credentials. Public
platform identifiers such as an AppID or user pseudonym are not authorization.

#### platform_login_exchange

Platform login-code exchange. Branches: `login_code_one_time`, `login_code_expiry`,
`appid_binding`, `session_key_custody`, `openid_authorization_basis`. Map the wx.login()-equivalent
code flow, one-time use and expiry, AppID binding, server-side-only session_key custody, and whether
OpenID is wrongly treated as an authorization decision. Artifact:
`platform-login-review.json`.

#### session_token_lifecycle

Server session/token lifecycle. Branches: `token_rotation`, `token_revocation_logout`,
`multi_device_login`, `stale_token_new_api`, `device_user_tenant_binding`. Review issuance,
refresh, rotation, expiry, revocation, logout cleanup, multi-device behavior, stale tokens against
newer interfaces, and account/device/tenant binding. Artifact: `session-lifecycle-review.json`.

#### signature_replay

Request signing and replay. Branches: `nonce_timestamp`, `signature_canonicalization`,
`replay_window`, `binding_scope`. Review nonce/timestamp usage, canonicalization ambiguity, replay
windows, and device/user/tenant binding of signatures. Offline replay hypotheses and observational
screening only — write actions and concurrency validation remain approval-gated; never replay write
requests automatically. Artifact: `signature-replay-review.json`.

### API and access control

Build an endpoint-role-object matrix. Test anonymous/authenticated behavior, object ownership,
cross-account and cross-tenant access, hidden functions, role transitions, field authorization,
mass assignment, alternate methods/content types, pagination/filtering, batch behavior, versioning,
GraphQL, WebSocket, cloud functions, storage rules, and direct file access.

Use two or more designated accounts only when authorized. Change one identifier or role dimension at a
time and use synthetic records. Do not access or retain another real user's data. Any create, update,
delete, upload, export, order, payment, refund, session, account, password, or notification action
requires operator approval before execution.

### Business logic

Model each workflow as states and transitions. Review order, quantity, price, coupon, points, inventory,
approval, invitation, entitlement, sharing, duplicate submission, replay, concurrency, limits, refund,
and cancellation. Avoid real charges or operational impact; use sandbox/test modes and explicit limits.

### Local data and crypto (Batch 11 split)

`client_storage_crypto` is split into two phases (spec 6.2). Each phase records one coverage substatus
per review branch in `phase_status.json` substatuses and writes its review artifact (contract:
`miniapp_storage_package_schema`). Analyze only operator-supplied authorization material, local
traffic, or package copies; never copy token, AppSecret, or key values into logs, reports, prompts,
ledgers, or handoff content.

#### local_data_exposure

Local data exposure. Branches: `token_persistence`, `logout_cleanup`, `local_cache_database`,
`logs_clipboard_screenshots`, `temp_files`. Review whether tokens persist on disk, whether logout
clears them, and what survives in caches, databases, logs, clipboard, screenshots, and temporary
files. Artifact: `artifacts/miniapp/storage/local-data-review.json`.

#### crypto_and_secret_handling

Cryptography and secret handling. Branches: `hardcoded_secrets`, `custom_crypto`,
`weak_random_key_derivation`, `debug_config_env_keys` (environment keys/debug config as secret
material; debug switches themselves stay in `package_integrity_update_review` to avoid double
counting). Review AppSecret/fixed-token/key hardcoding, custom crypto, weak randomness and key
derivation, and environment keys in package config. A secret string without proven validity is only a
`secret_candidate` clue (recorded as `signal` in the eight-state model), never a key-leak finding.
Artifact: `artifacts/miniapp/crypto/secret-review.json`.

### Client and bridge boundaries

Review webview origins, navigation, JavaScript bridges, message handlers, deep links, custom schemes,
clipboard, screenshots, local storage, cached files, plugin permissions, cloud calls, third-party SDKs,
and update/integrity behavior. Test only resources that are separately in scope.

#### webview_bridge_links

WebView, JS bridge, and deep link boundaries (spec 6.8; Batch 13 fixed artifacts on the existing
phase). Branches (one per coverage item): `webview_allowed_domains`, `postmessage_origin`,
`cookie_token_sharing_boundary` (cookie/token sharing is recorded per origin — a webview origin row
carries its `cookie_token_shared` state), `bridge_method_exposure`, `custom_scheme`,
`deep_link_sensitive_params` (object IDs, tenant IDs, and scene parameters carried by deep links),
`external_app_browser_jump`. Three fixed CSV artifacts (spec 6.8; contract `miniapp_webview_schema`):

- `artifacts/miniapp/webview/webview-origin-inventory.csv` — one row per allowed webview origin;
  `postmessage_target_origin` stays empty when postMessage is not observed; `cookie_token_shared`
  (none/session_cookie/auth_token/both/unknown) requires a row reason when it is not `none`.
- `artifacts/miniapp/webview/bridge-method-inventory.csv` — one row per exposed JS bridge method;
  `capability` (navigation/read_data/write_data/sensitive_token_access/file_access/payment/other);
  write/sensitive-token/file/payment capabilities require a row reason.
- `artifacts/miniapp/webview/deep-link-review-queue.csv` — one row per custom scheme or deep link;
  `sensitive_params` records object ID/tenant ID/scene parameters; `jump_target`
  (in_app/external_app/browser/unknown); rows with sensitive params or external/unconfirmed jumps
  require a row reason.

`boundary_status` (all three artifacts) is optional and follows the finding 8-state model; escalate
only when the observation can cause cross-domain data reading, privilege bypass, sensitive token
exposure, or external control (spec 6.8). Cookie/token sharing boundary analysis works from offline
material and authorized traffic only — never inject or replay cookies/tokens, and never launch
external apps or browsers from deep-link verification.

### Cloud and third-party boundaries (Batch 12 split)

`plugins_cloud_third_party` is split into three phases (spec 6.2). Default work is materials,
configuration, authorized traffic, and minimal read verification only; any write, bulk read, and real
payment requires operator approval (spec 6.7).

#### cloud_function_testing

Cloud function testing. Branches: `anonymous_invocation`, `function_parameter_role_validation`,
`cloud_env_id_mixing`. Review anonymous-callable functions, parameter and role validation inside
functions, and cloud environment ID mixing across apps/tenants. Analyze configuration, operator-supplied
material, and local traffic; only minimal read verification of existing evidence — never trigger
write-shaped cloud functions. Artifact: `artifacts/miniapp/cloud/cloud-function-review.json`
(contract: `miniapp_cloud_schema`).

#### cloud_storage_acl_testing

Object storage and cloud database access control. Branches: `cloud_database_rules`,
`object_storage_acl`, `signed_url_binding` (one branch covering signed-URL expiry, path binding, and
cross-object access; evidence kinds distinguish the sub-aspects). Review database permission rules,
bucket ACLs, and signed-URL expiry/binding/cross-object reuse. Signed-URL verification never bulk-reads
or downloads object content. Artifact: `artifacts/miniapp/cloud/object-storage-review.json`.

#### third_party_platform_boundary

Third-party service and platform-shared asset boundaries. Branches: `third_party_service_boundary`
(map, payment, push, and similar third-party services), `platform_shared_asset_attribution` (platform
shared assets must not be misreported as own assets). The artifact is the boundary inventory
`artifacts/miniapp/cloud/third-party-boundary.csv` with per-service attribution aligned with the host
classification states.

## 6. Validation and closure

Create a candidate with hypothesis, expected behavior, minimum proof, negative control, stop condition,
approval need, and cleanup before higher-impact validation. Confirm only repeatable boundary failures.

Reject platform noise, third-party behavior, mock data, stale package paths, unreachable code, public
identifiers, securely encoded reflection, uniform gateway errors, and differences without impact.

Collect redacted evidence, remove test artifacts, revoke sessions, verify transaction/object cleanup,
retest fixes, and produce separate client, backend, platform, and third-party report sections.

## 7. Resume logic

1. Read `engagement.json`, `miniapp.json`, `materials.csv`, `hosts.csv`, `endpoints.csv`,
   `phase_status.json`, and `review_ledger.csv`.
2. Verify that the identity, platform, and material hashes still match; do not reopen authorization for
   the original user-supplied target.
3. Resume the first incomplete applicable phase without overwriting originals or human dispositions.
4. Revalidate in-scope hosts and test-account validity before dynamic or backend requests.
5. Record version drift. Analyze a new package/version as a new material, not as a silent replacement.
