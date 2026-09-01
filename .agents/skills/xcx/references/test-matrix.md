# Mini-program test matrix

Use this as a coverage index. Apply only to authorized accounts, devices, versions, and owned backends.

| Area | Coverage questions |
|---|---|
| Identity and provenance | Are platform, AppID, name, operator, version, source, hash, and deployment match established? |
| Package inventory | Are the main package, all subpackages, plugins, versions, hashes, extraction tools, failures, and output directories recorded? |
| Unpack and decompile | Are supported packages actually unpacked/decompiled, expected entry files recovered, and declared subpackages reconciled? |
| Source reconstruction | Are bundles beautified, modules/imports mapped, source maps recovered, transformations recorded, and unreadable regions identified? |
| Package and integrity | Are manifests, signing/integrity, update paths, debug flags, source maps, and repack assumptions reviewed? |
| Routes and components | Are pages, hidden routes, components, permissions, feature flags, environments, and administrative paths inventoried? |
| Embedded configuration | Are hosts, API bases, keys, identifiers, environment switches, cloud configuration, and secret patterns classified by actual privilege? |
| Local data | Are storage, cache, database, files, logs, clipboard, screenshots, temporary data, backup, and logout cleanup reviewed? |
| Cryptography | Are key origin/storage, algorithms, randomness, nonces, timestamps, signatures, replay, canonicalization, and server verification reviewed? |
| Transport | Are TLS validation, pinning, proxy behavior, cleartext, redirects, mixed content, certificate errors, and sensitive caching reviewed? |
| Platform login | Are login codes one-time/short-lived, AppID binding, server exchange, account binding, recovery, logout, token rotation, and revocation reviewed? |
| Session and identity | Are tokens, cookies, platform identifiers, device/tenant binding, fixation, expiry, refresh, concurrent sessions, and stale sessions reviewed? |
| Endpoint inventory | Are methods, paths, parameters, object IDs, auth, roles, state changes, versions, GraphQL, WebSocket, files, and cloud calls mapped? |
| Object authorization | Are cross-account, cross-tenant, owner, shared-object, export, file, message, order, and profile boundaries tested with designated accounts? |
| Function authorization | Are user/admin/support/operator functions, hidden routes, alternate methods, role transitions, and field-level permissions tested? |
| Input and parsing | Are server-side validation, injection classes, canonicalization, template rendering, headers, parsers, and serialization surfaces reviewed? |
| Upload and download | Are extension/type/content, filename/path, overwrite, storage, retrieval authorization, preview, processing, quotas, and cleanup tested? |
| Server-side requests | Are URL fetches, callbacks, images, imports, redirects, DNS behavior, protocol restrictions, and cloud metadata controls reviewed? |
| Business workflow | Are state order, replay, duplicate requests, concurrency, limits, approvals, invitations, prices, quantities, inventory, points, and entitlements tested? |
| Payment and refund | Are sandbox mode, amount source, order binding, callback verification, idempotency, status transitions, refund authorization, and reconciliation reviewed? |
| Webview and bridge | Are allowed origins, postMessage origin control, JS bridge exposure and capability, custom schemes, deep-link object/tenant/scene parameters, external app/browser jumps, and cookie/token sharing boundaries reviewed and inventoried per branch (origin/bridge-method inventories and deep-link review queue)? |
| Plugins and SDKs | Are permissions, data sharing, update trust, vendor endpoints, analytics, maps, customer service, and platform plugins classified and scoped? |
| Cloud capabilities | Are cloud functions, databases, storage rules, signed URLs, environment IDs, IAM, event triggers, and administrative consoles reviewed? |
| Privacy | Are consent, unnecessary fields, identifiers, contacts/location/media access, analytics, logs, exports, deletion, and retention reviewed without retaining data? |
| Resilience | Are rate limits, quotas, expensive operations, job creation, retries, offline synchronization, and duplicate handling assessed within non-disruptive bounds? |
| Detection and cleanup | Are security events logged without secrets, and are test users, objects, files, orders, tokens, webhooks, and device changes removed? |

## Required dimensions

Repeat applicable rows across anonymous, new user, established user, privileged role, disabled account,
expired session, different tenant, different device, old client version, and interrupted workflow. Use
only authorized combinations and record unavailable dimensions as blocked or not applicable.

Test static, dynamic, backend, and business dimensions separately. Static evidence can establish
presence and reachability clues; it usually cannot establish server-side authorization or impact.

## Authentication phase substatus branches (Batch 10, contract: miniapp_auth_schema)

`authentication_session` is split into three phases; each records one coverage substatus
(tested/not_applicable/blocked/approval_required/needs_manual_validation/inconclusive) per branch in
`phase_status.json` and writes its review artifact under `artifacts/miniapp/auth/`. A phase is only
complete with proven tested/not_applicable statuses per branch.

| Phase | Substatus branches |
|---|---|
| platform_login_exchange | login_code_one_time, login_code_expiry, appid_binding, session_key_custody, openid_authorization_basis |
| session_token_lifecycle | token_rotation, token_revocation_logout, multi_device_login, stale_token_new_api, device_user_tenant_binding |
| signature_replay | nonce_timestamp, signature_canonicalization, replay_window, binding_scope |

## Storage/package phase substatus branches (Batch 11, contract: miniapp_storage_package_schema)

`client_storage_crypto` is split into two phases and `package_integrity_update_review` is inserted
between `source_reconstruction` and `static_analysis`; each records one coverage substatus per branch
in `phase_status.json` and writes its review artifact. A phase is only complete with proven
tested/not_applicable statuses per branch. Package integrity review works on operator-supplied
package copies only (no repacking, tampering, pinning bypass, or device attacks); a secret string
without proven validity is only a `secret_candidate` clue, never a key-leak finding.

| Phase | Substatus branches |
|---|---|
| package_integrity_update_review | package_version_inventory, manifest_resource_diff, update_endpoint_environment, debug_switches, source_map_exposure, version_drift, trusted_update_config |
| local_data_exposure | token_persistence, logout_cleanup, local_cache_database, logs_clipboard_screenshots, temp_files |
| crypto_and_secret_handling | hardcoded_secrets, custom_crypto, weak_random_key_derivation, debug_config_env_keys |

## Reconciliation and cloud phase substatus branches (Batch 12, contracts: miniapp_reconciliation_schema + miniapp_cloud_schema)

`static_dynamic_reconciliation` is inserted after `dynamic_mapping` and `plugins_cloud_third_party` is
split into three phases (spec 6.2); each records one coverage substatus per branch in
`phase_status.json`. The reconciliation phase writes
`artifacts/miniapp/reconciliation/static-dynamic-endpoints.csv` whose rows carry one of ten row-level
endpoint states (static_only/dynamic_only/both_seen/feature_gated/stale/version_specific/third_party/
platform_shared/unreachable/needs_manual_validation) — distinct from the six-value coverage substatus.
Reconciliation is offline comparison only: no new requests to "verify" unreachable or stale rows, and
stale/unreachable entries are never live findings. Cloud reviews work on materials, configuration,
authorized traffic, and minimal read verification only; any write, bulk read, and real payment is
approval-gated. A phase is only complete with proven tested/not_applicable statuses per branch (CSV
phases: tested requires at least one recorded row; not_applicable requires a phase reason).

| Phase | Substatus branches |
|---|---|
| static_dynamic_reconciliation | static_endpoint_base, dynamic_endpoint_base, match_status_classification, hidden_flow_identification, stale_entry_disposition |
| cloud_function_testing | anonymous_invocation, function_parameter_role_validation, cloud_env_id_mixing |
| cloud_storage_acl_testing | cloud_database_rules, object_storage_acl, signed_url_binding |
| third_party_platform_boundary | third_party_service_boundary, platform_shared_asset_attribution |
