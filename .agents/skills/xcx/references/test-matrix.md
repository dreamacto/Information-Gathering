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
| Webview and bridge | Are allowed origins, navigation, JS bridge exposure, message validation, postMessage, cookies, deep links, schemes, and external apps reviewed? |
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
