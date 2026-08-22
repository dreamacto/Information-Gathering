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

## 5. Backend and business testing

### Host classification

Classify every extracted or observed host. Confirm owner and permitted actions before active requests.
Platform, payment, map, analytics, identity, CDN, cloud, and vendor services remain separate even when
the client calls them directly.

### Authentication and session

Map the platform login-code exchange, server session/token issuance, binding to account/device/tenant,
refresh, rotation, expiry, revocation, logout, recovery, MFA, replay, nonce/timestamp, signature, and
error behavior. Public platform identifiers such as an AppID or user pseudonym are not authorization.

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

### Client and bridge boundaries

Review webview origins, navigation, JavaScript bridges, message handlers, deep links, custom schemes,
clipboard, screenshots, local storage, cached files, plugin permissions, cloud calls, third-party SDKs,
and update/integrity behavior. Test only resources that are separately in scope.

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
