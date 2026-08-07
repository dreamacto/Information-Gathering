# Package unpacking, decompilation, and source reconstruction

## Purpose

Use this branch whenever the operator supplies a package, cache directory, extracted bundle, source
archive, or device-acquired package. The goal is not merely to list strings. Produce a traceable,
readable source tree and an explicit account of what could and could not be recovered.

Before deciding that a package or cache is unavailable, attempt local decoding/unpacking on a copy.
For common mini-program formats this is usually productive, so try reasonable maintained local tools
and record partial recovery rather than stopping at raw metadata.

## 1. Preserve and inventory

1. Hash and preserve every original file before transformation.
2. Identify platform, container type, AppID/identifier, version, main package, subpackages, plugin
   packages, compression/encryption state, size, provenance, and acquisition time.
3. Compare package names and hashes to avoid analyzing duplicates or mixing unrelated applications.
4. Analyze copies in a separate working directory. Never overwrite the original package.
5. Keep extraction, beautification, source-map application, and indexing local/offline. Do not contact
   target services during decoding.

Record every package in `artifacts/package-inventory.csv`, including failures and unsupported formats.

## 2. Select and validate extraction tools

Inventory locally available maintained extractors/decompilers for the detected platform. Read help,
version, supported container variants, output behavior, and known limitations before use. Prefer tools
that preserve paths and emit structured manifests. Do not silently download or run unknown binaries.

For WeChat material, expect `.wxapkg` main/subpackages and recover `app-config`, `app-service`, page
configuration, WXML, WXSS, JavaScript, assets, and subpackage metadata as available. For Alipay,
Douyin, Baidu, Quick App, or another platform, identify the equivalent manifest, template, style,
logic, route, component, and bundle structures rather than applying WeChat filenames blindly.

An extractor exit code is not proof of success. Verify expected entry files, non-empty recovered logic,
declared routes, declared subpackages, and file counts.

## 3. Recover all packages and source layers

1. Extract the main package and each declared or discovered subpackage independently.
2. Recover manifests, route tables, components, templates, styles, JavaScript/other logic, assets,
   worker code, plugins, webview resources, source maps, and bootstrap/runtime metadata.
3. Detect nested packages, split packages, dynamically loaded bundles, duplicate modules, and stale
   cached versions.
4. Keep package-internal paths and map every recovered file to its source package and hash in
   `artifacts/source-map.csv`.
5. Record encrypted, corrupted, unsupported, empty, dynamically generated, or missing regions.

## 4. Make recovered code analyzable

Beautify minified code without altering the original. Where supported, split module bundles, recover
module identifiers, resolve import/require graphs, apply source maps, normalize generated filenames,
and annotate runtime bootstrap or framework wrappers. Record each transformation and tool version.

Perform bounded deobfuscation to expose control flow, strings, endpoints, signing code, and storage
operations. Do not claim complete source recovery when names or control flow remain ambiguous. Use
dynamic traces to resolve ambiguous runtime values rather than inventing them.

## 5. Build security-oriented indexes

From the recovered tree, index:

- routes, pages, components, hidden or feature-gated screens, and administrative paths
- full URLs, hosts, relative API paths, methods, parameter names, object identifiers, and versions
- login-code exchange, token/session lifecycle, signatures, nonces, timestamps, replay checks, and crypto
- local storage, cache, database, files, logs, clipboard, screenshots, and temporary data
- upload, download, import, export, payment, order, approval, sharing, and cloud operations
- webviews, JavaScript bridges, deep links, custom schemes, plugins, SDKs, and cloud capabilities
- environment switches, debug/test hosts, source maps, hardcoded-secret patterns, and trust decisions

Preserve source location and confidence for every extracted item. Redact actual credentials, tokens,
personal data, and business values.

## 6. Reconcile static and dynamic behavior

Compare recovered routes and endpoints with runtime navigation and proxy traffic. Mark static-only,
dynamic-only, unreachable, feature-gated, version-specific, third-party, and platform entries. Use this
comparison to find hidden flows and to avoid reporting dead code as an active issue.

## 7. Completion criteria

The package branch is complete only when:

- all supplied and discovered main/subpackages have a recorded result
- expected entry files and declared routes are reconciled
- a recovered-source map exists, even if some entries are failures
- transformations and tool versions are recorded
- unreadable, unsupported, encrypted, missing, and dynamic regions are explicit
- security indexes have source references
- static results have been queued for dynamic or backend confirmation where needed

If recovery fails, keep the phase `blocked` with the exact package, tool, error, attempted alternatives,
and minimum missing input. Do not mark it `not_applicable` merely because extraction was difficult.
