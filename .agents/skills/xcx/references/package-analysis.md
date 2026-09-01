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

### 2.1 本项目已有工具（优先使用，禁止重复造轮子）

项目根目录下已有成熟的批量解密+API提取工具，**必须优先使用，不要每次临时写脚本**：

**主工具：** `tools/miniapp_extract/extract_encrypted_wxapkg_domains.py`

```bash
# 批量解码全部缓存小程序
python tools/miniapp_extract/extract_encrypted_wxapkg_domains.py \
  --root "C:/Users/ASUS/AppData/Roaming/Tencent/xwechat/radium/users/64a7b1dae792358764749c820add44b9/applet/packages"

# 解码单个小程序（用 AppID 路径）
python tools/miniapp_extract/extract_encrypted_wxapkg_domains.py \
  --root "C:/Users/ASUS/AppData/Roaming/Tencent/xwechat/radium/users/64a7b1dae792358764749c820add44b9/applet/packages/<appid>"
```

**解密算法：**
- 文件头 `V1MMWX`（6字节）
- AES-CBC 解密前1024字节：key = `PBKDF2(appid, "saltiest", 1000, dklen=32)`，IV = `"the iv: 16 bytes"`
- 剩余字节用4个XOR key（`appid[-2]`, `appid[-1]`, `0x66`, `0x00`）尝试，选API关键词命中率最高的
- 解密后尝试结构化解析（`0xBE...0xED` 头），失败则用正则回退（strings_only模式）

**输出文件（CSV）：**
| 文件 | 内容 |
|------|------|
| `wxapkg_urls.csv` | 完整URL、host、分类 |
| `wxapkg_api_paths.csv` | 疑似API路径 |
| `wxapkg_domains_all.csv` | 所有域名 |
| `wxapkg_package_parse_summary.csv` | 每个包的解析状态 |

**已知局限：**
- `strings_only` 模式的正则只抓 `https?://` 绝对URL，`config.baseUrl` 变量存储的相对路径抓不到
- 需要额外关键词深搜（`baseUrl`, `config`, `request`, 特定域名）来补充API端点
- `urlparse` 遇到畸形URL已加 try/except 保护，不会再崩溃

**解密脚本（20260823 起为可复用 CLI，算法经合成往返测试验证）：** `decrypt_wxapkg.py`（项目根目录，须 .venv 运行时）

```
.venv/Scripts/python.exe decrypt_wxapkg.py --appid <appid> --dir <包目录> --out <输出目录>
```

输出 `<名>.decrypted.wxapkg`（可继续喂 full_unpack）+ `decrypt_report.md/.jsonl`（非微信系 URL/域名线索）。无 V1MMWX 头的包自动按已解密透传。

### 2.2 工具选择流程

1. **首选** `extract_encrypted_wxapkg_domains.py` — 支持批量/单个，输出结构化CSV
2. 如果 CSV 中真实业务域名/API太少 → 用 Python 内联脚本深搜 `baseUrl`、`config` 等关键词
3. **禁止**每次临时写 `nncc_analysis.py`、`liugong_deep_search.py` 这种一次性脚本

### 2.3 其他工具

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

Preserve source location, evidence path, hash, and confidence for every extracted item. Redact actual
credentials, tokens, personal data, and business values.

## 6. Package integrity and update trust review (Batch 11)

The `package_integrity_update_review` phase (between `source_reconstruction` and `static_analysis`,
spec 6.2) turns the integrity-relevant clues collected above into an auditable review with one
coverage substatus per branch and the artifact
`artifacts/miniapp/package/package-integrity-review.json` (contract:
`miniapp_storage_package_schema`). Offline checks on operator-supplied package copies and existing
inventory evidence only:

1. `package_version_inventory` — main, subpackage, and plugin package versions versus declared
   configuration and inventory records.
2. `manifest_resource_diff` — manifest and resource differences between packages, versions, and
   declared versus recovered files.
3. `update_endpoint_environment` — update/download addresses and environment switching
   (test/staging/pre endpoints reachable from the client).
4. `debug_switches` — debug flags and switches left in the shipped package.
5. `source_map_exposure` — source maps shipped or recoverable from the package.
6. `version_drift` — stale cached versions and drift between materials and declared versions.
7. `trusted_update_config` — whether the frontend trusts controllable update configuration
   (client-applied config that could redirect code or data flows).

Red line: never repack, tamper with, or resign packages, never bypass TLS/certificate pinning, and
never attack the device or runtime protection. An observed control or leftover debug artifact is a
clue (`signal`), not automatically a vulnerability; candidates still go through the finding gates.

## 7. Reconcile static and dynamic behavior

The `static_dynamic_reconciliation` phase (after `dynamic_mapping`, spec 6.2/6.4) turns the comparison
into an auditable artifact: `artifacts/miniapp/reconciliation/static-dynamic-endpoints.csv` (contract:
`miniapp_reconciliation_schema`), one row per endpoint with a ten-value row-level status
(static_only, dynamic_only, both_seen, feature_gated, stale, version_specific, third_party,
platform_shared, unreachable, needs_manual_validation). Review branches record coverage substatuses:
static/dynamic baseline collection, match and status classification, hidden-flow identification
(dynamic_only/feature_gated rows become hypotheses for later phases), and stale-entry disposition
(stale/unreachable rows are never reported as live issues). Reconciliation is an offline comparison of
existing static evidence and authorized dynamic evidence — never send new requests to "verify"
unreachable or stale rows.

## 8. Completion criteria

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
