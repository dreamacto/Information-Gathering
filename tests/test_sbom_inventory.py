"""tests/test_sbom_inventory.py —— batch16_5 专属测试。

正例：requirements/package-lock v3/v1/package.json 离线清单；advisory 命中与
比较器（==/</>=）确定性匹配。
规格 7.2 负例：无 advisory 数据 → 只报清单+人工复核不伪造结论；vulnerable/
confirmed 状态被 validator 拒绝；解析失败行进违例不猜测；约束不可解析
fail-closed；空目录/损坏 JSON。幂等例。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for candidate in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from authorized_assessment.analysis import sbom_inventory as sbom  # noqa: E402


def _make_tree(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text(
        "# comment line\nrequests==2.28.1\nurllib3>=1.26.0\n-r extras.txt\nnot-a-requirement!\n",
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "app",
                "packages": {
                    "": {"dependencies": {"lodash": "4.17.21"}},
                    "node_modules/lodash": {"version": "4.17.21"},
                    "node_modules/lodash-dep": {"version": "1.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"axios": "^1.2.3"}, "devDependencies": {"jest": "29.0.0"}}),
        encoding="utf-8",
    )
    return tmp_path


# ---------- 清单解析 ----------

def test_requirements_parsing_with_violations(tmp_path):
    _make_tree(tmp_path)
    rows, summary, violations = sbom.build_sbom_from_directory(tmp_path)
    python_rows = [r for r in rows if r["ecosystem"] == "python"]
    assert [(r["name"], r["version"], r["version_pinned"]) for r in python_rows] == [
        ("requests", "2.28.1", True),
        ("urllib3", "1.26.0", False),
    ]
    assert all(r["advisory_status"] == "no_advisory_data" for r in python_rows)
    assert any("-r extras.txt" in v for v in violations)
    assert any("not-a-requirement!" in v for v in violations)
    assert summary["conclusion"].startswith("无 advisory 数据")
    assert "伪造" in summary["conclusion"]


def test_package_lock_v3_direct_vs_transitive(tmp_path):
    _make_tree(tmp_path)
    rows, _s, violations = sbom.build_sbom_from_directory(tmp_path)
    assert violations == [] or all("package" not in v for v in violations)
    npm_rows = [r for r in rows if r["source_file"] == "package-lock.json"]
    by_name = {r["name"]: r for r in npm_rows}
    assert by_name["lodash"]["direct"] is True
    assert by_name["lodash-dep"]["direct"] is False
    assert all(r["relations_available"] for r in npm_rows)


def test_package_json_unpinned_versions(tmp_path):
    _make_tree(tmp_path)
    rows, _s, violations = sbom.build_sbom_from_directory(tmp_path)
    assert not any("package.json" in v for v in violations)  # 故意坏行来自 requirements 夹具
    pkg_rows = [r for r in rows if r["source_file"].startswith("package.json")]
    by_name = {r["name"]: r for r in pkg_rows}
    assert by_name["axios"]["version"] == "^1.2.3" and by_name["axios"]["version_pinned"] is False
    assert by_name["jest"]["version_pinned"] is True


def test_empty_and_missing_directories(tmp_path):
    (tmp_path / "empty").mkdir()
    rows, summary, violations = sbom.build_sbom_from_directory(tmp_path / "empty")
    assert rows == []
    assert summary["total_dependencies"] == 0
    rows2, summary2, violations2 = sbom.build_sbom_from_directory(tmp_path / "nope")
    assert rows2 == [] and summary2 == {}
    assert any("目录不存在" in v for v in violations2)


def test_corrupt_lockfile_recorded(tmp_path):
    (tmp_path / "package-lock.json").write_text("{not json", encoding="utf-8")
    _rows, _s, violations = sbom.build_sbom_from_directory(tmp_path)
    assert any("JSON 解析失败" in v for v in violations)


# ---------- advisory 匹配 ----------

def _cache() -> dict:
    return {
        "cache_available": True,
        "packages": {
            "requests": [{"cve": "CVE-2023-32681", "affected": "<2.31.0", "summary": "Proxy-Authorization leak"}],
            "lodash": [{"cve": "CVE-2021-23337", "affected": "<4.17.21", "summary": "command injection"}],
            "weird": [{"cve": "CVE-X", "affected": "not-a-constraint"}],
        },
    }


def test_advisory_hit_is_manual_review_not_conclusion(tmp_path):
    _make_tree(tmp_path)
    rows, summary, _v = sbom.build_sbom_from_directory(tmp_path, _cache())
    requests_row = next(r for r in rows if r["name"] == "requests")
    assert requests_row["advisory_status"] == "advisory_hit_manual_review"
    assert requests_row["advisories"][0]["cve"] == "CVE-2023-32681"
    assert requests_row["status"] == "inventory"
    lodash_row = next(r for r in rows if r["name"] == "lodash")
    assert lodash_row["advisory_status"] == "no_advisory_data"  # 4.17.21 不满足 <4.17.21
    assert "人工复核" in summary["reason"]


def test_unparsable_constraint_fail_closed(tmp_path):
    (tmp_path / "requirements.txt").write_text("weird==1.0.0\n", encoding="utf-8")
    rows, _s, _v = sbom.build_sbom_from_directory(tmp_path, _cache())
    assert rows[0]["advisory_status"] == "advisory_unparsed"


def test_version_comparator_semantics():
    assert sbom._satisfies("2.31.0", ">=2.28.1") is True
    assert sbom._satisfies("2.28.1", "<2.31.0") is True
    assert sbom._satisfies("2.28", "==2.28.0") is True
    assert sbom._satisfies("2.28.1", "!=2.28.1") is False
    assert sbom._satisfies("2.28.1", "junk") is None
    assert sbom._satisfies("2.28.1", "") is None


# ---------- 漏洞结论禁入 ----------

def test_vulnerable_status_rejected_by_validator():
    violations = sbom.validate_sbom_row(
        {"component_id": "sbom-0001", "status": "vulnerable", "ecosystem": "python",
         "name": "requests", "version": "2.28.1", "source_file": "requirements.txt:2"},
        label="neg",
    )
    assert any("不伪造漏洞结论" in v for v in violations)
    violations2 = sbom.validate_sbom_row(
        {"component_id": "sbom-0002", "status": "confirmed", "ecosystem": "python",
         "name": "requests", "version": "2.28.1", "source_file": "requirements.txt:2",
         "advisory_status": "advisory_hit_manual_review"},
        label="neg",
    )
    assert any("不伪造漏洞结论" in v for v in violations2)


def test_missing_fields_rejected():
    violations = sbom.validate_sbom_row({"status": "inventory"}, label="neg")
    assert any("缺少必需字段" in v for v in violations)


# ---------- 幂等 ----------

def test_sbom_is_idempotent(tmp_path):
    _make_tree(tmp_path)
    first = sbom.build_sbom_from_directory(tmp_path, _cache())
    second = sbom.build_sbom_from_directory(tmp_path, _cache())
    assert first == second
