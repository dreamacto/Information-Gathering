#!/usr/bin/env python3
# encoding: utf-8
"""
结果数据库模块 (SQLite)
  功能: 跨项目漏洞追踪、历史对比、统计面板
  所有扫描器和模块的统一结果存储
  用法: python results_db.py --stats          # 全局统计
        python results_db.py --project glut   # 项目统计
        python results_db.py --export all     # 导出所有结果
"""

import json
import os
import sqlite3
import sys
from datetime import datetime

from config import BASE_DIR

DB_PATH = os.path.join(BASE_DIR, "pentest_results.db")


def get_db():
    """获取数据库连接（自动创建表）"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _init_tables(conn)
    return conn


def _init_tables(conn):
    """初始化数据库表"""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            domain TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER REFERENCES projects(id),
            url TEXT NOT NULL,
            fingerprint TEXT,
            tech_stack TEXT,
            status_code INTEGER,
            alive INTEGER DEFAULT 1,
            priority_tier INTEGER,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            UNIQUE(project_id, url)
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER REFERENCES projects(id),
            target_id INTEGER REFERENCES targets(id),
            vuln_type TEXT NOT NULL,
            severity TEXT CHECK(severity IN ('critical','high','medium','low','info')),
            title TEXT,
            description TEXT,
            evidence TEXT,
            url TEXT,
            param TEXT,
            payload TEXT,
            verified INTEGER DEFAULT 0,
            cve TEXT,
            cvss REAL,
            tool TEXT,
            discovered_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER REFERENCES projects(id),
            url TEXT,
            system_type TEXT,
            username TEXT,
            password TEXT,
            hash TEXT,
            discovered_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER REFERENCES projects(id),
            url TEXT,
            method TEXT,
            endpoint TEXT,
            params TEXT,
            source TEXT,
            discovered_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER REFERENCES projects(id),
            tool TEXT NOT NULL,
            target_count INTEGER,
            findings_count INTEGER,
            status TEXT,
            output_file TEXT,
            duration_seconds REAL,
            scanned_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE INDEX IF NOT EXISTS idx_vulns_project ON vulnerabilities(project_id);
        CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(vuln_type);
        CREATE INDEX IF NOT EXISTS idx_vulns_sev ON vulnerabilities(severity);
        CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id);
        CREATE INDEX IF NOT EXISTS idx_creds_project ON credentials(project_id);
    """)


# ==================== 增 ====================

def ensure_project(conn, name, domain=""):
    """确保项目存在，返回 project_id"""
    cur = conn.execute(
        "INSERT OR IGNORE INTO projects (name, domain) VALUES (?, ?)",
        (name, domain)
    )
    if cur.rowcount > 0:
        conn.commit()
    row = conn.execute(
        "SELECT id FROM projects WHERE name = ?", (name,)
    ).fetchone()
    # 更新 updated_at
    conn.execute(
        "UPDATE projects SET updated_at = datetime('now','localtime') WHERE id = ?",
        (row["id"],)
    )
    conn.commit()
    return row["id"]


def add_target(conn, project_id, url, fingerprint="", tech_stack="",
               status_code=None, priority_tier=None):
    """添加/更新目标"""
    conn.execute("""
        INSERT OR REPLACE INTO targets
        (project_id, url, fingerprint, tech_stack, status_code, priority_tier)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (project_id, url, fingerprint, tech_stack, status_code, priority_tier))
    conn.commit()
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def add_vulnerability(conn, project_id, vuln_type, severity="medium",
                      title="", url="", param="", payload="",
                      evidence="", cve="", tool="", target_id=None):
    """添加漏洞记录"""
    conn.execute("""
        INSERT INTO vulnerabilities
        (project_id, target_id, vuln_type, severity, title, url, param,
         payload, evidence, cve, tool)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (project_id, target_id, vuln_type, severity, title, url,
          param, payload, evidence, cve, tool))
    conn.commit()


def add_credential(conn, project_id, url, system_type, username, password):
    """添加凭据"""
    conn.execute("""
        INSERT INTO credentials (project_id, url, system_type, username, password)
        VALUES (?, ?, ?, ?, ?)
    """, (project_id, url, system_type, username, password))
    conn.commit()


def add_scan_log(conn, project_id, tool, target_count=0,
                 findings_count=0, status="completed",
                 output_file="", duration=0):
    """添加扫描日志"""
    conn.execute("""
        INSERT INTO scans (project_id, tool, target_count, findings_count,
                          status, output_file, duration_seconds)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (project_id, tool, target_count, findings_count,
          status, output_file, duration))
    conn.commit()


# ==================== 查 ====================

def get_project_stats(conn, project_name=None):
    """获取项目统计"""
    if project_name:
        pid_row = conn.execute(
            "SELECT id FROM projects WHERE name = ?", (project_name,)
        ).fetchone()
        if not pid_row:
            return None
        pid = pid_row["id"]
        where = f"WHERE project_id = {pid}"
    else:
        where = ""

    stats = {}

    # 漏洞统计
    stats["vulns_by_severity"] = [
        dict(row) for row in conn.execute(f"""
            SELECT severity, COUNT(*) as count
            FROM vulnerabilities {where}
            GROUP BY severity ORDER BY
            CASE severity
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'info' THEN 5
            END
        """).fetchall()
    ]

    stats["vulns_by_type"] = [
        dict(row) for row in conn.execute(f"""
            SELECT vuln_type, COUNT(*) as count
            FROM vulnerabilities {where}
            GROUP BY vuln_type ORDER BY count DESC
        """).fetchall()
    ]

    # 目标统计
    stats["target_count"] = conn.execute(
        f"SELECT COUNT(*) FROM targets {where}"
    ).fetchone()[0]

    stats["alive_targets"] = conn.execute(
        f"SELECT COUNT(*) FROM targets {where} AND alive=1"
    ).fetchone()[0]

    # 凭据统计
    stats["credential_count"] = conn.execute(
        f"SELECT COUNT(*) FROM credentials {where}"
    ).fetchone()[0]

    # 扫描统计
    stats["scan_count"] = conn.execute(
        f"SELECT COUNT(*) FROM scans {where}"
    ).fetchone()[0]

    stats["last_scan"] = conn.execute(f"""
        SELECT tool, scanned_at FROM scans {where}
        ORDER BY scanned_at DESC LIMIT 1
    """).fetchone()

    return stats


def get_recent_vulns(conn, limit=20):
    """获取最近的漏洞"""
    rows = conn.execute("""
        SELECT v.*, p.name as project_name
        FROM vulnerabilities v
        LEFT JOIN projects p ON v.project_id = p.id
        ORDER BY v.discovered_at DESC LIMIT ?
    """, (limit,)).fetchall()
    return [dict(r) for r in rows]


def list_projects(conn):
    """列出所有项目"""
    rows = conn.execute("""
        SELECT p.*,
               (SELECT COUNT(*) FROM targets WHERE project_id = p.id) as target_count,
               (SELECT COUNT(*) FROM vulnerabilities WHERE project_id = p.id) as vuln_count,
               (SELECT COUNT(*) FROM credentials WHERE project_id = p.id) as cred_count
        FROM projects p ORDER BY updated_at DESC
    """).fetchall()
    return [dict(r) for r in rows]


# ==================== 导入 ====================

def import_from_project(project_name):
    """从项目目录自动导入结果"""
    project_dir = os.path.join(BASE_DIR, project_name)
    if not os.path.isdir(project_dir):
        print(f"[-] 项目目录不存在: {project_dir}")
        return

    conn = get_db()
    pid = ensure_project(conn, project_name)

    # 导入 targets
    urls_file = os.path.join(project_dir, f"{project_name}_urls.txt")
    if os.path.isfile(urls_file):
        with open(urls_file, "r", encoding="utf-8") as f:
            for line in f:
                url = line.strip()
                if url.startswith("http"):
                    add_target(conn, pid, url)

    # 导入 priority targets (带指纹)
    priority_file = os.path.join(project_dir, f"{project_name}_priority_targets.txt")
    if os.path.isfile(priority_file):
        current_tier = 0
        with open(priority_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "第一梯队" in line:
                    current_tier = 1
                elif "第二梯队" in line:
                    current_tier = 2
                elif "第三梯队" in line:
                    current_tier = 3
                elif line.startswith("http"):
                    add_target(conn, pid, line, priority_tier=current_tier)

    # 导入 phase1_analysis.json
    phase1_file = os.path.join(project_dir, "phase1_analysis.json")
    if os.path.isfile(phase1_file):
        with open(phase1_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            for item in (data if isinstance(data, list) else [data]):
                url = item.get("url", "")
                fps = item.get("cms", "") or item.get("tech", "")
                add_target(conn, pid, url, fingerprint=fps)

    conn.close()
    print(f"[√] 项目 '{project_name}' 已导入数据库")
    return True


# ==================== 导出 ====================

def export_json(conn, output_file="results_export.json"):
    """导出所有结果为 JSON"""
    data = {
        "exported_at": datetime.now().isoformat(),
        "projects": list_projects(conn),
        "recent_vulns": get_recent_vulns(conn, 100),
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[√] 导出完成: {output_file}")
    return output_file


# ==================== 命令行 ====================

def print_stats(stats, title="全局统计"):
    """格式化打印统计"""
    print(f"\n{'='*50}")
    print(f"  {title}")
    print(f"{'='*50}")

    if not stats:
        print("  (无数据)")
        return

    print(f"\n  目标总数: {stats.get('target_count', 0)}")
    print(f"  存活目标: {stats.get('alive_targets', 0)}")
    print(f"  发现凭据: {stats.get('credential_count', 0)}")
    print(f"  扫描次数: {stats.get('scan_count', 0)}")

    if stats.get("last_scan"):
        print(f"  最近扫描: {stats['last_scan']['tool']} @ "
              f"{stats['last_scan']['scanned_at']}")

    print(f"\n  漏洞分布:")
    for row in stats.get("vulns_by_severity", []):
        bar = "█" * min(row["count"], 40)
        print(f"    {row['severity']:8s} | {bar} {row['count']}")

    print(f"\n  漏洞类型 Top 10:")
    for row in stats.get("vulns_by_type", [])[:10]:
        print(f"    {row['vuln_type']:25s} {row['count']}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="结果数据库")
    parser.add_argument("--stats", action="store_true", help="全局统计")
    parser.add_argument("--project", help="项目统计")
    parser.add_argument("--import", dest="import_proj", help="导入项目数据")
    parser.add_argument("--list", action="store_true", help="列出所有项目")
    parser.add_argument("--export", help="导出 (all/项目名)")
    parser.add_argument("--recent", type=int, default=20, help="最近漏洞数")
    args = parser.parse_args()

    conn = get_db()

    if args.stats:
        stats = get_project_stats(conn)
        print_stats(stats, "全局统计")
    elif args.project:
        stats = get_project_stats(conn, args.project)
        print_stats(stats, f"项目: {args.project}")
    elif args.import_proj:
        import_from_project(args.import_proj)
    elif args.list:
        projects = list_projects(conn)
        print(f"\n项目列表 ({len(projects)} 个):")
        for p in projects:
            print(f"  {p['name']:15s} | 目标:{p['target_count']:3d} | "
                  f"漏洞:{p['vuln_count']:3d} | 凭据:{p['cred_count']:2d} | "
                  f"更新:{p['updated_at']}")
    elif args.export:
        if args.export == "all":
            export_json(conn)
        else:
            stats = get_project_stats(conn, args.export)
            if stats:
                export_file = f"{args.export}_export.json"
                with open(export_file, "w", encoding="utf-8") as f:
                    json.dump(stats, f, ensure_ascii=False, indent=2)
                print(f"[√] 导出: {export_file}")
    elif args.recent:
        vulns = get_recent_vulns(conn, args.recent)
        print(f"\n最近 {len(vulns)} 个漏洞:")
        for v in vulns:
            print(f"  [{v['severity']:8s}] {v['vuln_type']:20s} | "
                  f"{v.get('project_name','?'):12s} | {v.get('url','')[:60]}")

    conn.close()


if __name__ == "__main__":
    main()
