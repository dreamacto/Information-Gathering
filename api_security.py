#!/usr/bin/env python3
# encoding: utf-8
"""
API 安全测试模块
  功能: Swagger/OpenAPI 发现、GraphQL introspection、API参数Fuzzing、JWT攻击
  集成天狐: API-T00L / API-Explorer
  用法: python api_security.py --project glut
        python api_security.py --url https://target.com
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings()

from config import BASE_DIR, TIANHU_GUI_SCAN, PYTHON_EXE, JAVA_CMD
from pentest_utils import resolve_path, load_targets, safe_request, random_ua

# 天狐 API 工具
API_TOOL_JAR = os.path.join(TIANHU_GUI_SCAN, "apitool", "API-T00L_v1.2.jar")
API_EXPLORER = os.path.join(TIANHU_GUI_SCAN, "apitool", "API-Explorer_v1.0.1.exe")

TIMEOUT = 15

# ==================== API 文档发现 ====================

SWAGGER_PATHS = [
    "/swagger-ui.html", "/swagger-ui/index.html", "/swagger-resources",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json", "/v1/swagger.json", "/v2/swagger.json",
    "/v3/swagger.json", "/api-docs", "/api-docs/v1", "/api-docs/v2",
    "/api/swagger.json", "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/doc.html", "/doc.json", "/api/doc.html",
    "/openapi.json", "/openapi.yaml", "/api-spec.json",
    "/docs/swagger.json", "/services/swagger.json",
]

GRAPQL_PATHS = [
    "/graphql", "/graphiql", "/gql", "/graphql/console",
    "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/query", "/playground",
]

OPENAPI_PROBE = [
    "/api/v1/openapi.json", "/api/v2/openapi.json",
    "/openapi/v1.json", "/openapi/v2.json",
]


def discover_api_docs(base_url):
    """发现 Swagger/OpenAPI/GraphQL 端点"""
    findings = {"swagger": [], "openapi": [], "graphql": []}
    base = base_url.rstrip("/")

    print(f"\n[*] API 文档发现: {base}")

    # Swagger 探测
    for path in SWAGGER_PATHS:
        url = urljoin(base, path)
        try:
            r = requests.get(url, timeout=TIMEOUT, verify=False,
                           headers={"User-Agent": random_ua()})
            if r.status_code == 200:
                text = r.text[:500].lower()
                if any(k in text for k in ["swagger", "openapi", "2.0", "3.0",
                                            "paths", "definitions"]):
                    findings["swagger"].append({"url": url, "status": r.status_code})
                    print(f"  [+] Swagger: {url}")
        except Exception:
            pass

    # OpenAPI schema
    for path in OPENAPI_PROBE:
        url = urljoin(base, path)
        try:
            r = requests.get(url, timeout=TIMEOUT, verify=False,
                           headers={"User-Agent": random_ua()})
            if r.status_code == 200:
                text = r.text[:500].lower()
                if "openapi" in text or "swagger" in text:
                    findings["openapi"].append({"url": url, "status": r.status_code})
                    print(f"  [+] OpenAPI: {url}")
        except Exception:
            pass

    # GraphQL 探测
    for path in GRAPQL_PATHS:
        url = urljoin(base, path)
        try:
            r = requests.get(url, timeout=TIMEOUT, verify=False,
                           headers={"User-Agent": random_ua()})
            if r.status_code in (200, 400, 405):
                # GraphQL 常用报错和信息
                if any(k in r.text.lower() for k in
                       ["graphql", "query", "mutation", "__schema",
                        "graphiql", "must provide query string"]):
                    findings["graphql"].append({"url": url, "status": r.status_code})
                    print(f"  [+] GraphQL: {url}")
        except Exception:
            pass

    total = sum(len(v) for v in findings.values())
    print(f"  [*] 发现 {total} 个API端点")
    return findings


def graphql_introspection(url):
    """GraphQL Schema 内省查询"""
    query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields { name type { name kind } }
        }
      }
    }
    """
    try:
        r = requests.post(url, json={"query": query}, timeout=TIMEOUT,
                         verify=False, headers={"User-Agent": random_ua()})
        if r.status_code == 200 and "__schema" in r.text:
            data = r.json()["data"]["__schema"]
            types = data.get("types", [])
            queries = [t["name"] for t in types if t.get("kind") == "OBJECT"
                      and t.get("fields")]
            print(f"  [+] GraphQL Schema 泄露! {len(types)} 类型, {len(queries)} 查询")
            # 提取敏感查询
            sensitive = [q for q in queries if any(
                k in q.lower() for k in ["user", "pass", "token", "key",
                                          "secret", "admin", "config"])]
            if sensitive:
                print(f"  [!] 敏感查询: {', '.join(sensitive)}")
            return data
    except Exception as e:
        print(f"  [-] GraphQL introspection 失败: {e}")
    return None


# ==================== JWT 攻击 ====================

def jwt_attack_test(url):
    """JWT 常见攻击测试"""
    results = []
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False,
                        headers={"User-Agent": random_ua()})
        auth_header = r.headers.get("Authorization", "")
        cookies = r.cookies

        # 检查是否使用 JWT
        jwt_pattern = r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"
        found_jwt = re.findall(jwt_pattern, str(r.headers) + str(cookies))
        if found_jwt:
            print(f"  [+] 发现 JWT Token ({len(found_jwt)} 个)")
            results.append({"type": "jwt_found", "tokens": found_jwt})
            print(f"  [!] 可尝试: none算法 / 密钥爆破 / kid注入 / 过期重用")

        # 检查 CORS 配置
        cors_origin = r.headers.get("Access-Control-Allow-Origin", "")
        if cors_origin == "*":
            print(f"  [!] CORS 配置宽松: Access-Control-Allow-Origin: *")
            results.append({"type": "cors_misconfig", "detail": "wildcard origin"})
        elif cors_origin:
            print(f"  [*] CORS: {cors_origin}")

    except Exception as e:
        print(f"  [-] JWT检查失败: {e}")
    return results


# ==================== API 参数 Fuzzing / Swagger解析 ====================

def parse_swagger_endpoints(swagger_url):
    """解析 Swagger/OpenAPI 文档，提取所有 API 端点+参数"""
    endpoints = []
    try:
        r = requests.get(swagger_url, timeout=TIMEOUT, verify=False,
                        headers={"User-Agent": random_ua()})
        data = r.json()

        # OpenAPI 3.x
        if "paths" in data:
            for path, methods in data["paths"].items():
                for method, details in methods.items():
                    if method in ("get", "post", "put", "delete", "patch"):
                        params = []
                        for p in details.get("parameters", []):
                            params.append({
                                "name": p.get("name"),
                                "in": p.get("in"),
                                "required": p.get("required", False),
                            })
                        # 也解析 requestBody
                        if "requestBody" in details:
                            content = details["requestBody"].get("content", {})
                            for ct, schema in content.items():
                                props = (schema.get("schema", {})
                                        .get("properties", {}))
                                for pname in props:
                                    params.append({
                                        "name": pname,
                                        "in": "body",
                                        "required": True,
                                    })
                        endpoints.append({
                            "method": method.upper(),
                            "path": path,
                            "params": params,
                        })
                        print(f"  {method.upper():6s} {path} ({len(params)} 参数)")

        elif "swagger" in data:
            # Swagger 2.0
            base_path = data.get("basePath", "")
            for path, methods in data.get("paths", {}).items():
                full_path = base_path + path
                for method, details in methods.items():
                    if method in ("get", "post", "put", "delete", "patch"):
                        params = []
                        for p in details.get("parameters", []):
                            params.append({
                                "name": p.get("name"),
                                "in": p.get("in"),
                                "required": p.get("required", False),
                            })
                        endpoints.append({
                            "method": method.upper(),
                            "path": full_path,
                            "params": params,
                        })
                        print(f"  {method.upper():6s} {full_path}")

        print(f"  [+] 解析出 {len(endpoints)} 个 API 端点")
    except Exception as e:
        print(f"  [-] Swagger 解析失败: {e}")
    return endpoints


# ==================== 主流程 ====================

def run_api_security(url, project=None):
    """对单个 URL 运行 API 安全测试"""
    print(f"\n{'='*60}")
    print(f"  API 安全测试 - {url}")
    print(f"{'='*60}")

    # Step 1: API 文档发现
    docs = discover_api_docs(url)

    # Step 2: 解析 Swagger/OpenAPI
    all_endpoints = []
    for swag in docs.get("swagger", []):
        print(f"\n[*] 解析 Swagger: {swag['url']}")
        endpoints = parse_swagger_endpoints(swag["url"])
        all_endpoints.extend(endpoints)
    for oapi in docs.get("openapi", []):
        print(f"\n[*] 解析 OpenAPI: {oapi['url']}")
        endpoints = parse_swagger_endpoints(oapi["url"])
        all_endpoints.extend(endpoints)

    # Step 3: GraphQL introspection
    for gql in docs.get("graphql", []):
        graphql_introspection(gql["url"])

    # Step 4: JWT 检测
    jwt_attack_test(url)

    # Step 5: 调用天狐 API 工具
    if os.path.isfile(API_TOOL_JAR):
        print(f"\n[*] 调用 API-T00L...")
        import subprocess
        try:
            subprocess.run(
                [JAVA_CMD, "-jar", API_TOOL_JAR, "-u", url],
                timeout=300, capture_output=True,
            )
            print(f"  [+] API-T00L 完成")
        except Exception as e:
            print(f"  [-] API-T00L 出错: {e}")

    # 保存结果
    if project and all_endpoints:
        output_path = resolve_path(project, "api_endpoints.json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(all_endpoints, f, ensure_ascii=False, indent=2)
        print(f"\n[√] API 端点已保存: {output_path}")

    return {"docs": docs, "endpoints": all_endpoints}


def main():
    parser = argparse.ArgumentParser(description="API 安全测试模块")
    parser.add_argument("--project", default=None, help="项目缩写")
    parser.add_argument("--url", default=None, help="单个URL")
    args = parser.parse_args()

    if args.url:
        run_api_security(args.url)
    elif args.project:
        urls = load_targets(args.project)
        # 只测有 API 特征的 URL
        api_candidates = [u for u in urls if any(
            k in u.lower() for k in ["api", "graphql", "swagger", "openapi",
                                       "rest", "service"]
        )]
        if not api_candidates:
            api_candidates = urls[:5]  # 回退到前几个
        print(f"[+] API 候选目标: {len(api_candidates)} 个")
        for url in api_candidates[:10]:
            run_api_security(url, args.project)
            time.sleep(2)
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 已取消")
    try:
        input("\n按 Enter 退出...")
    except (EOFError, KeyboardInterrupt):
        pass
