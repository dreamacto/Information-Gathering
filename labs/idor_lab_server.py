# -*- coding: utf-8 -*-
"""W7 · IDOR 靶场 labs/idor_lab_server.py

stdlib http.server 靶场，四类端点提供测试地面真值：
  /api/order/1      正确鉴权（B 访问 A 的订单 → 403）       真值: inconclusive/noise
  /api/order_vuln/1 不校验归属（B 也能读 A 的订单）          真值: idor_horizontal_candidate
  /api/leak/1       匿名可读                                   真值: unauth_access
  /api/soft_deny    200 但正文"权限不足"                      真值: noise（200-with-error）

用法：python labs/idor_lab_server.py [--port 8891]
"""
import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKENS = {
    "token-userA": {"user": "A", "name": "用户A"},
    "token-userB": {"user": "B", "name": "用户B"},
}

ORDER_A = {"id": 1, "owner": "A", "item": "简历投递记录", "amount": 3}
ORDER_B = {"id": 2, "owner": "B", "item": "简历投递记录", "amount": 1}


def _auth(hd):
    m = re.search(r"token-(user[AB])", hd.get("Authorization", "") or hd.get("Cookie", "") or "")
    return m.group(1) if m else None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        user = _auth(self.headers)
        path = self.path

        if path == "/api/soft_deny":
            # 200-with-error 真值：任何请求都 200 + 权限不足文案
            return self._json(200, {"code": 0, "msg": "权限不足，请联系管理员"})

        if path.startswith("/api/leak/"):
            # unauth_access 真值：匿名可读，结构一致
            return self._json(200, {"code": 0, "data": ORDER_A, "msg": "ok"})

        if path.startswith("/api/order_vuln/"):
            # IDOR 真值：只校验登录，不校验归属
            if not user:
                return self._json(401, {"code": 401, "msg": "未登录"})
            return self._json(200, {"code": 0, "data": ORDER_A, "msg": "ok"})

        m = re.match(r"^/api/order/(\d+)$", path)
        if m:
            oid = int(m.group(1))
            if not user:
                return self._json(401, {"code": 401, "msg": "未登录"})
            order = ORDER_A if oid == 1 else ORDER_B if oid == 2 else None
            if order is None:
                return self._json(404, {"code": 404, "msg": "not found"})
            if order["owner"] != user:
                return self._json(403, {"code": 403, "msg": "无权访问他人订单"})
            return self._json(200, {"code": 0, "data": order, "msg": "ok"})

        self._json(404, {"code": 404, "msg": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8891)
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print(f"[*] IDOR lab 就绪 http://127.0.0.1:{a.port}  (Ctrl+C 停)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
