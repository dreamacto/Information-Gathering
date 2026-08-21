# -*- coding: utf-8 -*-
"""W8 · 竞态靶场 labs/race_lab_server.py

stdlib 靶场，两个真值端点：
  /claim       check-then-act 非原子（库存 1，并发可多次成功）   → overrun=true 真值
  /claim_safe  threading.Lock 保护（并发只能成功 1 次）          → overrun=false 负例真值
  /transfer    非事务余额（超扣真值，仅 POST，需 write_risk_ack） → overrun=true 真值

用法：python labs/race_lab_server.py [--port 8892]
"""
import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INIT_STOCK = 1
INIT_BALANCE = 100

state_lock = threading.Lock()
stock = {"count": INIT_STOCK}
balance = {"amount": INIT_BALANCE}


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

    def _reset(self):
        global stock, balance
        with state_lock:
            stock = {"count": INIT_STOCK}
            balance = {"amount": INIT_BALANCE}

    def do_GET(self):
        if self.path == "/reset":
            self._reset()
            return self._json(200, {"ok": True, "stock": stock["count"], "balance": balance["amount"]})
        if self.path == "/claim":
            # check-then-act 非原子：先查后扣
            if stock["count"] <= 0:
                return self._json(200, {"ok": False, "msg": "已领完"})
            time.sleep(0.15)  # 放大竞态窗口
            stock["count"] -= 1
            return self._json(200, {"ok": True, "msg": "领取成功"})
        if self.path == "/claim_safe":
            with state_lock:
                if stock["count"] <= 0:
                    return self._json(200, {"ok": False, "msg": "已领完"})
                time.sleep(0.15)
                stock["count"] -= 1
                return self._json(200, {"ok": True, "msg": "领取成功"})
        if self.path == "/stock":
            return self._json(200, {"stock": stock["count"]})
        self._json(404, {"msg": "not found"})

    def do_POST(self):
        if self.path == "/transfer":
            ln = int(self.headers.get("Content-Length", "0"))
            try:
                data = json.loads(self.rfile.read(ln) or b"{}")
            except json.JSONDecodeError:
                data = {}
            amt = int(data.get("amount", 10))
            # 非事务：先查余额后扣，无锁 → 超扣真值
            if balance["amount"] < amt:
                return self._json(200, {"ok": False, "msg": "余额不足"})
            time.sleep(0.15)
            balance["amount"] -= amt
            return self._json(200, {"ok": True, "msg": "转账成功", "balance": balance["amount"]})
        self._json(404, {"msg": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8892)
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print(f"[*] race lab 就绪 http://127.0.0.1:{a.port}  (/reset 恢复库存)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
