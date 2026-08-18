#!/usr/bin/env python3
"""本地 XSS 测试靶场 — 仅供本地验证 XSS 检测脚本，监听 127.0.0.1"""
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

DB = "xss_lab.db"


def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return "<h3>XSS Lab</h3><p><a href='/xss/reflected?q=hello'>reflected</a> | " \
           "<a href='/xss/attr?u=javascript:alert(1)'>attr</a> | " \
           "<a href='/xss/stored'>stored</a> | <a href='/xss/dom'>dom</a></p>"


@app.route("/xss/reflected")
def reflected():
    q = request.args.get("q", "")
    html = f"<h3>Reflected XSS</h3><p>Your input: {q}</p>"
    return html


@app.route("/xss/attr")
def attr():
    u = request.args.get("u", "")
    html = f"<h3>Attribute XSS</h3><a href='{u}'>link</a>"
    return html


@app.route("/xss/stored", methods=["GET", "POST"])
def stored():
    msg = ""
    if request.method == "POST":
        body = request.form.get("body", "")
        conn = sqlite3.connect(DB)
        conn.execute("INSERT INTO posts (body) VALUES (?)", (body,))
        conn.commit()
        conn.close()
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT id, body FROM posts ORDER BY id DESC LIMIT 10").fetchall()
    conn.close()
    items = "".join(f"<li>{r[1]}</li>" for r in rows)
    page = f"""<h3>Stored XSS</h3>
<form method='post'><input name='body' size=40><button>post</button></form>
<ul>{items}</ul>"""
    return page


@app.route("/xss/dom")
def dom():
    page = """<h3>DOM XSS</h3>
<p>Your hash fragment is rendered below:</p>
<div id="out">none</div>
<script>
var h = location.hash.slice(1);
document.getElementById('out').innerHTML = h;
</script>"""
    return page


if __name__ == "__main__":
    init_db()
    print("=" * 50)
    print("  本地 XSS 测试靶场")
    print("  反射型: http://127.0.0.1:9001/xss/reflected?q=abc")
    print("  属性型: http://127.0.0.1:9001/xss/attr?u=...")
    print("  存储型: http://127.0.0.1:9001/xss/stored")
    print("  DOM型:  http://127.0.0.1:9001/xss/dom#<script>alert(1)</script>")
    print("=" * 50)
    app.run(host="127.0.0.1", port=9001, debug=False)