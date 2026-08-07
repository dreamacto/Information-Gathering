#!/usr/bin/env python3
"""本地SQL注入测试靶场 —— 仅供本地测试 vuln_sqli_pure.py 使用"""
import sqlite3
from flask import Flask, request

app = Flask(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT, password TEXT);
DELETE FROM users;
INSERT INTO users VALUES (1, 'admin', 'super_secret_123');
INSERT INTO users VALUES (2, 'guest', 'guest123');
INSERT INTO users VALUES (3, 'test', 'test456');
"""

def get_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.executescript(SCHEMA)
    return conn

# 每个请求自己创建连接，用完就丢
def query_db(sql):
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    try:
        conn.executescript(SCHEMA)
        c = conn.cursor()
        c.execute(sql)
        rows = c.fetchall()
        conn.close()
        return rows, None
    except Exception as e:
        conn.close()
        return [], str(e)

@app.route("/")
def index():
    return """<h1>本地SQL注入测试靶场</h1>
<ul>
<li><a href='/user?id=1'>/user?id=1</a> (数字型注入)</li>
<li><a href='/user_str?name=admin'>/user_str?name=admin</a> (字符型注入)</li>
<li><a href='/search?q=test'>/search?q=test</a> (LIKE搜索)</li>
<li><a href='/time?id=1'>/time?id=1</a> (时间盲注)</li>
</ul>"""

@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    sql = f"SELECT id, name FROM users WHERE id = {uid}"
    print(f"[SQL] {sql}")
    rows, err = query_db(sql)
    if err:
        return f"<pre>SQL Error: {err}</pre>", 500
    if rows:
        return "<pre>" + "<br>".join(f"id={r[0]} name={r[1]}" for r in rows) + "</pre>"
    return "<pre>No user found</pre>"

@app.route("/user_str")
def user_str():
    name = request.args.get("name", "")
    sql = f"SELECT id, name FROM users WHERE name = '{name}'"
    print(f"[SQL] {sql}")
    rows, err = query_db(sql)
    if err:
        return f"<pre>SQL Error: {err}</pre>", 500
    if rows:
        return "<pre>" + "<br>".join(f"id={r[0]} name={r[1]}" for r in rows) + "</pre>"
    return "<pre>No user found</pre>"

@app.route("/search")
def search():
    q = request.args.get("q", "")
    sql = f"SELECT id, name FROM users WHERE name LIKE '%{q}%'"
    print(f"[SQL] {sql}")
    rows, err = query_db(sql)
    if err:
        return f"<pre>SQL Error: {err}</pre>", 500
    if rows:
        return "<pre>" + "<br>".join(f"id={r[0]} name={r[1]}" for r in rows) + "</pre>"
    return "<pre>No results</pre>"

@app.route("/time")
def time_query():
    uid = request.args.get("id", "1")
    sql = f"SELECT id, name FROM users WHERE id = {uid}"
    print(f"[SQL] {sql}")
    rows, err = query_db(sql)
    if err:
        return f"<pre>SQL Error: {err}</pre>", 500
    if rows:
        return "<pre>" + f"id={rows[0][0]} name={rows[0][1]}" + "</pre>"
    return "<pre>No user</pre>"

@app.route("/login", methods=["POST"])
def login():
    """POST 注入点 —— 表单登录，body 参数拼接 SQL"""
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    sql = f"SELECT id, name FROM users WHERE name = '{username}' AND password = '{password}'"
    print(f"[SQL] {sql}")
    rows, err = query_db(sql)
    if err:
        return f"<pre>SQL Error: {err}</pre>", 500
    if rows:
        return f"<pre>Login OK: id={rows[0][0]} name={rows[0][1]}</pre>"
    return "<pre>Login failed</pre>"


if __name__ == "__main__":
    print("=" * 50)
    print("  本地SQL注入测试靶场")
    print("  数字型: http://127.0.0.1:9999/user?id=1")
    print("  字符型: http://127.0.0.1:9999/user_str?name=admin")
    print("  LIKE:   http://127.0.0.1:9999/search?q=test")
    print("  POST:   http://127.0.0.1:9999/login  POST username=admin&password=test")
    print("=" * 50)
    app.run(host="127.0.0.1", port=9999, debug=False)
