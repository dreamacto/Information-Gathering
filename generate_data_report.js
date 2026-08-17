const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, ShadingType, WidthType,
  PageBreak, Header, Footer, PageNumber } = require('docx');

const DARK_BLUE = "1F4E79"; const MED_GRAY = "555555"; const DARK_TEXT = "333333";
const WHITE = "FFFFFF"; const RED = "C62828"; const ORANGE = "E65100";
const BORDER = "CCCCCC";
const bd = { style: BorderStyle.SINGLE, size: 1, color: BORDER };
const cB = { top: bd, bottom: bd, left: bd, right: bd };
const cM = { top: 60, bottom: 60, left: 100, right: 100 };

function hc(text, w) { return new TableCell({ borders: cB, shading: { fill: DARK_BLUE, type: ShadingType.CLEAR }, width: { size: w, type: WidthType.DXA }, margins: cM, children: [new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text, bold: true, color: WHITE, size: 18, font: "Arial" })] })] }); }
function dc(text, w, o = {}) { return new TableCell({ borders: cB, width: { size: w, type: WidthType.DXA }, margins: cM, shading: o.shading ? { fill: o.shading, type: ShadingType.CLEAR } : undefined, children: [new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text, bold: o.bold || false, color: o.color || DARK_TEXT, size: 17, font: "Arial" })] })] }); }
function bp(text, o = {}) { return new Paragraph({ spacing: { after: 120, line: 360, lineRule: "auto" }, children: [new TextRun({ text, bold: o.bold || false, size: 21, font: "Arial", color: DARK_TEXT })] }); }
function h1(text) { return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 200 }, children: [new TextRun({ text, bold: true, size: 32, font: "Arial", color: DARK_BLUE })] }); }
function h2(text) { return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 240, after: 160 }, children: [new TextRun({ text, bold: true, size: 26, font: "Arial", color: DARK_BLUE })] }); }
function empty() { return new Paragraph({ spacing: { after: 80 }, children: [] }); }
function sect() { return { properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } }, headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: "媒体资源数智化平台 · 数据泄露报告", size: 16, font: "Arial", color: "999999" })] })] }) }, footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "第 ", size: 16 }), new TextRun({ children: [PageNumber.CURRENT], size: 16 }), new TextRun({ text: " 页", size: 16 })] })] }) } }, children: [] }; }

// ===== 封面 =====
const cover = sect();
cover.properties.headers = {}; cover.properties.footers = {};
cover.children.push(
  empty(), empty(), empty(), empty(),
  new Paragraph({ spacing: { after: 200 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "媒体资源数智化平台", bold: true, size: 48, font: "Arial", color: DARK_BLUE })] }),
  new Paragraph({ spacing: { after: 100 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "敏感业务数据泄露报告", size: 36, font: "Arial", color: DARK_TEXT })] }),
  empty(), empty(),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "adv-webpt.nn-cc.cn / adv-file.nn-cc.cn", size: 24, font: "Arial", color: MED_GRAY })] }),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "2026年8月11日", size: 24, font: "Arial", color: MED_GRAY })] }),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 一、概述 =====
const s1 = sect();
s1.children.push(
  h1("一、概述"),
  bp("媒体资源数智化平台由南宁市民卡公司运营，为南宁地铁1-5号线及公交系统提供户外广告媒体交易服务。本次评估使用注册的代理方测试账号moon（19162390621），通过只读方式发现平台存在严重的数据访问控制缺陷。以下为泄露数据的具体内容。"),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 二、商业定价全暴露 =====
const s2 = sect();
s2.children.push(
  h1("二、商业定价全暴露"),
  bp("端点 POST /api/v1/product/assetSchedules/schedule/all 无需任何权限即可返回全部12,162个广告位的完整数据，包含精确到个位数的价格。这意味着南宁地铁公交广告的完整定价表被完全暴露。"),
  empty(),
  bp("价格统计：", { bold: true }),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [3120, 3120, 3120],
    rows: [
      new TableRow({ children: [hc("指标", 3120), hc("数值", 3120), hc("说明", 3120)] }),
      new TableRow({ children: [dc("广告位总数", 3120, { bold: true }), dc("12,162", 3120), dc("全部在线（status=1）", 3120)] }),
      new TableRow({ children: [dc("媒体价格总价值", 3120, { bold: true, color: RED }), dc("¥46,391,635", 3120, { color: RED }), dc("mediaPrice 字段合计", 3120)] }),
      new TableRow({ children: [dc("制作价格总价值", 3120, { bold: true, color: RED }), dc("¥26,327,400", 3120, { color: RED }), dc("productionPrice 字段合计", 3120)] }),
      new TableRow({ children: [dc("合计总价值", 3120, { bold: true, color: RED }), dc("¥72,719,035", 3120, { bold: true, color: RED }), dc("整个广告位库存底价", 3120)] }),
      new TableRow({ children: [dc("价格区间", 3120), dc("¥10 ~ ¥300,000", 3120), dc("最低电梯屏 ~ 最高品牌墙", 3120)] }),
      new TableRow({ children: [dc("均价", 3120), dc("¥5,542", 3120), dc("8,371个有定价广告位均值", 3120)] }),
    ]
  }),
  empty(),
  bp("各线路价格：", { bold: true }),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [1560, 1560, 1560, 1560, 1560, 1560],
    rows: [
      new TableRow({ children: [hc("线路", 1560), hc("广告位数", 1560), hc("均价", 1560), hc("最高价", 1560), hc("总面积(m²)", 1560), hc("总价值", 1560)] }),
      new TableRow({ children: [dc("1号线", 1560, { bold: true }), dc("2,349", 1560), dc("¥5,548", 1560), dc("¥300,000", 1560, { color: RED }), dc("66,575", 1560), dc("¥13,031,000", 1560, { color: RED })] }),
      new TableRow({ children: [dc("2号线", 1560, { bold: true }), dc("1,374", 1560), dc("¥6,702", 1560), dc("¥175,000", 1560), dc("38,689", 1560), dc("¥9,206,000", 1560, { color: RED })] }),
      new TableRow({ children: [dc("3号线", 1560, { bold: true }), dc("2,150", 1560), dc("¥4,641", 1560), dc("¥140,000", 1560), dc("60,191", 1560), dc("¥9,980,000", 1560, { color: RED })] }),
      new TableRow({ children: [dc("4号线", 1560, { bold: true }), dc("1,524", 1560), dc("¥4,277", 1560), dc("¥125,000", 1560), dc("46,762", 1560), dc("¥6,517,000", 1560, { color: RED })] }),
      new TableRow({ children: [dc("5号线", 1560, { bold: true }), dc("1,638", 1560), dc("¥3,977", 1560), dc("¥125,000", 1560), dc("48,182", 1560), dc("¥6,514,000", 1560, { color: RED })] }),
      new TableRow({ children: [dc("2号线东延", 1560, { bold: true }), dc("425", 1560), dc("¥2,679", 1560), dc("¥50,000", 1560), dc("12,114", 1560), dc("¥1,138,000", 1560, { color: RED })] }),
    ]
  }),
  empty(),
  bp("最贵广告位 TOP 5：", { bold: true }),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [1800, 2500, 2500, 2560],
    rows: [
      new TableRow({ children: [hc("价格", 1800), hc("站点", 2500), hc("媒体形式", 2500), hc("位置", 2560)] }),
      new TableRow({ children: [dc("¥300,000", 1800, { bold: true, color: RED }), dc("朝阳广场站", 2500), dc("超视觉品牌墙", 2500), dc("1号线", 2560)] }),
      new TableRow({ children: [dc("¥250,000", 1800, { bold: true, color: RED }), dc("朝阳广场站", 2500), dc("超视觉品牌墙", 2500), dc("1号线", 2560)] }),
      new TableRow({ children: [dc("¥175,000", 1800, { bold: true, color: RED }), dc("亭洪路站", 2500), dc("超视觉品牌墙", 2500), dc("2号线", 2560)] }),
      new TableRow({ children: [dc("¥175,000", 1800, { bold: true, color: RED }), dc("亭洪路站", 2500), dc("超视觉品牌墙", 2500), dc("2号线", 2560)] }),
      new TableRow({ children: [dc("¥162,500", 1800, { bold: true, color: RED }), dc("明秀路站", 2500), dc("超视觉品牌墙", 2500), dc("2号线", 2560)] }),
    ]
  }),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 三、广告位布局图 =====
const s3 = sect();
s3.children.push(
  h1("三、广告位布局图"),
  bp("pointLocationName 字段暴露了每个广告位在站点内部的精确位置，包含出入口编号、轨行区方向、站厅/站台区域等。可据此反推出地铁站内完整的广告位施工级部署图。"),
  empty(),
  bp("站内位置分布统计：", { bold: true }),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [3120, 3120, 3120],
    rows: [
      new TableRow({ children: [hc("位置类型", 3120), hc("数量", 3120), hc("示例", 3120)] }),
      new TableRow({ children: [dc("站厅非付费区墙面", 3120, { bold: true }), dc("481", 3120), dc("站厅层公共区域墙面广告", 3120)] }),
      new TableRow({ children: [dc("轨行区上行/下行", 3120, { bold: true }), dc("2,458", 3120, { color: RED }), dc("轨行区上行（往科园/东站/西津/金桥/龙岗）+ 下行各方向", 3120)] }),
      new TableRow({ children: [dc("各出入口", 3120, { bold: true }), dc("1,905", 3120), dc("A口(402) B口(377) C口(436) D口(365) + 各口通道", 3120)] }),
      new TableRow({ children: [dc("站厅付费区", 3120, { bold: true }), dc("561", 3120), dc("付费区墙面(336) + 付费区(225)", 3120)] }),
      new TableRow({ children: [dc("站厅非付费区", 3120), dc("306", 3120), dc("非付费区公共空间", 3120)] }),
      new TableRow({ children: [dc("公交车队场站", 3120, { bold: true }), dc("1,197", 3120), dc("五一/安吉/高新/金桥/五象/竹溪/洪运/西乡塘/埌东/茅桥/武鸣/朝阳 共12个车队", 3120)] }),
    ]
  }),
  empty(),
  bp("这意味着攻击者可以准确知道：每个地铁站哪个出入口有什么类型的广告牌、轨行区哪个方向有多少灯箱、站厅付费区和非付费区各有多少广告位。配合广告位编号体系（如 17WXCJ1-UPC20），可精确定位到每一个广告位。"),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 四、排期数据字段全览 =====
const s4 = sect();
s4.children.push(
  h1("四、排期数据25个字段全览"),
  bp("每条广告位记录包含25个字段。以下列出所有敏感字段："),
  empty(),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [2400, 3800, 3160],
    rows: [
      new TableRow({ children: [hc("字段", 2400), hc("含义", 3800), hc("敏感度", 3160)] }),
      new TableRow({ children: [dc("mediaPrice", 2400, { bold: true, color: RED }), dc("媒体价格", 3800, { color: RED }), dc("🔴🔴🔴 核心商业机密", 3160, { bold: true, color: RED })] }),
      new TableRow({ children: [dc("productionPrice", 2400, { bold: true, color: RED }), dc("制作费用", 3800, { color: RED }), dc("🔴🔴 成本结构", 3160, { bold: true, color: ORANGE })] }),
      new TableRow({ children: [dc("pointLocationName", 2400, { bold: true, color: RED }), dc("站内具体位置（出入口/轨行区方向/墙面）", 3800, { color: RED }), dc("🔴🔴🔴 布局机密", 3160, { bold: true, color: RED })] }),
      new TableRow({ children: [dc("pointLevelName", 2400, { bold: true, color: RED }), dc("站点商业等级（S++/S+/S/A++/A+/旗舰级/AA+/AA/A）", 3800, { color: RED }), dc("🔴🔴 商业评级", 3160, { bold: true, color: ORANGE })] }),
      new TableRow({ children: [dc("length/width/area", 2400, { bold: true }), dc("广告位精确尺寸（长宽到厘米，面积到0.001m²）", 3800), dc("🔴 施工规格", 3160, { color: ORANGE })] }),
      new TableRow({ children: [dc("qrcode", 2400, { bold: true, color: RED }), dc("实景照片路径（129个广告位有图片）", 3800, { color: RED }), dc("🔴🔴 可拖图片", 3160, { bold: true, color: RED })] }),
      new TableRow({ children: [dc("number", 2400), dc("广告位内部编号（如17WXCJ1-UPC20）", 3800), dc("🟡 内部编码", 3160)] }),
      new TableRow({ children: [dc("lineId/lineName", 2400), dc("所属线路", 3800), dc("🟡", 3160)] }),
      new TableRow({ children: [dc("pointId/pointName", 2400), dc("站点名称", 3800), dc("🟡", 3160)] }),
      new TableRow({ children: [dc("mediaFormatName", 2400), dc("媒体形式（32种）", 3800), dc("🟡", 3160)] }),
      new TableRow({ children: [dc("assetScheduleStatus", 2400), dc("排期状态（全部=3）", 3800), dc("🟡", 3160)] }),
      new TableRow({ children: [dc("categoryId", 2400), dc("分类ID", 3800), dc("🟡", 3160)] }),
      new TableRow({ children: [dc("uniqueId", 2400), dc("{id}-null-null-3", 3800), dc("🟢 null=未出租", 3160, { color: "2E7D32" })] }),
    ]
  }),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 五、额外暴露的信息链 =====
const s5 = sect();
s5.children.push(
  h1("五、额外暴露的信息链"),
  bp("除广告位本身外，以下关联数据也被暴露："),
  empty(),
  h2("5.1 公交车牌与车队"),
  bp("1,527个公交车辆广告位包含199辆公交车的桂A牌照信息。按车队分布："),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [1170, 1170, 1170, 1170, 1170, 1170, 1170, 1170],
    rows: [
      new TableRow({ children: [hc("五一", 1170), hc("安吉", 1170), hc("高新", 1170), hc("金桥", 1170), hc("五象", 1170), hc("竹溪", 1170), hc("洪运", 1170), hc("西乡塘", 1170)] }),
      new TableRow({ children: [dc("180", 1170), dc("178", 1170), dc("170", 1170), dc("142", 1170), dc("136", 1170), dc("135", 1170), dc("131", 1170), dc("125", 1170)] }),
    ]
  }),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [1170, 1170, 1170, 1170, 1170, 1170, 1170, 1170],
    rows: [
      new TableRow({ children: [hc("埌东", 1170), hc("茅桥", 1170), hc("武鸣", 1170), hc("朝阳", 1170), hc("", 1170), hc("", 1170), hc("", 1170), hc("", 1170)] }),
      new TableRow({ children: [dc("118", 1170), dc("116", 1170), dc("114", 1170), dc("64", 1170), dc("", 1170), dc("", 1170), dc("", 1170), dc("", 1170)] }),
    ]
  }),
  empty(),
  h2("5.2 站点商业等级"),
  bp("532个站点均标注了商业等级，直接暴露了哪些站值钱、哪些不值钱的商业判断。三个旗舰级站点（万象城站、金湖广场站、朝阳广场站）为最高价值站点。"),
  empty(),
  h2("5.3 广告位利用状态"),
  bp("uniqueId 字段格式为 {id}-null-null-3，其中 null 代表该广告位当前未被任何广告商租用。12,162个广告位全部为 null 状态，说明整个平台库存完全空闲。"),
  empty(),
  h2("5.4 覆盖范围总结"),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [3120, 3120, 3120],
    rows: [
      new TableRow({ children: [hc("类别", 3120), hc("数量", 3120), hc("详情", 3120)] }),
      new TableRow({ children: [dc("地铁线路", 3120), dc("5条+1东延", 3120), dc("1/2/3/4/5号线+2号线东延线", 3120)] }),
      new TableRow({ children: [dc("地铁站点", 3120), dc("105个", 3120), dc("含等级标注（S++~A）", 3120)] }),
      new TableRow({ children: [dc("公交候车亭", 3120), dc("297个", 3120), dc("覆盖南宁主要街道", 3120)] }),
      new TableRow({ children: [dc("公交线路", 3120), dc("130条", 3120), dc("含BRT/快线/微循环/城际/响应式", 3120)] }),
      new TableRow({ children: [dc("公交车辆", 3120), dc("199辆", 3120, { color: RED }), dc("桂A牌照（193辆R系列+5辆F/G/D系列）", 3120, { color: RED })] }),
      new TableRow({ children: [dc("媒体形式", 3120), dc("32种", 3120), dc("十二封灯箱/品牌墙/LED屏/屏蔽门贴等", 3120)] }),
    ]
  }),
  empty(),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 六、敏感等级总表 =====
const s6 = sect();
s6.children.push(
  h1("六、敏感等级总表"),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [1400, 7960],
    rows: [
      new TableRow({ children: [hc("等级", 1400), hc("内容", 7960)] }),
      new TableRow({ children: [dc("🔴🔴🔴", 1400, { bold: true }), dc("全量定价表（¥72.7M）+ 站内精确位置布局 + 实景照片", 7960, { color: RED })] }),
      new TableRow({ children: [dc("🔴🔴", 1400, { bold: true }), dc("站点商业等级（S++~A）+ 199辆公交车牌及车队 + 制作成本结构", 7960, { color: ORANGE })] }),
      new TableRow({ children: [dc("🔴", 1400, { bold: true }), dc("广告位精确尺寸规格（厘米级）+ 各线路广告位分布", 7960, { color: ORANGE })] }),
      new TableRow({ children: [dc("🟡", 1400), dc("内部编号体系 + 32种媒体形式分类 + 字典配置数据", 7960)] }),
    ]
  }),
  empty(),
  bp("以上数据均通过以下端点在未授权情况下获取：", { bold: true }),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [4000, 5360],
    rows: [
      new TableRow({ children: [hc("端点", 4000), hc("泄露内容", 5360)] }),
      new TableRow({ children: [dc("POST /api/v1/product/assetSchedules/schedule/all", 4000, { color: RED }), dc("12,162条广告位全量数据（25个字段）", 5360)] }),
      new TableRow({ children: [dc("POST /api/v1/device/points/search", 4000, { color: RED }), dc("532个站点数据（含名称/线路/等级/运营时间）", 5360)] }),
      new TableRow({ children: [dc("GET /api/v1/main/dictionarys/tree", 4000), dc("完整数据字典（行业/等级/媒体形式/材质等）", 5360)] }),
      new TableRow({ children: [dc("GET /api/v1/partner/agents/{id}", 4000, { color: RED }), dc("代理方详情（含bcrypt密码哈希+手机号）", 5360)] }),
    ]
  }),
  empty(),
  bp("复核命令：", { bold: true }),
  new Paragraph({
    spacing: { after: 40, line: 280, lineRule: "auto" },
    indent: { left: 200 },
    shading: { fill: "F5F5F5", type: ShadingType.CLEAR },
    children: [new TextRun({ text: "curl -s -X POST 'https://adv-file.nn-cc.cn/api/v1/product/assetSchedules/schedule/all' -H \"Authorization: Bearer $TOKEN\" -H \"Content-Type: application/json\" -d '{}' | python3 -c \"import sys,json; d=json.load(sys.stdin); items=d.get('data',{}).get('list',[]); print(f'Total: {len(items)}'); prices=[i.get('mediaPrice',0) or 0 for i in items]; print(f'Price range: {min(prices)} - {max(prices)}'); print(f'Total value: {sum(prices)}')\"", font: "Courier New", size: 16, color: "333333" })]
  }),
  empty(),
  bp("— 报告完 —", { bold: true })
);

const doc = new Document({
  styles: {
    default: { document: { run: { font: "Arial", size: 21 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 32, bold: true, font: "Arial", color: DARK_BLUE }, paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 26, bold: true, font: "Arial", color: DARK_BLUE }, paragraph: { spacing: { before: 240, after: 160 }, outlineLevel: 1 } },
    ]
  },
  sections: [cover, s1, s2, s3, s4, s5, s6]
});

const out = process.argv[2] || "D:\\Desktop\\媒体资源平台_数据泄露报告.docx";
Packer.toBuffer(doc).then(buf => { fs.writeFileSync(out, buf); console.log("OK: " + out + " (" + buf.length + " bytes)"); }).catch(e => { console.error(e.message); process.exit(1); });
