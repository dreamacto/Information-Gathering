// 攻击成果报告生成器
// 用法: node attack_report_gen.js "<json_file>"
const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
        Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
        ShadingType, PageNumber, PageBreak } = require('docx');

const args = process.argv.slice(2);
if (args.length < 1) { console.log('Usage: node attack_report_gen.js <findings.json>'); process.exit(1); }

const data = JSON.parse(fs.readFileSync(args[0], 'utf-8'));

const border = { style: BorderStyle.SINGLE, size: 1, color: '000000' };
const borders = { top: border, bottom: border, left: border, right: border };
const cellMargins = { top: 60, bottom: 60, left: 100, right: 100 };
const hdrShade = { fill: 'D9E2F3', type: ShadingType.CLEAR };

function hc(text, width) {
    return new TableCell({ borders, width: { size: width, type: WidthType.DXA }, margins: cellMargins, shading: hdrShade,
        children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [
            new TextRun({ text, bold: true, font: 'SimSun', size: 21 })
        ]})]
    });
}
function tc(text, width, opts = {}) {
    return new TableCell({ borders, width: { size: width, type: WidthType.DXA }, margins: cellMargins,
        children: [new Paragraph({ alignment: opts.center ? AlignmentType.CENTER : AlignmentType.LEFT, children: [
            new TextRun({ text: String(text), font: 'SimSun', size: 21, bold: opts.bold })
        ]})]
    });
}
function h1(text) { return new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text, font: 'SimHei', size: 32, bold: true })] }); }
function coverTitle(text) { return new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text, font: 'SimHei', size: 52, bold: true })] }); }
function h2(text) { return new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun({ text, font: 'SimHei', size: 28, bold: true })] }); }
function p(text) { return new Paragraph({ children: [new TextRun({ text, font: 'SimSun', size: 24 })] }); }
function indent(text) { return new Paragraph({ indent: { firstLine: 480 }, children: [new TextRun({ text, font: 'SimSun', size: 24 })] }); }
function ss() { return new Paragraph({ children: [new TextRun({ text: '【需截图】', font: 'SimSun', size: 24, color: 'FF0000', bold: true })] }); }

const children = [];

// === COVER ===
children.push(new Paragraph({ spacing: { before: 3600 } }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: '【' + (data.defender || '被攻击单位名称') + '】', font: 'SimHei', size: 36, bold: true })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: '攻防演习成果报告', font: 'SimHei', size: 52, bold: true })] }));
children.push(new Paragraph({ spacing: { before: 3600 } }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: '【' + (data.attacker || '观叶识微') + '】', font: 'SimSun', size: 28, bold: true })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: '2026年  ' + (data.month || '') + '月  ' + (data.day || '') + '日', font: 'SimSun', size: 28 })] }));
children.push(new Paragraph({ children: [new PageBreak()] }));

// === 1. 综述 ===
children.push(h1('1. 综述'));
children.push(indent('经过演习指挥部授权，' + (data.attacker || '【攻击方名称】') + '团队于2026年' + (data.month || '') + '月' + (data.day || '') + '日，对' + (data.defender || '【防守方名称】') + '单位进行了渗透评估，通过模拟真实网络攻击行为，评估系统是否存在可以被攻击者利用的漏洞以及由此引发的风险大小，为制定相应的安全措施与解决方案提供实际的依据。'));
children.push(p('渗透结果总结汇总如下表：'));

// Summary table
const summaryRows = [new TableRow({ children: [hc('渗透系统对象', 1600), hc('漏洞类型', 1600), hc('URL', 2500), hc('数量', 800), hc('网络区域', 1200), hc('申报分数', 1200)] })];
for (const f of data.findings || []) {
    summaryRows.push(new TableRow({ children: [
        tc(f.system || '', 1600), tc(f.vuln_type || '', 1600),
        tc(f.url || '', 2500, { size: 16 }), tc(String(f.count || 1), 800, { center: true }),
        tc(f.network || '外网', 1200, { center: true }), tc(String(f.score || 0), 1200, { center: true, bold: true })
    ]}));
}
children.push(new Table({ width: { size: 9300, type: WidthType.DXA }, columnWidths: [1600, 1600, 2500, 800, 1200, 1200], rows: summaryRows }));
children.push(new Paragraph({ children: [new PageBreak()] }));

// === 2. 渗透分析过程 ===
children.push(h1('2. 渗透分析过程'));
children.push(p('渗透路径说明'));
children.push(indent((data.attack_path || '互联网目标系统 → 发现漏洞 → 获取权限')));

// === 3. 渗透成果说明 ===
children.push(h1('3. 渗透成果说明'));

if (data.findings) {
    data.findings.forEach((f, idx) => {
        children.push(h2('3.' + (idx+1) + ' 成果' + (idx+1)));

        // (1) 成果目标基本情况
        children.push(p('（1）成果目标基本情况'));
        const infoTable = new Table({
            width: { size: 9300, type: WidthType.DXA },
            columnWidths: [2000, 7300],
            rows: [
                new TableRow({ children: [hc('序号', 2000), tc(String(idx+1), 7300)] }),
                new TableRow({ children: [hc('成果描述', 2000), tc(f.description || '', 7300)] }),
                new TableRow({ children: [hc('目标系统', 2000), tc(f.system || '', 7300)] }),
                new TableRow({ children: [hc('目标URL', 2000), tc(f.url || '', 7300)] }),
                new TableRow({ children: [hc('目标IP', 2000), tc(f.ip || '', 7300)] }),
                new TableRow({ children: [hc('内网系统', 2000), tc(f.is_internal ? '是' : '否', 7300)] }),
                new TableRow({ children: [hc('威胁类型', 2000), tc(f.threat_type || '', 7300)] }),
            ]
        });
        children.push(infoTable);

        // (2) 成果说明
        children.push(p('（2）成果说明  攻击过程描述：'));
        children.push(indent(f.process || ''));
        children.push(ss());  // Screenshot needed
        children.push(p('【截图内容：' + (f.screenshot_desc || '漏洞证明截图') + '】'));

        if (f.credentials) {
            children.push(p('获取的账号密码：' + f.credentials));
            children.push(ss());
        }
        if (f.webshell_path) {
            children.push(p('Webshell/工具路径：' + f.webshell_path));
            children.push(ss());
        }

        if (idx < data.findings.length - 1) {
            children.push(new Paragraph({ children: [new PageBreak()] }));
        }
    });
}

// === 4. 存在问题 ===
children.push(new Paragraph({ children: [new PageBreak()] }));
children.push(h1('4. 存在问题'));
children.push(indent((data.problems || '目标单位存在以下安全问题：')));

// === 5. 整改建议 ===
children.push(h1('5. 整改建议'));
children.push(indent((data.suggestions || '针对上述问题提出相应整改建议：')));

const doc = new Document({
    styles: {
        default: { document: { run: { font: 'SimSun', size: 24 } } },
        paragraphStyles: [
            { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
              run: { size: 36, bold: true, font: 'SimHei' }, paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 } },
            { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
              run: { size: 28, bold: true, font: 'SimHei' }, paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 1 } },
        ]
    },
    sections: [{
        properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } } },
        headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: '攻防演习成果报告', font: 'SimSun', size: 18, color: '999999' })] })] }) },
        footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'Page ', font: 'SimSun', size: 18 }), new TextRun({ children: [PageNumber.CURRENT], font: 'SimSun', size: 18 })] })] }) },
        children
    }]
});

const path = require('path');
const basename = path.basename(args[0], '.json');
const output = path.join('D:/Desktop/claude projects/攻防演练/attack', basename + '_报告.docx');
Packer.toBuffer(doc).then(buffer => {
    fs.writeFileSync(output, buffer);
    console.log('Generated: ' + output);
});
