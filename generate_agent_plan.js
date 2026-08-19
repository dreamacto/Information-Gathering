const fs = require('fs');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, ShadingType, WidthType,
  PageBreak, Header, Footer, PageNumber
} = require('docx');

// 颜色
const BLUE = "1F4E79", GRAY = "555555", TXT = "333333", WHITE = "FFFFFF";
const RED = "C62828", ORANGE = "E65100", GREEN = "2E7D32";
const BORDER = "CCCCCC";
const border = { style: BorderStyle.SINGLE, size: 1, color: BORDER };
const cellBorders = { top: border, bottom: border, left: border, right: border };
const cellMargins = { top: 60, bottom: 60, left: 100, right: 100 };
const FONT = "微软雅黑";

function hc(text, w) {
  return new TableCell({
    borders: cellBorders, shading: { fill: BLUE, type: ShadingType.CLEAR },
    width: { size: w, type: WidthType.DXA }, margins: cellMargins,
    children: [new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text, bold: true, color: WHITE, size: 18, font: FONT })] })]
  });
}
function dc(text, w, o = {}) {
  return new TableCell({
    borders: cellBorders,
    width: { size: w, type: WidthType.DXA }, margins: cellMargins,
    shading: o.shading ? { fill: o.shading, type: ShadingType.CLEAR } : undefined,
    children: [new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text, bold: o.bold || false, color: o.color || TXT, size: 17, font: FONT })] })]
  });
}
function P(text, o = {}) {
  return new Paragraph({
    spacing: { after: 100, line: 320, lineRule: "auto" },
    children: [new TextRun({ text, bold: o.bold || false, color: o.color || TXT, size: o.size || 21, font: o.font || FONT })]
  });
}
function codeBlock(lines) {
  return lines.map(line => new Paragraph({
    spacing: { after: 30, line: 260, lineRule: "auto" },
    indent: { left: 200 },
    shading: { fill: "F5F5F5", type: ShadingType.CLEAR },
    children: [new TextRun({ text: line, font: "Consolas", size: 16, color: "333333" })]
  }));
}
function H1(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 280, after: 160 }, children: [new TextRun({ text, bold: true, size: 30, font: FONT, color: BLUE })] });
}
function H2(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 120 }, children: [new TextRun({ text, bold: true, size: 24, font: FONT, color: BLUE })] });
}
function empty() { return new Paragraph({ spacing: { after: 60 }, children: [] }); }

function sec() {
  return {
    properties: {
      page: { size: { width: 11906, height: 16838 }, margin: { top: 1300, right: 1300, bottom: 1300, left: 1300 } },
      headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: "AI 半自动挖洞提升上限完整方案", size: 16, font: FONT, color: "999999" })] })] }) },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "第 ", size: 16, font: FONT }), new TextRun({ children: [PageNumber.CURRENT], size: 16 }), new TextRun({ text: " 页", size: 16, font: FONT })] })] }) }
    },
    children: []
  };
}

// ===== 封面 =====
const cover = sec();
cover.properties.headers = {}; cover.properties.footers = {};
cover.children.push(
  empty(), empty(), empty(), empty(),
  new Paragraph({ spacing: { after: 200 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "AI 半自动挖洞提升上限", bold: true, size: 44, font: FONT, color: BLUE })] }),
  new Paragraph({ spacing: { after: 100 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "完整方案", bold: true, size: 44, font: FONT, color: BLUE })] }),
  empty(), empty(),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "从「给 AI 目标」到「带复利的闭环流水线」", size: 26, font: FONT, color: GRAY })] }),
  empty(), empty(), empty(),
  new Paragraph({ spacing: { after: 60 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "2026年8月", size: 22, font: FONT, color: GRAY })] }),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 一、项目现状 =====
const s1 = sec();
s1.children.push(
  H1("一、项目现状"),
  P("项目已经拥有非常完整的黑盒/灰盒流水线，这是很多人做不到的：", { bold: true }),
  P("21 个 phase（gov_exercise_workflow.json）：scope → subdomain → alive_probe → fingerprint → product_aware_triage → shiro/sqli/xss → crawl_api_js → wechat_miniapp_discovery → authenticated_session_review → weak_credential → healthcare → truth_verify → approval_gate → minimal_validation → report。"),
  P("统一调度器 vuln_dispatcher.py：40+ 指纹 → 90+ 工具映射（天狐 sqlmap/afrog/ez/rscan/shiro/fastjson 等）。"),
  P("专项 triage 脚本：shiro/fastjson/nacos/redis/springboot/struts2/tomcat/sqli/xss/second_pass。"),
  P("解包能力：full_unpack_wxapkg.py + analyze_js_static.py + analyze_wx_miniapp_source.py。"),
  P("指纹库 asset_fingerprint_lib.jsonl：3315 条。"),
  P("三个 skill：xcx（小程序）、wz（网站）、fh（run目录复核）。"),
  empty(),
  P("真正缺的只有 4 块：", { bold: true }),
  new Table({
    width: { size: 8806, type: WidthType.DXA }, columnWidths: [2600, 6206],
    rows: [
      new TableRow({ children: [hc("缺口", 2600), hc("证据", 6206)] }),
      new TableRow({ children: [dc("白盒源码审计", 2600, { bold: true }), dc("有解包+JS提取，但无 sink 定位/污点追踪/调用链（七大步骤第3/4/5步）", 6206)] }),
      new TableRow({ children: [dc("逻辑漏洞（竞态/条件竞争）", 2600, { bold: true }), dc("无任何 biz/race/logic/concurrent 相关脚本", 6206)] }),
      new TableRow({ children: [dc("水平/垂直越权", 2600, { bold: true }), dc("authenticated_session_review 只做未认证vs已认证对比，无多账户三请求对照", 6206)] }),
      new TableRow({ children: [dc("复利资产库", 2600, { bold: true }), dc("只有指纹库，无 sink 库/漏洞模式库/误报记忆库", 6206)] }),
    ]
  }),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 二、方案总览 =====
const s2 = sec();
s2.children.push(
  H1("二、方案总览"),
  P("方案分两个维度：维度A解决「怎么用 AI」，维度B解决「补什么能力」。两者都要做，缺一不可。"),
  empty(),
  new Table({
    width: { size: 8806, type: WidthType.DXA }, columnWidths: [4403, 4403],
    rows: [
      new TableRow({ children: [hc("维度 A：横切关注点", 4403), hc("维度 B：能力建设", 4403)] }),
      new TableRow({ children: [
        dc("A1. 给三个 skill 加「硬约束」（上下文预算）\nA2. subagent 隔离上下文（外部记忆）\nA3. SAST 底座 + 证据链（反幻觉）", 4403),
        dc("B1. 白盒源码审计\nB2. 逻辑漏洞（竞态/条件竞争）\nB3. 越权（水平/垂直）\nB4. 复利资产库", 4403)
      ] }),
    ]
  }),
  empty(),
  P("维度 A 解决你列的 agent 挖洞 4 个问题（上下文丢失/过载/误判/流程断裂）；维度 B 补齐七大步骤里缺失的第 3/4/5 步，以及逻辑漏洞和越权两大高频漏洞。", {}),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 三、维度A =====
const s3 = sec();
s3.children.push(
  H1("三、维度 A：横切关注点（解决 AI 好不好用）"),
  H2("A1. 给三个 skill 加「硬约束」"),
  P("解决：上下文丢失/过载/流程断裂。在 xcx/SKILL.md、wz/SKILL.md 顶部加（不是 workflow 建议，是最高优先级规则）："),
  codeBlock([
    "## 硬约束（不可违反）",
    "1. 每次只推进【一个 phase】，完成即落盘 work-dir，返回下一阶段指针。",
    "2. 单次只处理【一个 target】。",
    "3. 每次开始先读 phase_status.json，从【未完成的第一阶段】继续。",
    "4. 产物必须写 work-dir（CSV/JSONL），不得只存在对话上下文。",
    "5. 白盒审计必须先跑 SAST 定位 sink，禁止 AI 裸读整库源码。",
    "6. 禁止 AI 自动关闭告警，误报要 mark-fp 留痕。",
    "7. 越权检测必须「三请求对照」，严禁批量遍历。",
  ]),
  P("为什么能解决上下文丢失：AI 不再是「单轮做完七步」，而是「每次只做一步 + 落盘」，下次从落盘续。对话上下文永远不超过一个 phase 的量。"),
  empty(),
  H2("A2. subagent 隔离上下文"),
  P("解决：上下文过载、噪音占算力。用 Claude Code 的 Agent 工具（subagent），主进程只看到摘要，不看到过程："),
  codeBlock([
    "主进程（编排者）→ 只看到：目标清单 + phase_status.json + subagent 返回的摘要",
    "  ├─ Subagent-资产收集 → 返回 {存活数、指纹分布}",
    "  ├─ Subagent-白盒审计 → 返回 {sink数、候选数}",
    "  └─ Subagent-越权研判 → 返回 {越权候选数}",
  ]),
  P("每个 subagent 独立上下文，只做一件事，产物落盘，返回结构化摘要。主进程永远不会上下文爆炸。"),
  empty(),
  H2("A3. SAST 底座 + 证据链"),
  P("解决：误判、幻觉、压制真阳性。白盒审计不是「AI 裸读源码」（精度仅 22.6%），而是「Semgrep 定位 sink → AI 研判 → 证据链验证」。"),
  P("研究数据：LLM 从零发现漏洞精度只有 22.6%（75% 幻觉）；但 LLM 过滤告警会误杀真阳性（弱加密漏报 77%、弱哈希被压制 84.5%）。所以必须 SAST 做确定性底座 + 证据链约束 + 禁止 AI 自动关闭告警。"),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 四、维度B =====
const s4 = sec();
s4.children.push(
  H1("四、维度 B：四个能力补丁"),
  H2("B1. 白盒源码审计（补七大步骤第 3/4/5 步）"),
  P("已有的：full_unpack_wxapkg.py（解包）→ analyze_js_static.py（提取 API/密钥/sink）。"),
  P("缺的：把解包源码送进「危险 sink 定位 + 调用链追踪 + 源码校验」。"),
  P("新增文件 ①：knowledge_base/sink_lib.jsonl（危险函数特征库，7 大类）："),
  codeBlock([
    '{"sink_type":"sql_injection","patterns":["createQuery","MyBatis ${","+ sql +","executeQuery"],"lang":"java"}',
    '{"sink_type":"rce","patterns":["Runtime.exec","ProcessBuilder","eval(","os.system","JNDI"],"lang":"all"}',
    '{"sink_type":"ssrf","patterns":["requests.get(","URL.openConnection","httpClient.execute"],"lang":"all"}',
    '{"sink_type":"xxe","patterns":["DocumentBuilderFactory","XMLReader"],"lang":"java"}',
    '{"sink_type":"deserialization","patterns":["readObject","parseObject","enableDefaultTyping"],"lang":"java"}',
    '{"sink_type":"path_traversal","patterns":["new File(","../","getCanonicalPath"],"lang":"all"}',
    '{"sink_type":"ssti","patterns":["render(","TemplateEngine","evaluate("],"lang":"all"}',
  ]),
  P("新增文件 ②：whitebox_audit.py（对标 sqli_triage.py 的结构）："),
  codeBlock([
    "输入：解包源码目录（unpacked/<appid>/）+ sink_lib.jsonl",
    "步骤：",
    "  1. 遍历源码文件，用 sink_lib 正则定位危险函数调用点",
    "     → 输出 sinks.jsonl {文件、行号、sink类型、代码片段}",
    "  2. 对每个 sink，提取上下文（前后 5 行），交给 AI 研判",
    "     → 参数是否用户可控？有无 sanitizer？业务是否可达？",
    "  3. 证据链：用 grep/LSP 追调用链，确认 source→sink 完整路径",
    "输出：whitebox_candidates.jsonl（含 sink、source、证据链、判断）",
  ]),
  P("在 gov_exercise_workflow.json 加 phase（挂在 wechat_miniapp_discovery 之后）："),
  codeBlock([
    '{"id":"whitebox_audit","title":"白盒源码审计","risk":"none","auto":true,',
    ' "tools":["whitebox_audit.py","semgrep","sink_lib.jsonl"],',
    ' "outputs":["sinks.jsonl","whitebox_candidates.jsonl"]}',
  ]),
  empty(),
  H2("B2. 逻辑漏洞（竞态/条件竞争）"),
  P("已有的：sqli_triage.py 的成熟结构（候选→探测→证据→输出）。缺的：完全没有竞态检测。"),
  P("新增 biz_race_triage.py（照抄 sqli_triage 结构）："),
  codeBlock([
    "输入：一个端点 + 请求(curl格式) + 业务假设（如「优惠券只能核销一次」）",
    "执行：",
    "  1. AI 从源码/流量提取业务规则，识别 check-then-act 模式",
    "     （if(balance>=amount){deduct()} / if(stock>0){stock--} / if(!used){use()}）",
    "  2. 生成测试矩阵（并发下单/重复核销/并发提现）",
    "  3. threading.Barrier 同步并发 N 个请求（Barrier 才能同时到达）",
    "  4. 统计「多个 200/201 成功响应」= 疑似竞态",
    "判定：复现 3 次（新状态），确认后进 fh skill 复核",
    "输出：biz_race_candidates.jsonl（含并发数、成功次数、响应证据）",
  ]),
  P("关键：高精度竞态用 Turbo Intruder 单包攻击 / HTTP/2 single-packet（20-30 请求放同一 TCP 包），低精度用 Barrier 并发。脚本里两种都要支持。"),
  empty(),
  H2("B3. 越权（水平/垂直）"),
  P("已有的：authenticated_session_review.py 的 unauthenticated_baseline 对比逻辑。缺的：只做「未认证 vs 已认证」（未授权访问），没做「账户A vs 账户B」（水平越权）和「普通用户 vs 管理员」（垂直越权）。"),
  P("新增 idor_triage.py（多账户三请求对照）："),
  codeBlock([
    "核心：多账户三请求对照",
    "  1. 多账户会话：≥2 个同权限账户（水平）+ ≥2 个不同权限账户（垂直）",
    "     （衔接 credential_spray.py / weak_passwd_scanner.py 拿多账户）",
    "  2. 敏感参数识别：id/user_id/uid/order_id/file_id + 值模式",
    "  3. 三请求对照：",
    "     基线请求（账户A访问自己资源）→ 记录响应",
    "     越权请求（账户A换成账户B的ID）→ 对比响应",
    "     移除凭证请求 → 区分「公开资源」vs「真越权」",
    "  4. 误报过滤：状态码、响应长度差异阈值(<5%)、内容相似度、关键词黑名单",
    "输出：idor_candidates.jsonl",
  ]),
  empty(),
  H2("B4. 复利资产库"),
  P("已有的：asset_fingerprint_lib.jsonl（指纹库，3315 条）。缺的：sink 库、漏洞模式库、误报记忆库。"),
  codeBlock([
    "knowledge_base/",
    "  ├── sink_lib.jsonl           # 危险函数特征（B1用）",
    "  ├── vuln_pattern_lib.jsonl   # 确认的漏洞→可复用测试方法",
    "  ├── biz_rule_lib.jsonl       # 支付/优惠券/状态机→测试矩阵模板",
    "  └── fp_memory.jsonl          # 误报记录（mark-fp）",
    "",
    "闭环：每次 fh skill 复核完，把 confirmed/rejected 沉淀进资产库",
  ]),
  P("复利效果：sink 库让白盒审计越来越准；vuln_pattern_lib 让同类漏洞直接套用上次测试方法；fp_memory 让误报越来越少。这是普通 AI 使用者（每次冷启动）做不到的。"),
  new Paragraph({ children: [new PageBreak()] })
);

// ===== 五、落地顺序 =====
const s5 = sec();
s5.children.push(
  H1("五、落地顺序"),
  new Table({
    width: { size: 8806, type: WidthType.DXA }, columnWidths: [700, 3200, 800, 2600, 1506],
    rows: [
      new TableRow({ children: [hc("顺序", 700), hc("做什么", 3200), hc("维度", 800), hc("解决什么", 2600), hc("耗时", 1506)] }),
      new TableRow({ children: [dc("1", 700), dc("给 xcx/wz 加硬约束", 3200), dc("A1", 800), dc("上下文丢失", 2600), dc("1小时", 1506)] }),
      new TableRow({ children: [dc("2", 700), dc("建 sink_lib + whitebox_audit.py", 3200), dc("B1", 800), dc("白盒深度", 2600), dc("1-2天", 1506)] }),
      new TableRow({ children: [dc("3", 700), dc("写 biz_race_triage.py", 3200), dc("B2", 800), dc("逻辑漏洞", 2600), dc("1-2天", 1506)] }),
      new TableRow({ children: [dc("4", 700), dc("写 idor_triage.py", 3200), dc("B3", 800), dc("越权", 2600), dc("1-2天", 1506)] }),
      new TableRow({ children: [dc("5", 700), dc("建 knowledge_base 闭环", 3200), dc("B4", 800), dc("复利", 2600), dc("持续", 1506)] }),
    ]
  }),
  empty(),
  P("为什么 A1 先做：它决定了后面所有 skill 的 AI 好不好用——不加硬约束，AI 还是单轮做完七步，上下文照样丢。", { bold: true }),
  empty(),
  P("核心思想：拉开差距的不是「让 AI 扫更多目标」，而是把 AI 从「端到端渗透者」降级成「确定性分析引擎」，把挖洞每一步沉淀成可复用资产——让文件系统当记忆、SAST 当底座、subagent 隔离上下文、证据链当护栏、资产库当复利。", { bold: true, color: BLUE })
);

// ===== 生成文档 =====
const doc = new Document({
  styles: {
    default: { document: { run: { font: FONT, size: 21 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 30, bold: true, font: FONT, color: BLUE },
        paragraph: { spacing: { before: 280, after: 160 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 24, bold: true, font: FONT, color: BLUE },
        paragraph: { spacing: { before: 200, after: 120 }, outlineLevel: 1 } },
    ]
  },
  sections: [cover, s1, s2, s3, s4, s5]
});

const out = "D:\\Desktop\\AI半自动挖洞提升上限完整方案.docx";
Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync(out, buf);
  console.log("OK: " + out + " (" + buf.length + " bytes)");
}).catch(e => { console.error(e.message); process.exit(1); });
