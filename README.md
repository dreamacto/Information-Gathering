# 攻防演练辅助项目入口

这个项目的定位是：把授权范围内的目标整理成低频、只读、证据友好的复核流程，帮你更快找到“值得人工确认”的接口泄露、越权、产品漏洞候选、弱口令入口和报告素材。

## 推荐入口

桌面批处理是最适合新手的一键入口：

- `D:\Desktop\一键保守全流程_尽量多信息_避WAF.bat`：推荐优先用。低频、信息收集更完整、尽量少触发 WAF。
- `D:\Desktop\一键完整流程_含弱口令.bat`：完整流程，包含显式弱口令复核。
- `D:\Desktop\一键已有子域名后流程_含弱口令.bat`：你已经有子域名文件时，从存活、指纹、接口、产品候选开始跑。
- `D:\Desktop\小程序Burp导入到最近一次流程.bat`：把你从 Burp 复制/导出的微信小程序后端 URL 导入最近一次流程。
- `D:\Desktop\启动浏览器XHR采集_本地复现版.bat`：需要浏览器里登录并采集接口时使用。

项目内主入口是：

```powershell
<python.exe> .\gov_exercise_runner.py --targets <目标文件> --probe --fingerprint --tool-fingerprint --high-value-paths --api-discovery --api-confirm --sqli-triage --shiro-triage --delay 3
```

跑完后先看：

```text
runs\<本轮目录>\00_重要_人工复核入口\README_先看这里.md
```

## 输出怎么读

- `00_重要_人工复核入口\01_需要你登录拿Cookie.md`：需要你手动登录/注册/拿 Cookie 的目标。
- `00_重要_人工复核入口\02_业务API只读复核队列.md`：最贴近接口泄露、越权、未授权访问的队列。
- `00_重要_人工复核入口\04B_产品漏洞候选队列.md`：Fastjson、Log4j、Struts2、Spring Boot、Nacos、ThinkPHP、泛微、致远、用友等候选，只排队不利用。
- `reports\screenshot_queue.md`：报告截图队列。
- `evidence\screenshots\截图队列_一键采集.bat`：只对公开页面做低频截图，不带 Cookie，不保存响应正文。
- `targets_with_auto_subdomains.txt`：子域名爆破结果和原目标自动合并后的下一轮目标文件。

## 子域名回流

完整流程会低频 DNS 爆破子域名。发现的同主域名候选不会在同一轮立刻 HTTP 探测，而是自动写入：

```text
runs\<本轮目录>\targets_with_auto_subdomains.txt
```

下一轮直接把这个文件拖给一键流程即可。

## 安全边界

- 默认只做低频、只读、元数据级检查。
- Cookie、Token、响应正文、敏感字段值不写入报告素材。
- 弱口令只有显式流程才会跑，并且低频、少量、遇到验证码/锁定/告警就停。
- 上传、SQLMap、RCE、反序列化、Shiro key 爆破、文件下载/导出、批量枚举、改删数据都需要演练规则明确允许后再单目标执行。
- 旧脚本很多是历史实验脚本，不建议作为主流程入口。先看 `LEGACY_UNSAFE_NOT_MAIN.md`。
