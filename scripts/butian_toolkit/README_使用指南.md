# 补天目标提取小工具包使用指南

这个文件夹把当前补天“学院”等关键字目标提取流程用到的浏览器控制台脚本集中放在一起。它们只用于从已登录的补天页面提取厂商 ID 与提交页展示的主域名信息，不会访问这些学院/医院/厂商自己的业务站点。

## 文件说明

- `抓ID.js`

  在补天厂商列表页运行，用于抓取 `company_id` 和 `company_name`。现在默认就是自动低速模式：粘贴运行后会安装接口捕获、自动翻页、结束后自动导出 `butian_company_ids_captured_*.csv`。默认每页间隔 5000 毫秒，只点分页，不点“提交漏洞”。

- `清缓存.js`

  清理浏览器里这套脚本使用过的 `sessionStorage` 缓存。重新跑、跑错、遇到 quota exceeded、或怀疑读到了旧结果时，先运行它。

- `抓URL.js`

  读取上一步导出的 company_id CSV，然后在隐藏 iframe 里逐个打开补天 `/Loo/submit?cid=...` 提交页，提取页面上的“域名或ip”。建议先跑 10 条测试，确认结果正常后再跑全量；全量时建议延迟 5000 毫秒、超时 20000 毫秒。脚本现在只导出一个总目标文件：`butian_targets_for_runner_*.txt`，格式是 `URL|靶标名称`，可以直接拖给桌面的一键完整流程脚本使用。

- `报错提取已扫描URL.js`

  救援导出脚本。全量跑到一半如果浏览器报 `DOMException: The quota has been exceeded` 或下载没触发，先别刷新页面，运行它把已缓存结果导出。

## 推荐完整流程

1. 登录补天，打开厂商列表页，搜索你要的关键字，例如“学院”。

2. 打开浏览器开发者工具 Console，粘贴并运行 `抓ID.js`。

3. 等它自动低速翻页。默认最多翻 200 页、每页间隔 5000 毫秒；翻到没有下一页时会自动下载 `butian_company_ids_captured_*.csv`。

   如果想临时改参数，先在 Console 运行这一行，再粘贴脚本：

   ```javascript
   window.__BUTIAN_COMPANY_CAPTURE_CONFIG__ = { maxPages: 80, delayMs: 8000 };
   ```

   如果想恢复旧的手动选择菜单，先运行：

   ```javascript
   window.__BUTIAN_COMPANY_CAPTURE_CONFIG__ = { action: "ask" };
   ```

   自动运行中想停，Console 里运行：

   ```javascript
   __butianCompanyCaptureStop()
   ```

   想手动导出当前已捕获结果，运行：

   ```javascript
   __butianCompanyCaptureExport()
   ```

4. 粘贴并运行 `清缓存.js`，清掉旧缓存。

5. 粘贴并运行 `抓URL.js`。在页面出现的选择文件区域里，手动选择第 3 步导出的 company_id CSV。

6. 第一次建议测试数量填 `10`，延迟填 `5000`，超时填 `20000`。如果前 10 条能正确得到不同厂商的域名，再重新运行全量，数量填 `0`。

   如果中途已经跑到某个序号，例如第 95 条附近报错，重新运行时“从第几条开始”填 `96`，不用从头开始。

   新版脚本会询问“遇到几次 Geetest/风控错误后自动导出并暂停”，建议保持默认 `1`。这样遇到补天/极验网络或风控错误时，会先导出已抓到的结果再停，不会闷头继续冲。

   新版脚本还会询问“低内存模式：每多少条重建一次 iframe”，建议保持默认 `10`。如果浏览器已经出现过 `out of memory`，可以填 `5`。

7. 跑完后会下载一个 `butian_targets_for_runner_captured_*.txt`。这个文件已经是项目一键流程可直接使用的目标文件，不需要再转换 CSV。

## 常见问题

- “由于用户并未触发，已禁用 input 选择器”：浏览器限制脚本自动弹文件框。用脚本生成的页面按钮/选择文件控件手动点一下即可。

- `DOMException: The quota has been exceeded`：浏览器临时缓存满了。先运行 `报错提取已扫描URL.js` 导出已抓到的数据，再运行 `清缓存.js` 清缓存，随后从剩余位置继续。

- `GeetestError: /get.php请求报错`：这是补天页面加载极验组件时的网络/风控错误，不是目标域名的问题。脚本会下载 `butian_targets_for_runner_geetest_pause_*.txt`；等几分钟后重新运行 `抓URL.js`，起始序号填下一条，例如跑到 95 就填 `96`，延迟建议改成 `8000` 或 `10000`。

- `Uncaught out of memory`：这是浏览器标签页内存爆了，常见原因是 iframe 连续加载补天提交页、DevTools 控制台保留了大量对象、或者插件脚本也在页面里长期运行。先运行 `报错提取已扫描URL.js` 尝试导出缓存；如果日志到 258，就关闭这个补天标签页，重新打开补天页面，重新运行最新版脚本，从 `259` 开始，延迟建议 `10000`，低内存 iframe 重建填 `5` 或 `10`。

- 结果里很多 URL 重复或还是旧厂商：通常是旧缓存或页面读到了未切换完成的内容。先清缓存，再用最新的 iframe 脚本，并保持 5000 毫秒左右的间隔。

- 没有自动保存文件：浏览器可能拦截下载或页面被刷新。立刻用救援导出脚本 `报错提取已扫描URL.js`。

## 后续一键流程

拿到 `butian_targets_for_runner_*.txt` 后，可以直接拖到桌面一键流程脚本：

`D:\Desktop\一键完整流程_含弱口令.bat`

正式跑之前，继续保持低速率、只读验证、敏感信息最小化留证。

## 小提醒

不要把补天 Cookie、Authorization、X-Access-Token 等登录凭据发给我，也不要贴到报告里。需要我帮你处理时，给导出的 `butian_targets_for_runner_*.txt` 文件路径就够了。
