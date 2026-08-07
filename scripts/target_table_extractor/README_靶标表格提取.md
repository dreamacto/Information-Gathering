# 靶标表格批量提取说明

这个工具用于提取“靶标名称 / 防守单位 / 所属单位 / 靶标 IP / 靶标域名 / 靶标 URL”这类分页表格。它只读取当前登录页面里已经展示的表格，并低速点击分页“下一页”，不会访问靶标 URL，也不会导出 Cookie、Token 或登录信息。

## 使用方法

1. 登录平台，打开靶标列表页。

2. 先把每页条数调到页面允许的最大值，例如截图里是 `20 条/页`。

3. 打开浏览器开发者工具 Console，粘贴运行：

   `scripts/target_table_extractor/target_table_auto_extract_console.js`

4. 等它自动翻页。截图里显示共 `863` 条、每页 `20` 条，大约是 `44` 页。默认最多翻 `80` 页，足够覆盖。

5. 完成后会下载：

   - `target_table_part_*.csv`：分片文件；
   - `target_table_captured_*.csv`：最终总表。

如果你之前已经跑出过只有 `1` 条的坏 CSV，直接复制新版脚本重跑即可。新版使用了新的缓存键，通常不会继续吃旧缓存；如果仍提示缓存，输入 `0` 清空重来。

如果新版能抓第一页 `20` 条，但没有自动翻第 2 页，说明页面分页控件结构比较特殊。此时先不要刷新，直接在 Console 运行：

```javascript
__targetTableDebugPagination()
```

然后把打印出来的表格截图或复制给我，我就能按真实分页控件继续补。

## 如果想调慢

先在 Console 运行这一行，再粘贴脚本：

```javascript
window.__TARGET_TABLE_EXTRACT_CONFIG__ = { maxPages: 60, delayMs: 3000, partEveryPages: 10 };
```

## 运行中控制

停止：

```javascript
__targetTableStop()
```

手动导出当前缓存：

```javascript
__targetTableExport()
```

清空缓存重来：

```javascript
__targetTableClear()
```

打印分页控件诊断：

```javascript
__targetTableDebugPagination()
```

## 如果失败，需要给我的信息

如果脚本只提取第一页、没有自动翻页，或者 CSV 里字段缺失，把下面任意一种信息给我即可：

1. 当前页面 URL，不需要 Cookie；
2. Console 里的 `[target-table]` 日志；
3. 下载出来的 CSV；
4. Network 里列表接口的一条响应 JSON，注意不要给 Cookie/Authorization；
5. 如果你愿意，也可以把页面 HTML 另存为文件给我。

如果能拿到列表接口响应，我可以再给你改成“接口直拉版”，速度更稳，也不需要模拟翻页。
