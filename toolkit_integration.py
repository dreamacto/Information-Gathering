#!/usr/bin/env python3
"""
天狐工具箱统一集成模块 v3.0
  封装 90+ 可用工具，提供统一调用接口。
  所有路径从 config.py 统一管理,不再硬编码。

  工具类型: exe / jar / python / ps1 / bat / gui
  调用方式: subprocess 子进程
"""

import os
import subprocess
import sys
import time

from config import (
    BASE_DIR, TIANHU_BASE, TIANHU_GUI_SCAN, TIANHU_GUI_SHOUJI, TIANHU_GUI_OTHER,
    PYTHON_EXE, JAVA_CMD, TOOL_TIMEOUT_SHORT, TOOL_TIMEOUT_LONG,
    tool_path, tool_exists,
)

# 确保 config 路径可用
sys.path.insert(0, BASE_DIR)

# ==================== 工具注册表（90+ 工具） ====================
# 格式: "name": { type, path, desc, args, timeout }
# args 中用 {url} {host} {file} {port} 作为占位符

REGISTRY = {

    # ===== 指纹识别 (6) =====
    "ehole": {
        "type": "exe", "path": tool_path("ehole"),
        "desc": "EHole 指纹识别（魔改版）",
        "args": ["finger", "-u", "{url}"], "timeout": 60,
    },
    "tidefinger": {
        "type": "exe", "path": tool_path("tidefinger"),
        "desc": "潮汐指纹识别 v3.2.3",
        "args": ["-u", "{url}"], "timeout": 60,
    },
    "p1finger": {
        "type": "exe", "path": tool_path("p1finger"),
        "desc": "P1finger 指纹识别",
        "args": ["-u", "{url}"], "timeout": 60,
    },
    "veo": {
        "type": "exe", "path": tool_path("veo"),
        "desc": "VEO 指纹识别",
        "args": ["-u", "{url}"], "timeout": 60,
    },
    "mfinger": {
        "type": "exe", "path": tool_path("mfinger"),
        "desc": "MFinder 资产测绘指纹",
        "args": ["-u", "{url}"], "timeout": 60,
    },
    "appinfo": {
        "type": "python", "path": tool_path("appinfo"),
        "desc": "应用信息识别（CMS/框架/中间件）",
        "args": ["-u", "{url}"], "timeout": 60,
    },

    # ===== 综合漏洞扫描 (13) =====
    "afrog": {
        "type": "exe", "path": tool_path("afrog"),
        "desc": "afrog POC快速扫描",
        "args": ["-t", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "xray": {
        "type": "exe", "path": tool_path("xray"),
        "desc": "xray 被动漏洞扫描",
        "args": ["webscan", "--url", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "rscan": {
        "type": "exe", "path": tool_path("rscan"),
        "desc": "Rscan 漏洞扫描器",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "ez": {
        "type": "exe", "path": tool_path("ez"),
        "desc": "EZ 新一代综合扫描器",
        "args": ["web", "--url", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "xscan": {
        "type": "exe", "path": tool_path("xscan"),
        "desc": "Xscan 多协议漏洞扫描",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "tscanplus": {
        "type": "exe", "path": tool_path("tscanplus"),
        "desc": "TscanPlus 综合扫描器",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "pppscan": {
        "type": "exe", "path": tool_path("pppscan"),
        "desc": "PPPScan 漏洞扫描",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "myexploit": {
        "type": "jar", "path": tool_path("myexploit"),
        "desc": "MYExploit 多产品漏洞利用",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "iwannagetall": {
        "type": "jar", "path": tool_path("iwannagetall"),
        "desc": "IWannaGetAll 多产品漏洞综合检测",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "team_0x7e": {
        "type": "jar", "path": tool_path("team_0x7e"),
        "desc": "0x7eTeamTools 团队工具集",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "poc2jar": {
        "type": "jar", "path": tool_path("poc2jar"),
        "desc": "Poc2jar POC批量验证",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "mitan": {
        "type": "jar", "path": tool_path("mitan"),
        "desc": "密探渗透测试工具",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "liqun": {
        "type": "jar", "path": tool_path("liqun"),
        "desc": "Liqun工具箱 1.6.2",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "serein": {
        "type": "python", "path": tool_path("serein"),
        "desc": "Serein Python漏扫",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "sqlmap": {
        "type": "python", "path": tool_path("sqlmap"),
        "desc": "SQLMAP X Plus（天狐集成版）",
        "args": ["-u", "{url}", "--batch", "--random-agent", "--level", "2"],
        "timeout": TOOL_TIMEOUT_LONG,
    },

    # ===== 框架漏洞 (18) =====
    "shiro": {
        "type": "jar", "path": tool_path("shiro"),
        "desc": "Apache Shiro RememberMe 反序列化 v4.7.0",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "shiro2": {
        "type": "jar", "path": tool_path("shiro2"),
        "desc": "Pyke-Shiro 另一款Shiro检测",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "fastjson": {
        "type": "exe", "path": tool_path("fastjson"),
        "desc": "Fastjson 检测利用 (JsonExp)",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "fastjson_jar": {
        "type": "jar", "path": tool_path("fastjson_jar"),
        "desc": "FastJson/Jackson 反序列化 (JAR版)",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "jndi": {
        "type": "jar", "path": tool_path("jndi"),
        "desc": "JNDI/Log4j 注入 v2.0",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "weblogic": {
        "type": "jar", "path": tool_path("weblogic"),
        "desc": "Oracle WebLogic Tool v1.3",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "jboss": {
        "type": "jar", "path": tool_path("jboss"),
        "desc": "JBoss AS 反序列化",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "struts2_19": {
        "type": "jar", "path": tool_path("struts2_19"),
        "desc": "Struts2 全版本漏洞检测 (S2-001~S2-062)",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "struts2_hyacinth": {
        "type": "jar", "path": tool_path("struts2_hyacinth"),
        "desc": "Hyacinth Java框架综合漏洞检测",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "jenkins": {
        "type": "jar", "path": tool_path("jenkins"),
        "desc": "Jenkins 未授权/命令执行 GUI v1.3",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "xxljob": {
        "type": "jar", "path": tool_path("xxljob"),
        "desc": "XXL-JOB 未授权/RCE 综合 v1.5",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "nacos": {
        "type": "jar", "path": tool_path("nacos"),
        "desc": "Nacos 未授权/漏洞综合 v3.0.5",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "jeecg": {
        "type": "jar", "path": tool_path("jeecg"),
        "desc": "Jeecg 系列综合利用",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "thinkphp_gui": {
        "type": "jar", "path": tool_path("thinkphp_gui"),
        "desc": "ThinkPHP 全版本漏洞利用 GUI版",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "thinkphp_killer": {
        "type": "jar", "path": tool_path("thinkphp_killer"),
        "desc": "ThinkPHP Killer 另一款利用工具",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "springboot_scan": {
        "type": "python", "path": tool_path("springboot_scan"),
        "desc": "Spring Boot Actuator 信息泄露扫描",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "springboot_gui": {
        "type": "jar", "path": tool_path("springboot_gui"),
        "desc": "SpringBootVul-GUI 综合漏洞检测",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "docker_api": {
        "type": "jar", "path": tool_path("docker_api"),
        "desc": "Docker API 未授权利用 v0.1",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },

    # ===== OA漏洞 (1) =====
    "oa_tools": {
        "type": "jar", "path": tool_path("oa_tools"),
        "desc": "OA-Tools 泛微/致远/通达/蓝凌综合 v1.3.1 (需JavaFX,手动运行)",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },

    # ===== RuoYi (2) =====
    "ruoyi": {
        "type": "jar", "path": tool_path("ruoyi"),
        "desc": "RuoYi 框架漏洞（Druid/任意文件/反序列化）",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "ruoyi_vue": {
        "type": "exe", "path": tool_path("ruoyi_vue"),
        "desc": "RuoYi-Vue 专项扫描 v7",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },

    # ===== 物联网/视频 (1) =====
    "hikvision": {
        "type": "exe", "path": tool_path("hikvision"),
        "desc": "海康威视综合漏洞利用",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },

    # ===== 数据库利用 (4) =====
    "mdut": {
        "type": "jar", "path": tool_path("mdut"),
        "desc": "MDUT 多数据库利用工具增强版",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "oracleshell": {
        "type": "jar", "path": tool_path("oracleshell"),
        "desc": "OracleShell Oracle 利用工具",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "postgresql": {
        "type": "jar", "path": tool_path("postgresql"),
        "desc": "PostgreSQL 一键利用工具",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "redis_exploit": {
        "type": "exe", "path": tool_path("redis"),
        "desc": "Redis Rogue Server 利用",
        "args": ["-h", "{host}"], "timeout": TOOL_TIMEOUT_SHORT,
    },

    # ===== Java 反序列化 =====
    "ysoserial": {
        "type": "jar",
        "path": os.path.join(TIANHU_GUI_SCAN, "yso", "ysoserial.jar"),
        "desc": "ysoserial Java反序列化利用工具",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },

    # ===== Spring/Java 辅助 =====
    "heapdump": {
        "type": "bat",
        "path": os.path.join(TIANHU_GUI_SCAN, "heapdump", "start1.bat"),
        "desc": "Spring Boot Heapdump 解密工具",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },

    # ===== 弱口令爆破 (1) =====
    "jubilant_wolf": {
        "type": "exe", "path": tool_path("jubilant_wolf"),
        "desc": "JUBILANT-WOLF 多协议弱口令爆破 v2.0.1",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },

    # ===== 内网工具 (4) =====
    "fscan": {
        "type": "exe", "path": tool_path("fscan"),
        "desc": "Fscan V2.0 内网漏洞扫描（MS17010/CVE/弱口令）",
        "args": ["-h", "{host}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "kscan": {
        "type": "exe", "path": tool_path("kscan"),
        "desc": "Kscan 1.85 内网资产扫描",
        "args": ["-h", "{host}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "ladon_gui": {
        "type": "exe", "path": tool_path("ladon_gui"),
        "desc": "Ladon GUI 内网渗透工具集",
        "args": [], "timeout": TOOL_TIMEOUT_LONG,
    },
    "goexec": {
        "type": "exe", "path": tool_path("goexec"),
        "desc": "GoExec 内网命令执行 v0.3.0",
        "args": ["-h", "{host}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "suo5": {
        "type": "exe", "path": tool_path("suo5"),
        "desc": "suo5 全双工HTTP隧道",
        "args": [], "timeout": TOOL_TIMEOUT_LONG,
    },

    # ===== 信息收集 (5) =====
    "oneforall": {
        "type": "python", "path": tool_path("oneforall"),
        "desc": "OneForAll 子域名收集",
        "args": ["--target", "{domain}", "run"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "golin": {
        "type": "exe", "path": tool_path("golin"),
        "desc": "GOlin 等保核查+资产发现",
        "args": ["web", "--url", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "goon": {
        "type": "exe", "path": tool_path("goon"),
        "desc": "goon 扫描探测爆破工具集 v3",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "httpx": {
        "type": "exe", "path": tool_path("httpx"),
        "desc": "Httpx HTTP探针（快速存活检测）",
        "args": ["-u", "{url}"], "timeout": 30,
    },
    "enscan": {
        "type": "exe", "path": tool_path("enscan"),
        "desc": "ENScan 企业信息收集 v2.0.4",
        "args": ["-k", "{domain}"], "timeout": 120,
    },

    # ===== 前端/源码分析 (4) =====
    "packerfuzzer": {
        "type": "python", "path": tool_path("packerfuzzer"),
        "desc": "PackerFuzzer Webpack/JS 源码泄露扫描",
        "args": ["--url", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "vuescan": {
        "type": "gui", "path": tool_path("vuescan"),
        "desc": "Vue.js 前端路由/组件扫描 (GUI工具, 需手动操作)",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "seay_svn": {
        "type": "exe", "path": tool_path("seay_svn"),
        "desc": "Seay SVN 源代码泄露利用",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "webcrack": {
        "type": "exe", "path": tool_path("webcrack"),
        "desc": "WebCrack 网页资产分析+爆破",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },

    # ===== 云安全 (3) =====
    "aksk": {
        "type": "bat", "path": tool_path("aksk"),
        "desc": "AK/SK 云凭证利用工具",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "cf": {
        "type": "exe", "path": tool_path("cf"),
        "desc": "CF 云平台后续利用（AK/SK后渗透）",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "cloud_asset": {
        "type": "exe", "path": tool_path("cloud_asset"),
        "desc": "云资产管理工具",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },

    # ===== API 工具 (2) =====
    "api_tool": {
        "type": "jar", "path": tool_path("api_tool"),
        "desc": "API-T00L API渗透利用 v1.2",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "api_explorer": {
        "type": "exe", "path": tool_path("api_explorer"),
        "desc": "API-Explorer API接管利用 v1.0.1",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },

    # ===== 后利用 (5) =====
    "webshell_gen": {
        "type": "jar", "path": tool_path("webshell_gen"),
        "desc": "Webshell 生成器 v1.2.4",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "xg_ntai": {
        "type": "jar", "path": tool_path("xg_ntai"),
        "desc": "XG 拟态 Webshell 免杀工具",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "vcenter_kit": {
        "type": "python", "path": tool_path("vcenter_kit"),
        "desc": "vCenter 综合漏洞利用（CVE-2021-21972/21985/22005/CVE-2022-22954）",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "tiquan_linux": {
        "type": "python", "path": tool_path("tiquan_linux"),
        "desc": "Linux 一键提权探测工具",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "hengxiang": {
        "type": "jar", "path": tool_path("hengxiang"),
        "desc": "内网横向移动利用工具",
        "args": ["-h", "{host}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "request_template": {
        "type": "jar", "path": tool_path("request_template"),
        "desc": "HTTP 请求模板生成器",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },

    # ===== 目录扫描 (3) =====
    "dirsearch": {
        "type": "python", "path": tool_path("dirsearch"),
        "desc": "Dirsearch 目录爆破",
        "args": ["-u", "{url}", "-e", "*", "--random-agent"],
        "timeout": TOOL_TIMEOUT_LONG,
    },
    "yjdirscan": {
        "type": "exe", "path": tool_path("yjdirscan"),
        "desc": "御剑目录扫描 v2 珍藏版",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },
    "dirscan_java": {
        "type": "jar", "path": tool_path("dirscan_java"),
        "desc": "Java 目录扫描 v3.0",
        "args": ["-u", "{url}"], "timeout": TOOL_TIMEOUT_LONG,
    },

    # ===== 解密工具 (3) =====
    "decrypt": {
        "type": "jar", "path": tool_path("decrypt"),
        "desc": "DecryptTools 综合解密 v3.0",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "beryl": {
        "type": "exe", "path": tool_path("beryl"),
        "desc": "BerylEnigma 加密解密（非MD5）",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "md5_tool": {
        "type": "exe", "path": tool_path("md5"),
        "desc": "MD5 杂项加密解密",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },

    # ===== 免杀工具 (5) =====
    "aniya": {
        "type": "exe", "path": tool_path("aniya"),
        "desc": "AniYa-GUI 免杀框架",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "yanri": {
        "type": "exe", "path": tool_path("yanri"),
        "desc": "掩日红队免杀工具",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "foxbypass": {
        "type": "exe", "path": tool_path("foxbypass"),
        "desc": "FoxBypass 分离免杀 v1.0",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "heavenly": {
        "type": "exe", "path": tool_path("heavenly"),
        "desc": "HeavenlyBypassAV 免杀",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "maloader": {
        "type": "exe", "path": tool_path("maloader"),
        "desc": "MaLoader 免杀工具",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },

    # ===== 隧道/代理 (4) =====
    "suo5_gui": {
        "type": "exe", "path": tool_path("suo5_gui"),
        "desc": "suo5 全双工HTTP隧道 (GUI版)",
        "args": [], "timeout": TOOL_TIMEOUT_LONG,
    },
    "frp": {
        "type": "exe", "path": tool_path("frp"),
        "desc": "Frp 内网穿透客户端",
        "args": [], "timeout": TOOL_TIMEOUT_LONG,
    },
    "clash": {
        "type": "exe", "path": tool_path("clash"),
        "desc": "Clash 代理工具",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "v2ray": {
        "type": "exe", "path": tool_path("v2ray"),
        "desc": "V2Ray 代理工具",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },

    # ===== 其他 (5) =====
    "heapsk": {
        "type": "exe", "path": tool_path("heapsk"),
        "desc": "棱镜X 单兵作战系统",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "blue_team": {
        "type": "jar", "path": tool_path("blue_team"),
        "desc": "蓝队分析辅助工具箱",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "auxtools": {
        "type": "exe", "path": tool_path("auxtools"),
        "desc": "AuxTools 辅助工具集",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
    "potato": {
        "type": "jar", "path": tool_path("potato"),
        "desc": "PotatoTool v2.4（密码:potato520）",
        "args": [], "timeout": TOOL_TIMEOUT_SHORT,
    },
}


# ==================== 指纹→工具智能映射 ====================
FINGERPRINT_SCANNERS = {
    # Java 框架
    "shiro":       ["shiro", "shiro2"],
    "weblogic":    ["weblogic"],
    "jboss":       ["jboss"],
    "tomcat":      ["rscan", "struts2_hyacinth"],
    "struts2":     ["struts2_19", "struts2_hyacinth"],
    "spring":      ["springboot_scan", "springboot_gui"],
    "springboot":  ["springboot_scan", "springboot_gui"],
    "fastjson":    ["fastjson", "fastjson_jar"],
    "jackson":     ["fastjson_jar"],
    "log4j":       ["jndi"],
    "log4shell":   ["jndi"],
    "jndi":        ["jndi"],
    "nacos":       ["nacos"],
    "jeecg":       ["jeecg"],
    "jenkins":     ["jenkins"],
    "ruoyi":       ["ruoyi", "ruoyi_vue"],
    "xxl-job":     ["xxljob"],
    "xxljob":      ["xxljob"],
    "docker":      ["docker_api"],

    # PHP 框架
    "thinkphp":    ["thinkphp_gui", "thinkphp_killer"],
    "laravel":     ["rscan"],
    "yii":         ["rscan"],
    "wordpress":   ["rscan"],
    "joomla":      ["rscan"],
    "drupal":      ["rscan"],
    "dedecms":     ["rscan"],
    "moodle":      ["rscan"],

    # OA
    "weaver":      ["oa_tools"],
    "seeyon":      ["oa_tools"],
    "landray":     ["oa_tools"],
    "tongda":      ["oa_tools"],
    "泛微":         ["oa_tools"],
    "致远":         ["oa_tools"],
    "蓝凌":         ["oa_tools"],

    # 前端
    "vue":         [],
    "webpack":     ["packerfuzzer"],
    "react":       [],

    # 邮件/认证
    "coremail":    ["jubilant_wolf"],
    "phpmyadmin":  ["jubilant_wolf"],
    "jenkins":     ["jenkins", "jubilant_wolf"],

    # 虚拟化
    "vcenter":     ["vcenter_kit"],
    "vmware":      ["vcenter_kit"],

    # 数据库/缓存
    "redis":       ["redis_exploit"],
    "postgresql":  ["postgresql"],
    "postgre":     ["postgresql"],
    "oracle":      ["oracleshell"],
    "mysql":       ["sqlmap"],

    # 物联网
    "hikvision":   ["hikvision"],
    "海康":         ["hikvision"],
    "dahua":       ["hikvision"],

    # 云
    "aliyun":      ["aksk", "cf"],
    "aws":         ["aksk", "cf"],
    "azure":       ["aksk", "cf"],
    "tencent":     ["aksk", "cf"],

    # 中间件
    "iis":         ["xscan"],
    "apache":      ["rscan"],
    "nginx":       ["rscan"],
    "tomcat":      ["rscan", "jboss"],

    # 语言/技术栈
    "php":         ["sqlmap", "rscan", "serein"],
    "asp.net":     ["sqlmap", "rscan"],
    "aspx":        ["sqlmap", "rscan"],
    "jsp":         ["sqlmap", "shiro", "rscan"],
    "python":      ["rscan"],
}


def get_tools_for_fingerprint(fingerprint):
    """根据指纹返回推荐工具列表"""
    fp_lower = fingerprint.lower()
    tools = set()
    for key, scanners in FINGERPRINT_SCANNERS.items():
        if key in fp_lower:
            tools.update(scanners)
    return sorted(tools) if tools else ["rscan", "xscan"]  # 默认用通用扫描器


def run_tool(name, url=None, host=None, domain=None, port=None, timeout=None,
             extra_args=None):
    """运行单个工具，返回 (success, output)

    Args:
        name:        工具名（REGISTRY中的key）
        url:         目标URL
        host:        目标IP/主机
        domain:      目标域名
        port:        目标端口
        timeout:     超时（覆盖默认）
        extra_args:  额外参数列表
    """
    if name not in REGISTRY:
        return False, f"未知工具: {name}"

    cfg = REGISTRY[name]
    tool_type = cfg["type"]
    tool_path = cfg.get("path", "")
    tool_args = list(cfg.get("args", []))
    tool_timeout = timeout or cfg.get("timeout", TOOL_TIMEOUT_SHORT)

    if extra_args:
        tool_args.extend(extra_args)

    # 检查工具是否存在
    if tool_path and not os.path.isfile(tool_path):
        if tool_type == "ps1":
            pass  # PowerShell 脚本可能不显示为文件
        else:
            return False, f"工具不存在: {tool_path}"

    print(f"  [{name}] {cfg['desc']}")

    try:
        # 格式化参数中的占位符
        formatted_args = []
        for arg in tool_args:
            arg = arg.format(
                url=url or "",
                host=host or "",
                domain=domain or "",
                port=str(port) if port else "",
            )
            formatted_args.append(arg)

        # === EXE 工具 ===
        if tool_type == "exe":
            result = subprocess.run(
                [tool_path] + formatted_args,
                capture_output=True, text=True, timeout=tool_timeout,
                encoding="utf-8", errors="replace",
            )
            return True, _combine_output(result)

        # === JAR 工具 ===
        elif tool_type == "jar":
            result = subprocess.run(
                [JAVA_CMD, "-jar", tool_path] + formatted_args,
                capture_output=True, text=True, timeout=tool_timeout,
                encoding="utf-8", errors="replace",
            )
            return True, _combine_output(result)

        # === Python 脚本 ===
        elif tool_type == "python":
            result = subprocess.run(
                [PYTHON_EXE, "-u", tool_path] + formatted_args,
                capture_output=True, text=True, timeout=tool_timeout,
                encoding="utf-8", errors="replace",
            )
            return True, _combine_output(result)

        # === PowerShell 脚本 ===
        elif tool_type == "ps1":
            result = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", tool_path] +
                formatted_args,
                capture_output=True, text=True, timeout=tool_timeout,
                encoding="utf-8", errors="replace",
            )
            return True, _combine_output(result)

        # === 批处理 ===
        elif tool_type == "bat":
            result = subprocess.run(
                [tool_path] + formatted_args,
                capture_output=True, text=True, timeout=tool_timeout,
                encoding="utf-8", errors="replace", shell=True,
            )
            return True, _combine_output(result)

        # === GUI 应用（不可自动化调用）===
        elif tool_type == "gui":
            return False, "GUI工具不支持命令行自动化调用"

        else:
            return False, f"未知工具类型: {tool_type}"

    except subprocess.TimeoutExpired:
        return False, f"超时 ({tool_timeout}s)"
    except FileNotFoundError as e:
        return False, f"依赖缺失: {e}"
    except Exception as e:
        return False, f"错误: {e}"


def _combine_output(result):
    """合并 stdout 和 stderr"""
    out = result.stdout or ""
    err = result.stderr or ""
    combined = (out + "\n" + err).strip()
    return combined[:8000] if len(combined) > 8000 else combined


def run_tools_batch(tool_names, url=None, host=None, domain=None):
    """批量运行多个工具，返回 {name: (success, output)}"""
    results = {}
    for name in tool_names:
        ok, out = run_tool(name, url=url, host=host, domain=domain)
        results[name] = (ok, out)
        if ok:
            print(f"    [+] {name} 完成")
        else:
            print(f"    [-] {name} 失败: {out}")
        time.sleep(2)  # 工具间延迟
    return results


def list_tools(category=None):
    """列出所有工具或按类别筛选"""
    if category:
        filtered = {k: v for k, v in REGISTRY.items()
                    if category.lower() in v.get("desc", "").lower()}
        for name, cfg in sorted(filtered.items()):
            exists = "✓" if os.path.isfile(cfg.get("path", "")) else "✗"
            print(f"  [{exists}] {name:25s} {cfg['desc']}")
    else:
        for name, cfg in sorted(REGISTRY.items()):
            exists = "✓" if os.path.isfile(cfg.get("path", "")) else "✗"
            print(f"  [{exists}] {name:25s} [{cfg['type']:6s}] {cfg['desc']}")


def list_fingerprint_mapping():
    """列出指纹→工具映射"""
    for fp, tools in sorted(FINGERPRINT_SCANNERS.items()):
        print(f"  {fp:20s} → {', '.join(tools) if tools else '(无)'}")


def get_available_tools():
    """获取所有可用（文件存在）的工具名列表"""
    available = []
    for name, cfg in REGISTRY.items():
        p = cfg.get("path", "")
        if p and os.path.isfile(p):
            available.append(name)
    return available


def get_tool_count():
    """统计可用/总数"""
    total = len(REGISTRY)
    avail = len(get_available_tools())
    return avail, total


# ==================== 命令行入口 ====================
if __name__ == "__main__":
    import argparse
    print(
        "[LEGACY WARNING] toolkit_integration.py is a raw tool wrapper. "
        "Prefer tool_assisted_triage.py or gov_exercise_runner.py for controlled workflows.",
        file=sys.stderr,
    )
    parser = argparse.ArgumentParser(description="天狐工具箱集成 v3.0")
    parser.add_argument("--list", action="store_true", help="列出所有工具")
    parser.add_argument("--list-cat", help="按类别筛选工具")
    parser.add_argument("--fingerprints", action="store_true", help="列出指纹映射")
    parser.add_argument("--stats", action="store_true", help="统计工具可用数")
    parser.add_argument("--tool", help="运行指定工具")
    parser.add_argument("--url", help="目标URL")
    parser.add_argument("--host", help="目标IP/主机")
    parser.add_argument("--domain", help="目标域名")
    parser.add_argument("--project", help="根据项目指纹自动选择")
    parser.add_argument("--batch", nargs="+", help="批量运行多个工具")
    args = parser.parse_args()

    if args.stats:
        avail, total = get_tool_count()
        print(f"工具总数: {total}, 可用: {avail}, 缺失: {total - avail}")
    elif args.list:
        list_tools(args.list_cat)
    elif args.fingerprints:
        list_fingerprint_mapping()
    elif args.batch and args.url:
        results = run_tools_batch(args.batch, url=args.url,
                                  host=args.host, domain=args.domain)
        ok_count = sum(1 for ok, _ in results.values() if ok)
        print(f"\n[+] 批量完成: {ok_count}/{len(results)} 成功")
    elif args.tool and (args.url or args.host):
        ok, out = run_tool(args.tool, url=args.url, host=args.host,
                          domain=args.domain)
        print(out if ok else f"[!] {out}")
    elif args.project:
        from pentest_utils import load_targets
        urls = load_targets(args.project)
        if urls:
            for url in urls[:10]:
                print(f"\n[*] {url[:90]}")
                tools = get_tools_for_fingerprint(url.lower())
                if tools:
                    print(f"    推荐工具: {', '.join(tools)}")
                    for t in tools[:3]:
                        ok, out = run_tool(t, url=url)
                        print(f"    -> {'OK' if ok else 'FAIL'}")
    else:
        parser.print_help()
