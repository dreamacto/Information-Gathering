#!/usr/bin/env python3
# encoding: utf-8
"""
统一配置中心
  所有路径、常量、开关集中管理，其他脚本统一从此 import。
  不再需要在各个文件中硬编码天狐路径。
"""

import os
import sys

# ==================== 基础路径 ====================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 天狐渗透工具箱根目录
TIANHU_BASE = os.path.join(
    "D:/Desktop",
    "天狐渗透工具箱-社区版V3.0+4.0更新升级包",
    "天狐渗透工具箱-社区版V3.0"
)

# 天狐子目录
TIANHU_TOOLS      = os.path.join(TIANHU_BASE, "tools")
TIANHU_GUI_SCAN   = os.path.join(TIANHU_TOOLS, "gui_scan")
TIANHU_GUI_SHOUJI = os.path.join(TIANHU_TOOLS, "gui_shouji")
TIANHU_GUI_OTHER  = os.path.join(TIANHU_TOOLS, "gui_other")
TIANHU_GUI_WEBSHELL = os.path.join(TIANHU_TOOLS, "gui_webshell")
TIANHU_CONFIG     = os.path.join(TIANHU_BASE, "config")
TIANHU_PYTHON     = os.path.join(TIANHU_BASE, "python3", "python.exe")

# ==================== 项目路径 ====================
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")

# ==================== 运行时 ====================
PYTHON_EXE = sys.executable
JAVA_CMD   = "java"

# ==================== 扫描全局开关 ====================
DEFAULT_THREADS    = 10
DEFAULT_TIMEOUT    = 20
DEFAULT_DELAY      = 3       # 请求间延迟（秒，防封）
NUCLEI_TIMEOUT     = 30
TOOL_TIMEOUT_LONG  = 600     # 长耗时工具（SQL注入等）
TOOL_TIMEOUT_SHORT = 300     # 短耗时工具

# ==================== HTTP 配置 ====================
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# ==================== 天狐工具路径注册表 ====================
# 所有可直接命令行调用的工具路径，按类别整理
# 格式: "工具名": "完整路径"

T_指纹识别 = {
    "ehole":          os.path.join(TIANHU_GUI_SCAN, "ehole", "EHole_windows_amd64.exe"),
    "tidefinger":     os.path.join(TIANHU_GUI_SHOUJI, "tide", "TideFinger_windows_amd64_v3.2.3.exe"),
    "p1finger":       os.path.join(TIANHU_GUI_SCAN, "P1finger", "P1finger64.exe"),
    "veo":            os.path.join(TIANHU_GUI_OTHER, "veo", "veo.exe"),
    "mfinger":        os.path.join(TIANHU_GUI_SHOUJI, "fine", "MFinder_windows_amd64.exe"),
    "appinfo":        os.path.join(TIANHU_GUI_SCAN, "appinfo", "app.py"),
}

T_漏洞扫描 = {
    # 综合扫描器
    "nuclei":         os.path.join(TIANHU_GUI_SCAN, "nuclei", "nuclei.exe"),
    "afrog":          os.path.join(TIANHU_GUI_OTHER, "afrog", "afrog.exe"),
    "xray":           os.path.join(TIANHU_GUI_OTHER, "xray", "xray_windows_amd64.exe"),
    "rscan":          os.path.join(TIANHU_GUI_SCAN, "Rscan", "Rscan_win64.exe"),
    "ez":             os.path.join(TIANHU_GUI_SCAN, "ez", "ez.exe"),
    "xscan":          os.path.join(TIANHU_GUI_SCAN, "xscan", "xscan.exe"),
    "tscanplus":      os.path.join(TIANHU_GUI_SCAN, "tscanplus", "TscanPlus_Win_Amd64.exe"),
    "pppscan":        os.path.join(TIANHU_GUI_SCAN, "pppscan", "pppscan.exe"),
    # 综合漏洞利用
    "myexploit":      os.path.join(TIANHU_GUI_SCAN, "MYExploit-2.0.5-SNAPSHOT.jar"),
    "iwannagetall":   os.path.join(TIANHU_GUI_SCAN, "apt", "IWannaGetAll-vFinal.jar"),
    "team_0x7e":      os.path.join(TIANHU_GUI_SCAN, "0x7eTeamTools", "0x7e.jar"),
    "poc2jar":        os.path.join(TIANHU_GUI_SCAN, "poc2jar-WINDOWS", "poc2jar.jar"),
    "mitan":          os.path.join(TIANHU_GUI_SCAN, "mitan", "mitan-jar-with-dependencies.jar"),
    "liqun":          os.path.join(TIANHU_GUI_SCAN, "LiqunKit_1.5.1", "LiqunKit_1.6.2_交流版.jar"),
    "serein":         os.path.join(TIANHU_GUI_SCAN, "serein", "Serein.py"),
    # SQL注入
    "sqlmap":         os.path.join(TIANHU_GUI_SCAN, "sqlmap", "sqlmap.py"),
}

T_框架漏洞 = {
    # Java 框架
    "shiro":          os.path.join(TIANHU_GUI_SCAN, "shiro", "shiro", "shiro_attack-4.7.0-SNAPSHOT-all.jar"),
    "shiro2":         os.path.join(TIANHU_GUI_SCAN, "shiro", "shiro_attack2", "Pyke-Shiro_0.3.jar"),
    "fastjson":       os.path.join(TIANHU_GUI_SCAN, "json", "JsonExp.exe"),
    "fastjson_jar":   os.path.join(TIANHU_GUI_SCAN, "FastJson_JackSon", "FastJson_JackSon.jar"),
    "jndi":           os.path.join(TIANHU_GUI_SCAN, "jndi", "JNDIExploit-2.0-SNAPSHOT.jar"),
    "weblogic":       os.path.join(TIANHU_GUI_SCAN, "weblogic", "WeblogicTool_1.3.jar"),
    "jboss":          os.path.join(TIANHU_GUI_SCAN, "jboss", "JavaJboss.jar"),
    "struts2_19":     os.path.join(TIANHU_GUI_SCAN, "struts2", "struts2_19.jar"),
    "struts2_hyacinth": os.path.join(TIANHU_GUI_SCAN, "struts2", "hyacinth.jar"),
    "jenkins":        os.path.join(TIANHU_GUI_SCAN, "jenkins", "JenkinsExploit-GUI-1.3-SNAPSHOT.jar"),
    "xxljob":         os.path.join(TIANHU_GUI_SCAN, "xxljob", "XXL-JOB漏洞综合利用工具_1.5.jar"),
    "nacos":          os.path.join(TIANHU_GUI_SCAN, "nacos", "nacos-exploit-3.0.5-jar-with-dependencies.jar"),
    "jeecg":          os.path.join(TIANHU_GUI_SCAN, "jeecg", "jeecgExploitss.jar"),
    "docker_api":     os.path.join(TIANHU_GUI_SCAN, "docker", "DockerAPITool_v0.1.jar"),
    # PHP 框架
    "thinkphp_gui":   os.path.join(TIANHU_GUI_SCAN, "thinkphp", "ThinkphpGUI.jar"),
    "thinkphp_killer": os.path.join(TIANHU_GUI_SCAN, "thinkphp", "ThinkPHPKiller.jar"),
    # Spring
    "springboot_scan": os.path.join(TIANHU_GUI_SCAN, "spring", "SpringBoot-Scan.py"),
    "springboot_gui":  os.path.join(TIANHU_GUI_SCAN, "spring", "SpringBootVul-GUI", "SpringBootVul_GUI.jar"),
    # OA
    "oa_tools":       os.path.join(TIANHU_GUI_SCAN, "hvvoaexploit", "Exp-Tools-1.3.1-encrypted.jar"),
    # RuoYi
    "ruoyi":          os.path.join(TIANHU_GUI_SCAN, "Ruoyi-All-master", "ruoyiVuln.jar"),
    "ruoyi_vue":      os.path.join(TIANHU_GUI_SCAN, "Ruoyi-All-master", "ruoyitools", "RuoYiVueScan-v7.exe"),
    # 物联网/视频
    "hikvision":      os.path.join(TIANHU_GUI_SCAN, "hikvision", "hikvision.exe"),
}

T_数据库利用 = {
    "mdut":           os.path.join(TIANHU_GUI_SCAN, "mdut", "Multiple.Database.Utilization.Tools-2.1.1-Extend-1.2.0-T00ls-jar-with-dependencies.jar"),
    "oracleshell":    os.path.join(TIANHU_GUI_SCAN, "oracleShell.jar"),
    "postgresql":     os.path.join(TIANHU_GUI_SCAN, "postgre", "postgreUtil-1.0-SNAPSHOT-jar-with-dependencies.jar"),
    "redis":          os.path.join(TIANHU_GUI_SCAN, "redis-rogue-server", "redis.exe"),
}

T_弱口令爆破 = {
    "jubilant_wolf":  os.path.join(TIANHU_GUI_SCAN, "weekpasswd", "JUBILANT-WOLF-V2.0.1.exe"),
    "gorailgun":      os.path.join(TIANHU_GUI_OTHER, "gorailgun", "Railgun.exe"),
}

T_内网工具 = {
    "fscan":          os.path.join(TIANHU_GUI_SCAN, "fscan", "fscan.exe"),
    "kscan":          os.path.join(TIANHU_GUI_OTHER, "kscan", "kscan_windows_amd64.exe"),
    "ladon_gui":      os.path.join(TIANHU_GUI_OTHER, "ladon", "LadonGUI.exe"),
    "goexec":         os.path.join(TIANHU_GUI_OTHER, "goexec", "goexec_v0.3.0_windows_amd64", "goexec.exe"),
    "suo5":           os.path.join(TIANHU_GUI_OTHER, "suo5", "suo5-windows-amd64.exe"),
}

T_信息收集 = {
    "oneforall":      os.path.join(TIANHU_GUI_SHOUJI, "oneforall", "oneforall.py"),
    "golin":          os.path.join(TIANHU_GUI_SHOUJI, "golin", "golin.exe"),
    "goon":           os.path.join(TIANHU_GUI_SHOUJI, "goon", "goon3_win_amd64.exe"),
    "httpx":          os.path.join(TIANHU_GUI_SCAN, "fcke", "httpx.exe"),
    "enscan":         os.path.join(TIANHU_GUI_OTHER, "enscan", "enscan-v2.0.4-windows-amd64.exe"),
}

T_前端分析 = {
    "packerfuzzer":   os.path.join(TIANHU_GUI_SCAN, "webpackscan", "PackerFuzzer.py"),
    "vuescan":        os.path.join(TIANHU_GUI_SCAN, "vuescan", "vue_scan.exe"),
}

T_源码泄露 = {
    "seay_svn":       os.path.join(TIANHU_GUI_SCAN, "Seay-Svn源代码泄露漏洞利用工具.exe"),
    "webcrack":       os.path.join(TIANHU_GUI_SCAN, "WebCrack-master", "2024-03-14-0.1.2-win-x64.exe"),
}

T_云安全 = {
    "aksk":           os.path.join(TIANHU_GUI_SCAN, "aksk", "start.bat"),
    "cf":             os.path.join(TIANHU_GUI_SCAN, "cf", "cf.exe"),
    "cloud_asset":    os.path.join(TIANHU_GUI_SCAN, "WebCrack-master", "云资产管理工具.exe"),
}

T_API工具 = {
    "api_tool":       os.path.join(TIANHU_GUI_SCAN, "apitool", "API-T00L_v1.2.jar"),
    "api_explorer":   os.path.join(TIANHU_GUI_SCAN, "apitool", "API-Explorer_v1.0.1.exe"),
}

T_后利用 = {
    "webshell_gen":   os.path.join(TIANHU_GUI_OTHER, "webshellsc", "Webshell_Generate-1.2.4.jar"),
    "xg_ntai":        os.path.join(TIANHU_GUI_OTHER, "XG_NTAI_V2", "XG_NTAI.jar"),
    "vcenter_kit":    os.path.join(TIANHU_GUI_OTHER, "vcenterKit", "VcenterKit_PyQt6.py"),
    "tiquan_linux":   os.path.join(TIANHU_GUI_OTHER, "tiquan", "main.py"),
    "hengxiang":      os.path.join(TIANHU_GUI_OTHER, "hengxiang", "gogogo-jar-with-dependencies.jar"),
    "request_template": os.path.join(TIANHU_GUI_SCAN, "RequestTemplate", "RequestTemplate.jar"),
}

T_目录扫描 = {
    "dirsearch":      os.path.join(TIANHU_GUI_SCAN, "dirsearch", "dirsearch.py"),
    "yjdirscan":      os.path.join(TIANHU_GUI_SHOUJI, "yjdirscanv1.1", "御剑2.exe"),
    "dirscan_java":   os.path.join(TIANHU_GUI_SHOUJI, "dirscan_3.0", "scandir-3.0.jar"),
}

T_解密工具 = {
    "decrypt":        os.path.join(TIANHU_GUI_SCAN, "decrypt", "DecryptToolsV3.0.jar"),
    "beryl":          os.path.join(TIANHU_GUI_SCAN, "jiamijiemi", "BE-BerylEnigma.exe"),
    "md5":            os.path.join(TIANHU_GUI_SCAN, "md5", "MD5.exe"),
}

T_免杀工具 = {
    "aniya":          os.path.join(TIANHU_GUI_OTHER, "aniya", "AniYa.exe"),
    "yanri":          os.path.join(TIANHU_GUI_OTHER, "yanri", "yanri.exe"),
    "foxbypass":      os.path.join(TIANHU_GUI_OTHER, "foxbypass", "FoxBypass_V1.0.exe"),
    "heavenly":       os.path.join(TIANHU_GUI_OTHER, "rqed", "Heavenly.exe"),
    "maloader":       os.path.join(TIANHU_GUI_OTHER, "rustms", "app.exe"),
}

T_隧道代理 = {
    "suo5_gui":       os.path.join(TIANHU_GUI_OTHER, "suo5", "suo5-gui-windows.exe"),
    "frp":            os.path.join(TIANHU_GUI_OTHER, "frp", "Frpc-Desktop-1.2.4-win", "Frpc-Desktop.exe"),
    "v2ray":          os.path.join(TIANHU_GUI_OTHER, "v2ray", "v2rayN.exe"),
}

T_WebShell管理 = {
    "antsword":       os.path.join(TIANHU_GUI_WEBSHELL, "AntSword", "AntSword-Loader-v4.0.3-win32-x64", "AntSword.exe"),
    "tianxie":        os.path.join(TIANHU_GUI_WEBSHELL, "TianXie", "天蝎权限管理工具.jar"),
    "ether_ghost":    os.path.join(TIANHU_GUI_WEBSHELL, "yh", "ether_ghost_v0.2.2.exe"),
}

T_C2工具 = {
    "cs47":           os.path.join(TIANHU_GUI_OTHER, "Cobalt_Strike_4.7", "cobaltstrike-client.jar"),
    "counter_strike": os.path.join(TIANHU_GUI_OTHER, "Counter-Strike", "cs.jar"),
}

T_其他工具 = {
    "heapsk":         os.path.join(TIANHU_GUI_SCAN, "heartsk", "HeartsK.exe"),
    "blue_team":      os.path.join(TIANHU_GUI_OTHER, "blue", "BlueTeamTools.jar"),
    "auxtools":       os.path.join(TIANHU_GUI_OTHER, "auxtools", "Auxtools.exe"),
    "potato":         os.path.join(TIANHU_GUI_SCAN, "PotatoTool-2.4-jdk11+.jar"),
    "everything":     os.path.join(TIANHU_GUI_OTHER, "everything", "everything.exe"),
}

# ==================== 合并所有工具路径 ====================
ALL_TOOL_PATHS = {}
for _d in [
    T_指纹识别, T_漏洞扫描, T_框架漏洞, T_数据库利用, T_弱口令爆破,
    T_内网工具, T_信息收集, T_前端分析, T_源码泄露, T_云安全,
    T_API工具, T_后利用, T_目录扫描, T_解密工具, T_免杀工具,
    T_隧道代理, T_WebShell管理, T_C2工具, T_其他工具,
]:
    ALL_TOOL_PATHS.update(_d)


def tool_path(name):
    """获取单个工具完整路径"""
    return ALL_TOOL_PATHS.get(name)


def tool_exists(name):
    """检查工具是否存在"""
    p = tool_path(name)
    if not p:
        return False
    return os.path.isfile(p) or os.path.isdir(p)


def list_missing_tools():
    """列出所有缺失的工具"""
    missing = []
    for name, path in sorted(ALL_TOOL_PATHS.items()):
        if not os.path.isfile(path) and not os.path.isdir(path):
            missing.append((name, path))
    return missing


if __name__ == "__main__":
    print(f"BASE_DIR:  {BASE_DIR}")
    print(f"TIANHU:    {TIANHU_BASE}")
    print(f"PYTHON:    {PYTHON_EXE}")
    print(f"工具总数:  {len(ALL_TOOL_PATHS)}")
    missing = list_missing_tools()
    if missing:
        print(f"\n缺失工具 ({len(missing)}):")
        for name, path in missing:
            print(f"  {name}: {path}")
    else:
        print("所有工具路径均存在")
