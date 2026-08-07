#!/usr/bin/env python3
"""
AI 产品/供应方检测模块 v1.0
  针对人工智能专项攻防演习:
    - 发现目标AI应用 (50分/个)
    - 识别AI供应方/模型品牌 (500-8000分)
    - 检测AI API端点
    - 供应链溯源

  用法: python ai_detector.py --project glut
        python ai_detector.py --url https://target.com
"""

import argparse
import json
import os
import re
import time
from urllib.parse import urljoin

import requests
import urllib3

urllib3.disable_warnings()

from config import BASE_DIR
from pentest_utils import resolve_path, load_targets, safe_request, random_ua

TIMEOUT = 10

# ==================== AI 供应方指纹库 ====================

AI_VENDORS = {
    # 国内大模型厂商
    "百度文心一言": {
        "keywords": ["wenxin", "ernie", "文心一言", "文心", "百度智能云", "yiyan.baidu.com",
                     "aip.baidubce.com", "ERNIE-Bot", "erniebot"],
        "api_patterns": ["aip.baidubce.com", "wenxin.baidu.com"],
        "js_patterns": ["baidu.*ai", "wenxin", "ernie"],
        "supply_chain": "百度智能云",
        "score": 500,
    },
    "阿里通义千问": {
        "keywords": ["tongyi", "qwen", "通义", "通义千问", "阿里云智能",
                     "dashscope.aliyuncs.com", "qwen-max", "qwen-plus"],
        "api_patterns": ["dashscope.aliyuncs.com", "tongyi.aliyun.com"],
        "js_patterns": ["tongyi", "qwen", "dashscope"],
        "supply_chain": "阿里云",
        "score": 500,
    },
    "讯飞星火": {
        "keywords": ["spark", "xinghuo", "星火", "讯飞", "iflytek",
                     "spark-api.xf-yun.com", "xinghuo.xfyun.cn"],
        "api_patterns": ["spark-api.xf-yun.com", "xf-yun.com"],
        "js_patterns": ["spark", "xinghuo", "iflytek", "xfyun"],
        "supply_chain": "科大讯飞",
        "score": 500,
    },
    "腾讯混元": {
        "keywords": ["hunyuan", "混元", "腾讯云智能", "tencentcloudapi",
                     "hunyuan.tencentcloudapi.com", "hunyuan-pro"],
        "api_patterns": ["hunyuan.tencentcloudapi.com", "tencentcloudapi.com"],
        "js_patterns": ["hunyuan", "tencent.*ai"],
        "supply_chain": "腾讯云",
        "score": 500,
    },
    "字节豆包": {
        "keywords": ["doubao", "豆包", "ark", "volcengine",
                     "maas.volcengine.com", "doubao-pro"],
        "api_patterns": ["maas.volcengine.com", "volcengine.com"],
        "js_patterns": ["doubao", "volcengine", "ark"],
        "supply_chain": "字节跳动/火山引擎",
        "score": 500,
    },
    "智谱ChatGLM": {
        "keywords": ["chatglm", "glm", "智谱", "zhipu", "清言",
                     "open.bigmodel.cn", "chatglm.cn"],
        "api_patterns": ["open.bigmodel.cn", "chatglm.cn"],
        "js_patterns": ["chatglm", "glm", "zhipu", "bigmodel"],
        "supply_chain": "智谱AI",
        "score": 500,
    },
    "百川智能": {
        "keywords": ["baichuan", "百川", "百川智能"],
        "api_patterns": ["baichuan-api.com", "baichuan.com"],
        "js_patterns": ["baichuan"],
        "supply_chain": "百川智能",
        "score": 500,
    },
    "月之暗面Kimi": {
        "keywords": ["kimi", "moonshot", "月之暗面", "kimi.moonshot.cn"],
        "api_patterns": ["api.moonshot.cn", "moonshot.cn"],
        "js_patterns": ["kimi", "moonshot"],
        "supply_chain": "月之暗面",
        "score": 500,
    },
    "MiniMax": {
        "keywords": ["minimax", "abab", "海螺AI"],
        "api_patterns": ["api.minimax.chat", "minimax.chat"],
        "js_patterns": ["minimax", "abab"],
        "supply_chain": "MiniMax",
        "score": 500,
    },
    "深度求索DeepSeek": {
        "keywords": ["deepseek", "深度求索", "deepseek-chat", "deepseek-coder"],
        "api_patterns": ["api.deepseek.com", "deepseek.com"],
        "js_patterns": ["deepseek"],
        "supply_chain": "深度求索",
        "score": 500,
    },

    # 开源模型框架
    "OpenAI API": {
        "keywords": ["openai", "gpt-4", "gpt-3.5", "chatgpt", "sk-",
                     "api.openai.com", "gpt-4o"],
        "api_patterns": ["api.openai.com", "openai.com"],
        "js_patterns": ["openai", "gpt-4", "chatgpt"],
        "supply_chain": "OpenAI",
        "score": 500,
    },
    "Ollama": {
        "keywords": ["ollama", "llama", "mistral", "gemma"],
        "api_patterns": [":11434/api", "ollama"],
        "js_patterns": ["ollama"],
        "supply_chain": "Ollama (本地部署)",
        "score": 300,
    },
    "LangChain": {
        "keywords": ["langchain", "langchain-", "lc_"],
        "api_patterns": [],
        "js_patterns": ["langchain"],
        "supply_chain": "LangChain框架",
        "score": 200,
    },
    "HuggingFace": {
        "keywords": ["huggingface", "hugging face", "transformers"],
        "api_patterns": ["huggingface.co", "hf.co"],
        "js_patterns": ["huggingface", "transformers"],
        "supply_chain": "HuggingFace",
        "score": 300,
    },
    "Dify": {
        "keywords": ["dify", "dify.ai"],
        "api_patterns": ["dify.ai", "dify"],
        "js_patterns": ["dify"],
        "supply_chain": "Dify (AI应用平台)",
        "score": 400,
    },
    "FastGPT": {
        "keywords": ["fastgpt", "fast-gpt"],
        "api_patterns": ["fastgpt", "fast-gpt"],
        "js_patterns": ["fastgpt"],
        "supply_chain": "FastGPT (AI知识库)",
        "score": 400,
    },
    "AnythingLLM": {
        "keywords": ["anythingllm", "anything-llm"],
        "api_patterns": [],
        "js_patterns": ["anythingllm"],
        "supply_chain": "AnythingLLM",
        "score": 300,
    },
    "Flowise": {
        "keywords": ["flowise", "flowiseai"],
        "api_patterns": ["flowise"],
        "js_patterns": ["flowise"],
        "supply_chain": "Flowise (AI工作流)",
        "score": 300,
    },
    "AutoGPT": {
        "keywords": ["autogpt", "auto-gpt", "auto_gpt"],
        "api_patterns": [],
        "js_patterns": ["autogpt"],
        "supply_chain": "AutoGPT",
        "score": 300,
    },
    "RAGFlow": {
        "keywords": ["ragflow", "rag-flow"],
        "api_patterns": ["ragflow"],
        "js_patterns": ["ragflow"],
        "supply_chain": "RAGFlow",
        "score": 300,
    },
    "OneAPI": {
        "keywords": ["one-api", "oneapi", "new-api"],
        "api_patterns": ["/api/one", "/v1/chat"],
        "js_patterns": ["one-api", "oneapi"],
        "supply_chain": "OneAPI (模型聚合)",
        "score": 400,
    },
}

# ==================== AI 应用特征 ====================

AI_APP_PATTERNS = {
    "AI聊天/对话": {
        "keywords": ["智能客服", "AI助手", "智能问答", "AI客服", "机器人",
                    "智能对话", "chatbot", "chat bot", "ai chat", "aichat",
                    "digital human", "数字人", "智能助手", "虚拟助手"],
        "paths": ["/ai", "/chat", "/aichat", "/ai/chat", "/chatbot",
                  "/bot", "/robot", "/assistant", "/smart", "/intelligent"],
    },
    "AI搜索引擎": {
        "keywords": ["AI搜索", "智能搜索", "ai search", "智能检索"],
        "paths": ["/ai/search", "/aisearch", "/search/ai"],
    },
    "AI图像生成": {
        "keywords": ["AI绘画", "AI生成", "AI作图", "ai image", "ai绘画",
                    "midjourney", "stable diffusion", "sd-webui", "comfyui",
                    "text-to-image", "txt2img"],
        "paths": ["/ai/image", "/ai/draw", "/sd", "/midjourney"],
    },
    "AI知识库": {
        "keywords": ["知识库", "智能知识库", "RAG", "向量检索",
                    "knowledge base", "智能文档", "文档问答"],
        "paths": ["/knowledge", "/kb", "/rag", "/document"],
    },
    "AI办公/写作": {
        "keywords": ["AI写作", "智能写作", "公文写作", "AI办公",
                    "智能办公", "ai write", "公文助手", "智能起草"],
        "paths": ["/ai/write", "/ai/office", "/write"],
    },
    "AI视觉识别": {
        "keywords": ["人脸识别", "图像识别", "目标检测", "OCR",
                    "视觉AI", "视频分析", "行为识别", "车牌识别",
                    "face recognition", "object detection", "cv"],
        "paths": ["/ai/vision", "/face", "/ocr", "/camera"],
    },
    "AI语音": {
        "keywords": ["语音识别", "语音合成", "TTS", "ASR",
                    "语音转文字", "speech-to-text", "智能语音",
                    "语音助手", "voice"],
        "paths": ["/ai/voice", "/tts", "/asr", "/speech"],
    },
    "AI数据分析": {
        "keywords": ["智能分析", "AI分析", "数据挖掘", "预测模型",
                    "机器学习", "深度学习", "智能决策", "BI智能"],
        "paths": ["/ai/analysis", "/ml", "/analytics"],
    },
    "AI编程": {
        "keywords": ["AI编程", "代码助手", "copilot", "code assistant",
                    "智能编码", "代码生成", "codex"],
        "paths": ["/ai/code", "/copilot", "/codex"],
    },
    "AI教育": {
        "keywords": ["AI教学", "智能教育", "自适应学习", "AI辅导",
                    "智能批改", "AI课堂", "虚拟实验"],
        "paths": ["/ai/edu", "/ai/learn", "/smart/edu"],
    },
}

# ==================== AI SDK/框架检测(供应链) ====================

AI_SDKS = {
    "TensorFlow": [r"tensorflow", r"tf\.", r"keras"],
    "PyTorch": [r"pytorch", r"torch\.", r"torchvision"],
    "PaddlePaddle": [r"paddlepaddle", r"paddle\.", r"paddlenlp"],
    "scikit-learn": [r"sklearn", r"scikit-learn", r"scikit_learn"],
    "ONNX Runtime": [r"onnxruntime", r"onnx"],
    "XGBoost": [r"xgboost", r"xgb\.Booster"],
    "LightGBM": [r"lightgbm"],
    "OpenVINO": [r"openvino"],
    "MindSpore": [r"mindspore", r"华为昇思"],
    "MLflow": [r"mlflow"],
    "Kubeflow": [r"kubeflow"],
    "vLLM": [r"vllm"],
    "Ollama": [r"ollama"],
    "LM Studio": [r"lmstudio", r"lm-studio"],
    "LocalAI": [r"localai", r"local-ai"],
    "text-generation-webui": [r"text-generation-webui", r"text_gen_webui"],
}


def detect_ai_vendor(content, url=""):
    """从网页内容中识别AI供应方"""
    findings = []
    content_lower = content.lower()

    for vendor_name, info in AI_VENDORS.items():
        matched = []
        for kw in info["keywords"]:
            if kw.lower() in content_lower:
                matched.append(kw)

        if matched:
            findings.append({
                "vendor": vendor_name,
                "supply_chain": info["supply_chain"],
                "score": info["score"],
                "matched_keywords": matched[:5],
                "url": url,
            })

    return findings


def detect_ai_app(content, url=""):
    """识别AI应用类型"""
    findings = []
    content_lower = content.lower()

    for app_type, info in AI_APP_PATTERNS.items():
        matched = []
        for kw in info["keywords"]:
            if kw.lower() in content_lower:
                matched.append(kw)

        if matched:
            findings.append({
                "app_type": app_type,
                "matched_keywords": matched[:5],
                "url": url,
            })

    return findings


def detect_api_endpoints(base_url, sub_urls):
    """检测AI相关API端点"""
    ai_apis = []

    # 检查已知AI API路径
    known_paths = [
        "/v1/chat/completions", "/v1/completions", "/api/chat",
        "/api/ai", "/api/chatbot", "/ai/api", "/chat/api",
        "/api/v1/chat", "/api/v1/ai", "/api/llm",
        "/api/generate", "/api/completion", "/api/embedding",
        "/api/rerank", "/api/summarize",
        "/api/knowledge", "/api/rag", "/api/search",
    ]

    for url in sub_urls[:30]:
        for path in known_paths:
            if path in url.lower():
                ai_apis.append(url)
                break

    return ai_apis


def detect_ai_sdk(content):
    """检测AI SDK/框架供应链"""
    findings = []
    content_lower = content.lower()

    for sdk_name, patterns in AI_SDKS.items():
        for pattern in patterns:
            if re.search(pattern, content_lower):
                findings.append({"sdk": sdk_name, "pattern": pattern})
                break

    return findings


def detect_api_key_leaks(content, url=""):
    """检测AI API密钥泄露"""
    key_patterns = {
        "OpenAI API Key": r"sk-[A-Za-z0-9]{32,}",
        "OpenAI Project Key": r"sk-proj-[A-Za-z0-9]{32,}",
        "百度千帆 API Key": r"(?:client_id|api_key|AK[A-Za-z0-9]{10,})[\"\\s:=]+([A-Za-z0-9]{16,})",
        "阿里云DashScope Key": r"sk-[a-z0-9]{32}",
        "智谱 API Key": r"[a-z0-9]{24}\.[A-Za-z0-9]{16,}",
        "HuggingFace Token": r"hf_[A-Za-z0-9]{34}",
        "Anthropic API Key": r"sk-ant-[A-Za-z0-9]{32,}",
        "Cohere API Key": r"[A-Za-z0-9]{40}",
    }

    findings = []
    for name, pattern in key_patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            findings.append({
                "key_type": name,
                "keys_found": min(len(matches), 5),
                "source": url[:100],
            })

    return findings


# ==================== 主逻辑 ====================

def run_ai_detection(url, project=None):
    """对单个目标URL做AI检测"""
    findings = {
        "vendors": [],
        "apps": [],
        "apis": [],
        "sdks": [],
        "key_leaks": [],
    }

    print(f"\n{'='*60}")
    print(f"  AI 产品/供应方检测 - {url}")
    print(f"{'='*60}")

    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False,
                        headers={"User-Agent": random_ua()})
        html = r.text

        # 1. 检测AI供应方
        print("\n[1] AI供应方检测...")
        vendors = detect_ai_vendor(html, url)
        if vendors:
            findings["vendors"] = vendors
            for v in vendors:
                print(f"  [!] {v['vendor']} → 供应方: {v['supply_chain']} ({v['score']}分)")
                print(f"      关键词: {', '.join(v['matched_keywords'][:3])}")
        else:
            print("  [-] 未发现已知AI供应方")

        # 也检测JS文件
        import re
        js_urls = re.findall(r'src=["\"]([^"\"]+\.js[^"\"]*)["\"]', html)
        for js_url in js_urls[:10]:
            try:
                abs_js = urljoin(url, js_url)
                r_js = requests.get(abs_js, timeout=8, verify=False,
                                   headers={"User-Agent": random_ua()})
                js_vendors = detect_ai_vendor(r_js.text[:5000], abs_js)
                if js_vendors:
                    for v in js_vendors:
                        print(f"  [!] JS中发现: {v['vendor']} @ {js_url[:80]}")
                    findings["vendors"].extend(js_vendors)
            except:
                pass

        # 2. 检测AI应用类型
        print("\n[2] AI应用类型检测...")
        apps = detect_ai_app(html, url)
        if apps:
            findings["apps"] = apps
            for a in apps:
                print(f"  [+] {a['app_type']}: {', '.join(a['matched_keywords'][:3])}")
        else:
            print("  [-] 未发现AI应用特征")

        # 3. 检测API端点
        print("\n[3] AI API检测...")
        # 从页面提取所有链接
        all_urls = re.findall(r'(?:href|src|action)="([^"]+)"', html)
        all_urls += re.findall(r"(?:href|src|action)='([^']+)'", html)
        urls_to_check = [urljoin(url, u) for u in all_urls[:50]]
        apis = detect_api_endpoints(url, urls_to_check)
        if apis:
            findings["apis"] = apis
            for a in apis[:10]:
                print(f"  [+] API: {a[:100]}")

        # 4. SDK/框架检测
        print("\n[4] AI SDK/框架(供应链)...")
        sdks = detect_ai_sdk(html)
        if sdks:
            findings["sdks"] = sdks
            for s in sdks:
                print(f"  [+] {s['sdk']} (pattern: {s['pattern']})")

        # 5. AI API密钥泄露
        print("\n[5] AI API密钥泄露检测...")
        leaks = detect_api_key_leaks(html, url)
        if leaks:
            findings["key_leaks"] = leaks
            for l in leaks:
                print(f"  [!] {l['key_type']}: {l['keys_found']} potential keys")
        else:
            print("  [-] 未发现密钥泄露")

    except Exception as e:
        print(f"  [-] 错误: {e}")

    # 统计分数
    total_score = 0
    for v in findings["vendors"]:
        total_score += v["score"]  # 供应方识别 200-500分
    total_score += len(findings["apps"]) * 50  # AI应用发现 50分/个
    total_score += len(findings["apis"]) * 30  # API端点 30分/个
    total_score += len(findings["key_leaks"]) * 1000  # 密钥泄露 1000分
    total_score += len(findings["sdks"]) * 200  # SDK识别 200分

    print(f"\n  --- 估计得分: {total_score} 分 ---")

    # 保存
    if project:
        output_path = resolve_path(project, "ai_findings.json")
        findings["estimated_score"] = total_score
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)
        print(f"  已保存: {output_path}")

    return findings


def detect_from_project(project):
    """对项目所有URL做AI检测"""
    urls = load_targets(project)
    # 过滤: 只测有AI嫌疑的URL
    ai_urls = [u for u in urls if any(
        kw in u.lower() for kw in ['ai', 'chat', 'smart', 'bot', 'api',
                                     'ml', 'model', '智能', '问答', '助手'])
    ]
    if not ai_urls:
        ai_urls = urls[:10]

    print(f"[+] {len(ai_urls)} AI嫌疑URL")

    all_findings = {}
    for url in ai_urls[:15]:
        findings = run_ai_detection(url)
        all_findings[url] = findings
        time.sleep(1)

    return all_findings


def main():
    parser = argparse.ArgumentParser(description="AI 产品/供应方检测模块")
    parser.add_argument("--project", default=None, help="项目缩写")
    parser.add_argument("--url", default=None, help="单个URL")
    args = parser.parse_args()

    if args.url:
        run_ai_detection(args.url)
    elif args.project:
        detect_from_project(args.project)
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 已取消")
    try:
        input("\n按 Enter 退出...")
    except (EOFError, KeyboardInterrupt):
        pass
