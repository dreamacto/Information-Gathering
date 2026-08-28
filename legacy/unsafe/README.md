# Legacy unsafe and approval-gated code

以下模块不进入默认主流程，也不应被新包自动调用：

- `credential_spray.py`
- `weak_passwd_scanner.py`
- `blind_exploit.py`
- `lateral_movement.py`
- `post_exploitation.py`
- `vuln_dispatcher.py`
- `waf403_bypass.py`
- `waf_advanced_bypass.py`

它们涉及凭证测试、主动利用、横向移动、后利用或绕过逻辑。继续保留根目录是为了兼容已有本地资料；实际使用必须遵守 `ROE.md`、脚本审批门和授权范围。
