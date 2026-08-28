# Miniapp stages

- `endpoint_offline.py`: offline endpoint, host, sign, and auth-hint extraction from unpacked source.
- `source_analysis.py`: static analysis of unpacked mini-program source.
- `manual_search_helper.py`: offline generation of manual search and review packages.
- `wechat_discovery.py`: facade for authorized WeChat/mini-program discovery; network access remains scope- and rate-controlled.
- `decrypt_wxapkg.py`: local wxapkg decryption and clue extraction; requires the optional cryptography dependency.
- `full_unpack_wxapkg.py`: local wxapkg source restoration; requires the optional PyCryptodome dependency.

Decryption, package unpacking, Burp import, browser capture, and live workflows remain separate and retain their existing approval and local-data boundaries.
