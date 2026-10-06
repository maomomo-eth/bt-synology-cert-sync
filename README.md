# 宝塔证书同步到群晖 DSM

每日检查宝塔 `*.example.com` 证书目录。证书、私钥或中间证书有变化时，通过 DSM 7 API 替换指定的**现有证书**，并保留其默认状态和服务绑定。首次运行会上传一次。`example.com` 只是示例；实际使用前请在 `config.json` 中改成自己的域名和 NAS 地址。

## 配置

1. 在群晖「控制面板 → 安全性 → 证书」中确认要替换的证书及其**描述**。脚本仅替换描述完全一致且唯一的证书，不会创建新证书。
2. 复制 `config.example.json` 为 `config.json`，填写 NAS 地址、管理员账号密码、`certificate_desc`，并把 `source_glob` 改为实际证书目录。默认优先使用与 `source_glob` 路径完全同名的目录（宝塔的通配符证书目录可能真的叫 `*.example.com`）；若没有同名目录，才按通配符搜索。如果搜索匹配多个目录，请增加 `"source_dir": "/www/server/panel/vhost/letsencrypt/实际目录.example.com"` 指定其中一个。
3. 将配置文件设为仅运行用户可读：`chmod 600 config.json`。NAS 账号需要证书管理权限。建议专用管理员账号；启用二次验证的账号可能无法用于无人值守登录。
4. `dsm_url` 使用可验证证书的 HTTPS 地址。若群晖使用私有 CA，可增加 `"ca_file": "/绝对路径/ca.pem"`。只有确认内网连接可信且无法配置 CA 时，才将 `verify_tls` 设为 `false`。

脚本只依赖 Python 标准库和系统 `openssl`。宝塔服务器需要能访问 NAS 的 DSM HTTPS 端口。配置文件和私钥不会写入日志。

## 运行与计划任务

先将 `sync_cert.py` 和填好的 `config.json` 放到宝塔服务器的 `/www/server/panel/script/bt-synology-cert-sync/`（或其他固定目录），然后手动检查并执行一次：

```bash
python3 /www/server/panel/script/bt-synology-cert-sync/sync_cert.py --config /www/server/panel/script/bt-synology-cert-sync/config.json --dry-run
python3 /www/server/panel/script/bt-synology-cert-sync/sync_cert.py --config /www/server/panel/script/bt-synology-cert-sync/config.json
```

在宝塔「计划任务 → Shell 脚本」中选择每天运行，脚本内容填写（若使用其他目录，请替换路径）：

```bash
export LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONUTF8=1 PYTHONIOENCODING=utf-8
/usr/bin/python3 /www/server/panel/script/bt-synology-cert-sync/sync_cert.py --config /www/server/panel/script/bt-synology-cert-sync/config.json
```

同步成功后才更新 `state.json`。若 DSM 上传失败，下次计划任务会重试。`state.json` 请保留；删除后下次运行会重新上传。

若登录返回 `407`，表示 DSM 已封锁请求来源 IP。请先在群晖「控制面板 → 安全性 → 保护 → 自动封锁 → 允许/封锁名单」中找到并解除该 IP 的封锁，再核对 `config.json` 中的账号密码。NAS 若经反向代理访问，封锁名单中可能显示反向代理的 IP。
