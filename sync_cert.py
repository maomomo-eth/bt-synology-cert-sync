#!/usr/bin/env python3
"""检查宝塔证书变化，并替换群晖 DSM 中指定的现有证书。"""

from __future__ import annotations

import argparse
import fcntl
import glob
import hashlib
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


DEFAULT_GLOB = "/www/server/panel/vhost/letsencrypt/*.example.com"
PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----\s*.*?-----END CERTIFICATE-----", re.S)


class SyncError(Exception):
    """可直接展示给计划任务日志的错误。"""


def load_config(path: Path) -> dict:
    try:
        config = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise SyncError(f"配置文件不存在：{path}") from exc
    except json.JSONDecodeError as exc:
        raise SyncError(f"配置文件 JSON 格式错误：{exc}") from exc
    if not isinstance(config, dict):
        raise SyncError("配置文件必须是 JSON 对象")
    for key in ("dsm_url", "username", "password", "certificate_desc"):
        if not isinstance(config.get(key), str) or not config[key].strip() or config[key].startswith("请填写"):
            raise SyncError(f"请在配置文件中填写 {key}")
    url = urllib.parse.urlsplit(config["dsm_url"])
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.path not in ("", "/") or url.query or url.fragment:
        raise SyncError("dsm_url 必须是 HTTPS 地址，例如 https://nas.example.com:5001")
    if "verify_tls" in config and not isinstance(config["verify_tls"], bool):
        raise SyncError("verify_tls 必须为 true 或 false")
    return config


def find_source(config: dict) -> Path:
    if config.get("source_dir"):
        source = Path(config["source_dir"])
        if not source.is_dir():
            raise SyncError(f"证书目录不存在：{source}")
        return source
    pattern = config.get("source_glob", DEFAULT_GLOB)
    # 宝塔可能把通配符本身作为目录名，例如「*.example.com」。
    literal_source = Path(pattern)
    if literal_source.is_dir():
        return literal_source
    matches = [Path(p) for p in glob.glob(pattern) if Path(p).is_dir()]
    if len(matches) != 1:
        raise SyncError(f"证书目录匹配到 {len(matches)} 个：{pattern}；请设置 source_dir 指定唯一目录")
    return matches[0]


def openssl(*args: str, data: bytes) -> bytes:
    try:
        result = subprocess.run(
            ["openssl", *args], input=data, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise SyncError("无法执行 openssl；请确认已安装且命令可用") from exc
    if result.returncode:
        raise SyncError(f"证书或私钥校验失败：openssl {' '.join(args)}")
    return result.stdout


def read_certificate(source: Path) -> tuple[bytes, bytes, bytes, str]:
    key_path = source / "privkey.pem"
    fullchain_path = source / "fullchain.pem"
    try:
        key = key_path.read_bytes()
        if fullchain_path.exists():
            chain_parts = PEM_CERT.findall(fullchain_path.read_bytes())
            if not chain_parts:
                raise SyncError(f"未在 {fullchain_path} 中找到 PEM 证书")
            cert = chain_parts[0] + b"\n"
            intermediate = b"\n".join(chain_parts[1:]) + (b"\n" if len(chain_parts) > 1 else b"")
        else:
            cert = (source / "cert.pem").read_bytes()
            chain_path = source / "chain.pem"
            intermediate = chain_path.read_bytes() if chain_path.exists() else b""
    except FileNotFoundError as exc:
        raise SyncError(f"缺少证书文件：{exc.filename}") from exc

    openssl("x509", "-noout", "-checkend", "0", data=cert)
    cert_pub = openssl("x509", "-pubkey", "-noout", data=cert)
    key_pub = openssl("pkey", "-pubout", data=key)
    if cert_pub.strip() != key_pub.strip():
        raise SyncError("证书与私钥不匹配，已取消上传")
    if intermediate:
        for part in PEM_CERT.findall(intermediate):
            openssl("x509", "-noout", data=part)
    fingerprint = hashlib.sha256(b"\0".join((cert, key, intermediate))).hexdigest()
    return cert, key, intermediate, fingerprint


def multipart(fields: dict[str, str], files: dict[str, tuple[str, bytes]]) -> tuple[bytes, str]:
    boundary = "----bt-synology-" + secrets.token_hex(16)
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.extend((f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n".encode(), value.encode(), b"\r\n"))
    for name, (filename, content) in files.items():
        chunks.extend((
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode(),
            content, b"\r\n",
        ))
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


class DsmClient:
    def __init__(self, config: dict):
        self.base = config["dsm_url"].rstrip("/")
        self.username = config["username"]
        self.password = config["password"]
        self.context = ssl.create_default_context(cafile=config.get("ca_file"))
        if config.get("verify_tls", True) is False:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        self.sid = ""
        self.token = ""

    def request(self, path: str, params: dict[str, str], body: bytes | None = None, content_type: str | None = None) -> dict:
        url = self.base + "/webapi/" + path + "?" + urllib.parse.urlencode(params)
        headers = {"Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = content_type
        if self.token:
            headers["X-SYNO-TOKEN"] = self.token
        req = urllib.request.Request(url, data=body, headers=headers, method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=30, context=self.context) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise SyncError(f"DSM HTTP 错误：{exc.code}") from exc
        except urllib.error.URLError as exc:
            raise SyncError(f"无法连接 DSM：{exc.reason}") from exc
        if not isinstance(data, dict) or data.get("success") is not True:
            code = data.get("error", {}).get("code", "未知") if isinstance(data, dict) else "响应格式错误"
            if path == "auth.cgi" and code == 407:
                raise SyncError("DSM 登录失败（407）：来源 IP 已被封锁。请在群晖「控制面板 → 安全性 → 保护 → 自动封锁 → 允许/封锁名单」中检查并解除封锁")
            raise SyncError(f"DSM API 调用失败，错误码：{code}")
        return data.get("data") or {}

    def login(self) -> None:
        body = urllib.parse.urlencode({
            "api": "SYNO.API.Auth", "version": "7", "method": "login", "session": "DSM",
            "format": "sid", "enable_syno_token": "yes", "account": self.username,
            "passwd": self.password,
        }).encode("utf-8")
        data = self.request("auth.cgi", {"enable_syno_token": "yes"}, body, "application/x-www-form-urlencoded")
        self.sid = data.get("sid", "")
        self.token = data.get("synotoken", "")
        if not self.sid or not self.token:
            raise SyncError("DSM 登录响应缺少 sid 或 synotoken")

    def logout(self) -> None:
        if self.sid:
            try:
                self.request("auth.cgi", {"api": "SYNO.API.Auth", "version": "7", "method": "logout", "session": "DSM", "_sid": self.sid})
            except SyncError:
                pass
            self.sid = ""

    def target_certificate(self, description: str) -> dict:
        data = self.request("entry.cgi", {
            "api": "SYNO.Core.Certificate.CRT", "version": "1", "method": "list", "_sid": self.sid,
        })
        matches = [cert for cert in data.get("certificates", []) if cert.get("desc") == description]
        if len(matches) != 1 or not matches[0].get("id"):
            raise SyncError(f"DSM 中描述为「{description}」的证书匹配到 {len(matches)} 个；请先在 DSM 确认")
        return matches[0]

    def import_certificate(self, target: dict, cert: bytes, key: bytes, intermediate: bytes) -> None:
        fields = {"id": str(target["id"]), "desc": target["desc"]}
        if target.get("is_default"):
            fields["as_default"] = "true"
        files = {"key": ("privkey.pem", key), "cert": ("cert.pem", cert)}
        if intermediate:
            files["inter_cert"] = ("chain.pem", intermediate)
        body, content_type = multipart(fields, files)
        self.request("entry.cgi", {
            "api": "SYNO.Core.Certificate", "version": "1", "method": "import",
            "SynoToken": self.token, "_sid": self.sid,
        }, body, content_type)


def save_state(path: Path, state: dict) -> None:
    temporary = path.with_name(path.name + ".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
            json.dump(state, file, ensure_ascii=False, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def sync(config_path: Path, dry_run: bool = False) -> str:
    config = load_config(config_path)
    source = find_source(config)
    cert, key, intermediate, fingerprint = read_certificate(source)
    state_path = Path(config.get("state_file") or config_path.with_name("state.json"))
    state_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = state_path.with_name(state_path.name + ".lock")
    lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
        current = {
            "source_dir": str(source.resolve()), "dsm_url": config["dsm_url"].rstrip("/"),
            "certificate_desc": config["certificate_desc"], "fingerprint": fingerprint,
        }
        if state == current:
            return "证书未变化，无需更新"
        if dry_run:
            return f"检测到新证书，校验通过；目标：{config['certificate_desc']}；未上传（dry-run）"
        client = DsmClient(config)
        try:
            client.login()
            target = client.target_certificate(config["certificate_desc"])
            client.import_certificate(target, cert, key, intermediate)
        finally:
            client.logout()
        save_state(state_path, current)
        return f"已更新 DSM 证书：{config['certificate_desc']}（{source}）"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.json"), help="配置文件路径")
    parser.add_argument("--dry-run", action="store_true", help="只检查本地证书，不连接 DSM")
    args = parser.parse_args()
    try:
        print(sync(args.config, args.dry_run))
        return 0
    except (SyncError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"证书同步失败：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
