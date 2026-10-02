#!/usr/bin/env python3
"""API Key 轮换功能调用示例（纯标准库，无需第三方依赖）。

覆盖本轮新增：
1) 账号持有人凭当前 X-API-Key 轮换密钥（POST /me/api-key/rotate）；
2) 新密钥只在成功响应中返回一次，库内只存 SHA-256 摘要；
3) 旧密钥自轮换提交起失效（重启后仍然如此），再使用与无效凭据一样 401，
   不泄露账号存在性；
4) 新密钥立即可用：/me、封存、开封请求等业务照常；
5) 未轮换账号与无凭据接口（快照公钥查询、阅览兑换）行为不变。

用法: python examples/demo_rotate_key.py [base_url]
"""
import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def call(method: str, path: str, key: str | None = None, payload: dict | None = None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json", **({"X-API-Key": key} if key else {})},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def show(title: str, status: int, body) -> None:
    print(f"-- {title} -> {status}")
    print("   " + json.dumps(body, ensure_ascii=False))


def main() -> None:
    users = {}
    for name in ["alice", "bob", "carol", "dave"]:
        _, body = call("POST", "/register", payload={"username": name})
        users[name] = body["api_key"]
    owner = users["alice"]

    print("== 1) 轮换前：当前密钥可用 ==")
    s, me = call("GET", "/me", owner)
    show("GET /me（旧密钥）", s, me)

    print("== 2) 凭当前密钥轮换：新密钥仅此一次返回 ==")
    s, rotated = call("POST", "/me/api-key/rotate", owner)
    show("POST /me/api-key/rotate", s, rotated)
    new_key = rotated["api_key"]

    print("== 3) 旧密钥自轮换提交起失效（与无效凭据同样的 401） ==")
    s, denied = call("GET", "/me", owner)
    show("GET /me（旧密钥）", s, denied)
    s, denied2 = call("GET", "/me", "not-a-real-key")
    show("GET /me（伪造密钥，文案一致，不泄露账号存在性）", s, denied2)

    print("== 4) 新密钥立即可用，业务照常 ==")
    s, me2 = call("GET", "/me", new_key)
    show("GET /me（新密钥）", s, me2)
    s, sealed = call("POST", "/documents", new_key,
                     {"body": "轮换后封存的正文", "witnesses": ["bob", "carol", "dave"]})
    show("POST /documents（新密钥封存）", s, sealed)

    print("== 5) 未轮换账号与无凭据接口行为不变 ==")
    s, bob_me = call("GET", "/me", users["bob"])
    show("GET /me（未轮换的 bob）", s, bob_me)
    s, pub = call("GET", "/audit-snapshots/public-key")
    show("GET /audit-snapshots/public-key（无需凭据）", s,
         {**pub, "public_key": pub["public_key"].splitlines()[0] + " …"})
    s, redeem = call("POST", "/view-passes/redeem", payload={"token": "no-such-token"})
    show("POST /view-passes/redeem（无效凭证统一 404）", s, redeem)

    print("== 6) 可再次轮换：凭当前密钥换新，上一把随即失效 ==")
    s, rotated2 = call("POST", "/me/api-key/rotate", new_key)
    show("POST /me/api-key/rotate（再次轮换）", s, rotated2)
    s, denied3 = call("GET", "/me", new_key)
    show("GET /me（上一把密钥已失效）", s, denied3)

    print("== 7) 无凭据 / 错凭据不能轮换 ==")
    s, no_auth = call("POST", "/me/api-key/rotate")
    show("POST /me/api-key/rotate（无 X-API-Key）", s, no_auth)


if __name__ == "__main__":
    main()
