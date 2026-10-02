"""API Key 轮换功能测试。

规则要点（规格）：
- 账号持有人凭当前 X-API-Key 轮换密钥（POST /me/api-key/rotate）；
- 新密钥只在成功响应中返回一次，持久层只存 SHA-256 摘要；
- 旧密钥自轮换提交起失效（重启后仍然如此），再使用与无效凭据一样 401，
  不泄露账号存在性；
- 轮换与封存、见证同意、交接、清除安排等已认证写操作并发时按事务提交
  先后判定：轮换先提交则旧密钥写入不得生效或留下业务审计；业务写入先
  提交则照常完成；
- 未轮换账号与无凭据接口（阅览兑换、快照验真、公钥查询）行为不变。
"""
import datetime as dt
import hashlib
import os
import socket
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import auth, digest_of, register, seal  # noqa: E402

BODY = "轮换并发封存正文 ROTATE-RACE-SECRET"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _deadline(hours: int = 2) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=hours)).isoformat()


# ---------------------------------------------------------------------------
# 基本行为
# ---------------------------------------------------------------------------


def test_rotate_requires_auth(client):
    assert client.post("/me/api-key/rotate").status_code == 401
    assert client.post("/me/api-key/rotate", headers=auth("wrong")).status_code == 401


def test_rotate_returns_new_key_once_and_old_key_invalid(client):
    old_key = register(client, "alice")
    me = client.get("/me", headers=auth(old_key)).json()

    r = client.post("/me/api-key/rotate", headers=auth(old_key))
    assert r.status_code == 200, r.text
    body = r.json()
    new_key = body["api_key"]
    assert new_key != old_key and len(new_key) == 64
    assert body["user_id"] == me["user_id"]
    assert body["username"] == "alice"
    assert body["rotated_at"]

    # 旧密钥自轮换提交起失效：与无效凭据一样的 401，不泄露账号存在性
    denied = client.get("/me", headers=auth(old_key))
    assert denied.status_code == 401
    assert denied.json() == client.get("/me", headers=auth("never-valid")).json()

    # 新密钥立即可用；/me 不再返回任何密钥（新密钥只返回那一次）
    me2 = client.get("/me", headers=auth(new_key))
    assert me2.status_code == 200
    assert me2.json() == me
    assert "api_key" not in me2.json()

    # 可连续轮换：凭当前密钥再换一次，上一把随即失效
    r2 = client.post("/me/api-key/rotate", headers=auth(new_key))
    assert r2.status_code == 200
    key3 = r2.json()["api_key"]
    assert client.get("/me", headers=auth(new_key)).status_code == 401
    assert client.get("/me", headers=auth(key3)).status_code == 200


def test_rotation_persists_only_digest(client, isolated_db):
    old_key = register(client, "digest-only")
    r = client.post("/me/api-key/rotate", headers=auth(old_key))
    assert r.status_code == 200
    new_key = r.json()["api_key"]

    # 冷读库：只存新密钥的 SHA-256 摘要，不存明文；旧摘要也不保留
    conn = sqlite3.connect(str(isolated_db))
    try:
        row = conn.execute(
            "SELECT key_hash FROM users WHERE username = 'digest-only'"
        ).fetchone()
        assert row[0] == _sha256(new_key)
        assert row[0] != new_key
        assert row[0] != _sha256(old_key)
        leaked = conn.execute(
            "SELECT COUNT(*) FROM users WHERE key_hash IN (?, ?)",
            (new_key, old_key),
        ).fetchone()[0]
        assert leaked == 0
    finally:
        conn.close()


def test_rotation_leaves_audit_and_old_key_invalid_after_restart(isolated_db):
    from app.main import app

    with TestClient(app) as c1:
        old_key = register(c1, "rot-restart")
        r = c1.post("/me/api-key/rotate", headers=auth(old_key))
        assert r.status_code == 200
        new_key = r.json()["api_key"]

    # 重启（重新进入应用生命周期，同一个数据库文件）：旧密钥仍然失效
    with TestClient(app) as c2:
        assert c2.get("/me", headers=auth(old_key)).status_code == 401
        assert c2.get("/me", headers=auth(new_key)).status_code == 200

    # 轮换本身按顺序留痕（actor 为本人，不关联任何资料）
    conn = sqlite3.connect(str(isolated_db))
    try:
        rows = conn.execute(
            "SELECT a.action, u.username, a.document_id FROM audit_log a"
            " JOIN users u ON u.id = a.actor_id WHERE a.action = 'api_key_rotated'"
        ).fetchall()
        assert rows == [("api_key_rotated", "rot-restart", None)]
    finally:
        conn.close()


def test_unrotated_accounts_and_public_endpoints_unchanged(client):
    alice = register(client, "alice")
    bob = register(client, "bob")

    r = client.post("/me/api-key/rotate", headers=auth(alice))
    assert r.status_code == 200

    # 未轮换账号行为不变
    assert client.get("/me", headers=auth(bob)).status_code == 200

    # 无需登录的接口保持原样：公钥查询 / 快照验真结构校验 / 阅览兑换统一 404
    assert client.get("/health").status_code == 200
    assert client.get("/audit-snapshots/public-key").status_code == 200
    bad_verify = client.post("/audit-snapshots/verify", json={
        "snapshot": {}, "signature": "x", "public_key": "y",
    })
    assert bad_verify.status_code == 422
    redeem = client.post("/view-passes/redeem", json={"token": "no-such-token"})
    assert redeem.status_code == 404


def test_business_as_usual_with_new_key(client):
    """轮换后新密钥可照常完成封存/开封全流程；旧密钥全程 401。"""
    old_key = register(client, "owner")
    for n in ("w1", "w2", "w3"):
        register(client, n)
    new_key = client.post("/me/api-key/rotate", headers=auth(old_key)).json()["api_key"]

    d = seal(client, new_key, BODY, ["w1", "w2", "w3"])
    doc_id = d["document_id"]
    assert client.get(f"/documents/{doc_id}", headers=auth(old_key)).status_code == 401
    r = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "轮换后申请", "deadline": _deadline()},
        headers=auth(new_key),
    )
    assert r.status_code == 201, r.text
    # 旧密钥对任何已认证写操作一律 401
    assert client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "旧密钥", "deadline": _deadline()},
        headers=auth(old_key),
    ).status_code == 401
    assert client.put(
        f"/documents/{doc_id}/purge",
        json={"purge_at": _deadline()},
        headers=auth(old_key),
    ).status_code == 401


# ---------------------------------------------------------------------------
# 并发：轮换 vs 已认证写操作（真实 uvicorn + 多线程）
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_server(tmp_path, monkeypatch):
    db = tmp_path / "live.db"
    monkeypatch.setenv("SEAL_DB_PATH", str(db))
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "1")

    import uvicorn

    from app.main import app

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            if httpx.get(base + "/health", timeout=1).status_code == 200:
                break
        except Exception:
            time.sleep(0.1)
    else:
        pytest.fail("server did not start")

    yield base, str(db)

    server.should_exit = True
    thread.join(timeout=5)


def _reg(c, base, name):
    r = c.post(base + "/register", json={"username": name})
    assert r.status_code == 201, r.text
    return r.json()["api_key"]


def test_concurrent_rotate_vs_seal_single_outcome(live_server):
    """轮换与封存赛跑：按事务提交先后判定，旧密钥写入要么照常完成、
    要么 401 且不留任何业务数据/审计；两种终态互斥且唯一。"""
    base, db_path = live_server
    with httpx.Client(timeout=10) as c:
        owner = _reg(c, base, "race-owner")
        for n in ("w1", "w2", "w3"):
            _reg(c, base, n)

    barrier = threading.Barrier(2)

    def rotate():
        barrier.wait()
        with httpx.Client(timeout=10) as c:
            return c.post(base + "/me/api-key/rotate", headers=auth(owner))

    def seal_doc():
        barrier.wait()
        with httpx.Client(timeout=10) as c:
            return c.post(base + "/documents",
                          json={"body": BODY, "witnesses": ["w1", "w2", "w3"]},
                          headers=auth(owner))

    with ThreadPoolExecutor(max_workers=2) as pool:
        rot_resp, seal_resp = list(pool.map(lambda f: f(), [rotate, seal_doc]))

    # 轮换必然成功（其自身在锁内复核时密钥仍当前，或它本就是先提交者）
    assert rot_resp.status_code == 200, rot_resp.text
    new_key = rot_resp.json()["api_key"]

    with httpx.Client(timeout=10) as c:
        # 旧密钥自轮换提交起失效
        assert c.get(base + "/me", headers=auth(owner)).status_code == 401
        assert c.get(base + "/me", headers=auth(new_key)).status_code == 200
        docs = c.get(base + "/documents", headers=auth(new_key)).json()["documents"]

    conn = sqlite3.connect(db_path)
    try:
        sealed = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
        seal_audit = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'seal'"
        ).fetchone()[0]
    finally:
        conn.close()

    if seal_resp.status_code == 201:
        # 业务写入先提交：照常完成，新密钥可见该资料
        assert len(docs) == 1 and sealed == 1 and seal_audit == 1
    else:
        # 轮换先提交：旧密钥写入不得生效，也不留业务审计
        assert seal_resp.status_code == 401
        assert docs == [] and sealed == 0 and seal_audit == 0


def test_concurrent_rotate_vs_approve_single_outcome(live_server):
    """见证人轮换密钥与见证同意赛跑：同意要么先提交生效，要么 401 且不留票。"""
    base, db_path = live_server
    with httpx.Client(timeout=10) as c:
        owner = _reg(c, base, "race2-owner")
        w1 = _reg(c, base, "race2-w1")
        for n in ("w2", "w3"):
            _reg(c, base, n)
        doc_id = c.post(base + "/documents",
                        json={"body": BODY, "witnesses": ["race2-w1", "w2", "w3"]},
                        headers=auth(owner)).json()["document_id"]
        req_id = c.post(f"{base}/documents/{doc_id}/open-requests",
                        json={"reason": "轮换赛跑", "deadline": _deadline()},
                        headers=auth(owner)).json()["request_id"]
        dg = digest_of(BODY)

    barrier = threading.Barrier(2)

    def rotate():
        barrier.wait()
        with httpx.Client(timeout=10) as c:
            return c.post(base + "/me/api-key/rotate", headers=auth(w1))

    def approve():
        barrier.wait()
        with httpx.Client(timeout=10) as c:
            return c.post(f"{base}/open-requests/{req_id}/approve",
                          json={"digest": dg}, headers=auth(w1))

    with ThreadPoolExecutor(max_workers=2) as pool:
        rot_resp, ap_resp = list(pool.map(lambda f: f(), [rotate, approve]))

    assert rot_resp.status_code == 200, rot_resp.text
    new_w1 = rot_resp.json()["api_key"]

    with httpx.Client(timeout=10) as c:
        got = c.get(f"{base}/documents/{doc_id}", headers=auth(owner)).json()
        count = got["latest_open_request"]["approval_count"]
        # 旧密钥已失效；新密钥仍是同一账号（见证人身份跟账号不跟密钥）
        assert c.get(base + "/me", headers=auth(w1)).status_code == 401
        assert c.get(base + "/me", headers=auth(new_w1)).status_code == 200

    conn = sqlite3.connect(db_path)
    try:
        approvals = conn.execute(
            "SELECT COUNT(*) FROM approvals WHERE request_id = ?", (req_id,)
        ).fetchone()[0]
        approval_audit = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'approval'"
        ).fetchone()[0]
    finally:
        conn.close()

    if ap_resp.status_code == 200:
        # 同意先提交：一票生效
        assert count == 1 and approvals == 1 and approval_audit == 1
    else:
        # 轮换先提交：旧密钥同意不得生效，不留票也不留审计
        assert ap_resp.status_code == 401
        assert count == 0 and approvals == 0 and approval_audit == 0
        # 新密钥可补票（账号身份不变）
        with httpx.Client(timeout=10) as c:
            r = c.post(f"{base}/open-requests/{req_id}/approve",
                       json={"digest": dg}, headers=auth(new_w1))
            assert r.status_code == 200 and r.json()["approval_count"] == 1


def test_concurrent_double_rotate_single_winner(live_server):
    """同一把旧密钥并发轮换两次：只有先提交者生效，另一把按 401 拒绝。"""
    base, _ = live_server
    with httpx.Client(timeout=10) as c:
        key = _reg(c, base, "double-rot")

    barrier = threading.Barrier(2)

    def rotate():
        barrier.wait()
        with httpx.Client(timeout=10) as c:
            return c.post(base + "/me/api-key/rotate", headers=auth(key))

    with ThreadPoolExecutor(max_workers=2) as pool:
        r1, r2 = list(pool.map(lambda f: f(), [rotate, rotate]))

    codes = sorted([r1.status_code, r2.status_code])
    assert codes == [200, 401], (r1.status_code, r2.status_code)
    winner = (r1 if r1.status_code == 200 else r2).json()["api_key"]

    with httpx.Client(timeout=10) as c:
        assert c.get(base + "/me", headers=auth(key)).status_code == 401
        assert c.get(base + "/me", headers=auth(winner)).status_code == 200
