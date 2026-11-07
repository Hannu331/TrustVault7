import pytest
from fastapi.testclient import TestClient
from app import db, security
from app.main import app

PW = "Passw0rd-test-1"


@pytest.fixture
def env(tmp_path):
    db.DB_PATH = str(tmp_path / "t.db")
    db.STORE = str(tmp_path / "blobs")
    security.FAILS.clear()
    db.init()
    c = db.connect()
    for n, r in [
        ("admin", "admin"),
        ("alice", "owner"),
        ("bob", "owner"),
        ("vera", "viewer"),
        ("wendy", "viewer"),
    ]:
        c.execute(
            "INSERT INTO users(username,pw_hash,role,created_at) VALUES(?,?,?,?)",
            (n, security.hash_pw(PW), r, db.now()),
        )
    c.close()
    with TestClient(app) as client:
        e = Env(client)
        for n in ("admin", "alice", "bob", "vera", "wendy"):
            e.login(n)  # ids/tokens available to every test
        yield e


class Env:
    def __init__(self, client):
        self.c = client
        self.tok = {}
        self.ids = {}

    def login(self, name):
        r = self.c.post("/api/auth/login", json={"username": name, "password": PW})
        assert r.status_code == 200, r.text
        self.tok[name] = r.json()["token"]
        self.ids[name] = r.json()["user"]["id"]
        return self.tok[name]

    def h(self, name):
        if name not in self.tok:
            self.login(name)
        return {"Authorization": f"Bearer {self.tok[name]}"}

    def upload(self, name, fname="a.txt", data=b"secret text", cat="hr"):
        r = self.c.post(
            "/api/documents",
            headers=self.h(name),
            files={"file": (fname, data)},
            data={"category": cat},
        )
        assert r.status_code == 201, r.text
        return r.json()["id"]

    def grant(self, owner, doc, to, perm="read"):
        self.h(to)
        r = self.c.put(
            f"/api/documents/{doc}/grants/{self.ids[to]}",
            headers=self.h(owner),
            json={"permission": perm},
        )
        assert r.status_code == 200, r.text

    def audit(self, **q):
        return self.c.get("/api/admin/audit", headers=self.h("admin"), params=q).json()
