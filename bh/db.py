from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT NOT NULL, slug TEXT NOT NULL,
    name TEXT, program_url TEXT, repo_url TEXT, scope TEXT, payout TEXT,
    stack TEXT, description TEXT, local_path TEXT,
    status TEXT DEFAULT 'discovered', created_at REAL, updated_at REAL,
    UNIQUE(platform, slug));
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fid TEXT, title TEXT, severity TEXT, confidence TEXT, category TEXT,
    file TEXT, line INTEGER, code TEXT, detail TEXT, remediation TEXT,
    references_ TEXT, cwe TEXT, cvss REAL, tool TEXT, fingerprint TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    stage TEXT, status TEXT, detail TEXT, duration REAL, created_at REAL);
CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    label TEXT, url TEXT, kind TEXT, created_at REAL);
"""

FIELDS = {"name", "program_url", "repo_url", "scope", "payout", "stack",
          "description", "local_path", "status"}


class DB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def upsert_project(self, platform: str, slug: str, **fields) -> int:
        now = time.time()
        row = self.conn.execute("SELECT id FROM projects WHERE platform=? AND slug=?",
                                (platform, slug)).fetchone()
        keys = [k for k in fields if k in FIELDS]
        if row:
            pid = row["id"]
            if keys:
                self.conn.execute(
                    f"UPDATE projects SET {', '.join(f'{k}=?' for k in keys)}, updated_at=? WHERE id=?",
                    (*[fields[k] for k in keys], now, pid))
            self.conn.commit()
            return pid
        cur = self.conn.execute(
            """INSERT INTO projects (platform, slug, name, program_url, repo_url, scope,
               payout, stack, description, local_path, status, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (platform, slug, fields.get("name"), fields.get("program_url"),
             fields.get("repo_url"), fields.get("scope"), fields.get("payout"),
             fields.get("stack"), fields.get("description"), fields.get("local_path"),
             fields.get("status", "discovered"), now, now))
        self.conn.commit()
        return cur.lastrowid

    def get_project(self, ident):
        if str(ident).isdigit():
            return self.conn.execute("SELECT * FROM projects WHERE id=?", (int(ident),)).fetchone()
        return self.conn.execute("SELECT * FROM projects WHERE slug=? ORDER BY id DESC LIMIT 1",
                                 (ident,)).fetchone()

    def list_projects(self, status=None):
        if status:
            return self.conn.execute("SELECT * FROM projects WHERE status=? ORDER BY id DESC",
                                     (status,)).fetchall()
        return self.conn.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()

    def set_status(self, pid: int, status: str):
        self.conn.execute("UPDATE projects SET status=?, updated_at=? WHERE id=?",
                          (status, time.time(), pid))
        self.conn.commit()

    def add_finding(self, pid: int, f: dict) -> bool:
        if self.conn.execute("SELECT 1 FROM findings WHERE project_id=? AND fingerprint=?",
                             (pid, f.get("fingerprint"))).fetchone():
            return False
        self.conn.execute(
            """INSERT INTO findings (project_id, fid, title, severity, confidence, category,
               file, line, code, detail, remediation, references_, cwe, cvss, tool,
               fingerprint, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (pid, f.get("fid"), f.get("title"), f.get("severity"), f.get("confidence"),
             f.get("category"), f.get("file"), f.get("line"), f.get("code"),
             f.get("detail"), f.get("remediation"), json.dumps(f.get("references", [])),
             f.get("cwe"), f.get("cvss"), f.get("tool"), f.get("fingerprint"), time.time()))
        self.conn.commit()
        return True

    def findings(self, pid: int):
        return self.conn.execute(
            "SELECT * FROM findings WHERE project_id=? ORDER BY cvss DESC, id ASC", (pid,)).fetchall()

    def add_run(self, pid: int, stage: str, status: str, detail: str = "", dur: float = 0.0):
        self.conn.execute(
            "INSERT INTO runs (project_id, stage, status, detail, duration, created_at)"
            " VALUES (?,?,?,?,?,?)", (pid, stage, status, detail[:4000], dur, time.time()))
        self.conn.commit()

    def runs(self, pid: int):
        return self.conn.execute("SELECT * FROM runs WHERE project_id=? ORDER BY id", (pid,)).fetchall()

    def add_link(self, pid, label: str, url: str, kind: str = "search"):
        self.conn.execute(
            "INSERT INTO links (project_id, label, url, kind, created_at) VALUES (?,?,?,?,?)",
            (pid, label, url, kind, time.time()))
        self.conn.commit()

    def links(self, pid=None):
        if pid:
            return self.conn.execute("SELECT * FROM links WHERE project_id=?", (pid,)).fetchall()
        return self.conn.execute("SELECT * FROM links WHERE project_id IS NULL").fetchall()
