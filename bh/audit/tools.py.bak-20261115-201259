from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..util import have_tool, log, run_cmd, short_hash

SEV_MAP = {"critical": "critical", "high": "high", "error": "high", "warning": "medium",
           "medium": "medium", "moderate": "medium", "low": "low", "info": "info",
           "note": "low", "style": "info"}

# these exit 1 to mean "findings found", not "crashed"
FINDING_EXIT = {"bandit", "gosec", "njsscan", "npm-audit", "osv-scanner",
                "gitleaks", "trufflehog"}


def _norm(s):
    return SEV_MAP.get(str(s or "").strip().lower(), "medium")


def _f(title, sev, tool, **kw):
    return {"title": title, "severity": _norm(sev), "confidence": kw.get("confidence", "medium"),
            "category": kw.get("category", "sast"), "cwe": kw.get("cwe"), "file": kw.get("file"),
            "line": kw.get("line"), "code": kw.get("code"), "detail": kw.get("detail", ""),
            "remediation": kw.get("remediation", ""), "tool": tool,
            "references": kw.get("references", []),
            "fingerprint": short_hash(f"{tool}:{kw.get('file')}:{kw.get('line')}:{title}")}


def _status(res, tool="", ok_extra=False):
    if res["ok"] or ok_extra or (tool in FINDING_EXIT and res["rc"] == 1):
        return "ok"
    return f"rc={res['rc']}"


def _meta(res, tool, ok_extra=False):
    return {"tool": tool, "status": _status(res, tool, ok_extra), "dur": res["dur"],
            "err": (res.get("err") or "")[:400]}


def semgrep(repo: Path, cfg, rules_dir: Path):
    if not have_tool("semgrep"):
        return [], {"tool": "semgrep", "status": "missing"}
    configs = ["--config", "auto"]
    custom = Path(rules_dir) / "custom.yaml"
    if cfg.audit.get("custom_rules", True) and custom.is_file():
        configs += ["--config", str(custom)]
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out = tf.name
    res = run_cmd(["semgrep", "--json", "--quiet", *configs,
                   "--max-target-bytes", str(cfg.audit.get("max_file_bytes", 2_000_000)),
                   "--output", out, "."], cwd=repo,
                  timeout=int(cfg.audit.get("tool_timeout", 1200)))
    findings = []
    try:
        data = json.loads(Path(out).read_text(encoding="utf-8", errors="replace") or "{}")
        for r in data.get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {})
            findings.append(_f(r.get("check_id") or "semgrep",
                               meta.get("impact") or extra.get("severity"), "semgrep",
                               confidence=meta.get("confidence", "medium"),
                               category=meta.get("category", "sast"),
                               cwe=(meta.get("cwe") or [None])[0], file=r.get("path"),
                               line=(r.get("start") or {}).get("line"), code=extra.get("lines"),
                               detail=extra.get("message", ""),
                               remediation=meta.get("fix") or "",
                               references=meta.get("references") or []))
    except Exception as exc:
        log.warning("semgrep parse: %s", exc)
    finally:
        Path(out).unlink(missing_ok=True)
    return findings, _meta(res, "semgrep")


def bandit(repo: Path, cfg):
    if not have_tool("bandit"):
        return [], {"tool": "bandit", "status": "missing"}
    res = run_cmd(["bandit", "-r", ".", "-f", "json", "-q", "-x",
                   ",".join(cfg.audit.get("exclude_dirs", []))], cwd=repo,
                  timeout=int(cfg.audit.get("tool_timeout", 1200)))
    findings = []
    try:
        for r in json.loads(res["out"] or "{}").get("results", []):
            findings.append(_f(r.get("test_name") or r.get("test_id"), r.get("issue_severity"),
                               "bandit", confidence=(r.get("issue_confidence") or "medium").lower(),
                               file=r.get("filename"), line=r.get("line_number"),
                               code=r.get("code"), detail=r.get("issue_text"),
                               remediation=r.get("more_info", "")))
    except Exception as exc:
        log.warning("bandit parse: %s", exc)
    return findings, _meta(res, "bandit")


def gosec(repo: Path, cfg):
    if not have_tool("gosec") or not (repo / "go.mod").exists():
        return [], {"tool": "gosec", "status": "missing/skipped"}
    res = run_cmd(["gosec", "-fmt=json", "-quiet", "./..."], cwd=repo, timeout=1200)
    findings = []
    try:
        for r in json.loads(res["out"] or "{}").get("Issues", []):
            findings.append(_f(r.get("rule_id"), r.get("severity"), "gosec",
                               file=r.get("file"), line=r.get("line"), code=r.get("code"),
                               detail=r.get("details")))
    except Exception as exc:
        log.warning("gosec parse: %s", exc)
    return findings, _meta(res, "gosec")


def njsscan(repo: Path, cfg):
    if not have_tool("njsscan"):
        return [], {"tool": "njsscan", "status": "missing"}
    res = run_cmd(["njsscan", "--json", "."], cwd=repo, timeout=1200)
    findings = []
    try:
        for _, items in (json.loads(res["out"] or "{}").get("nodejs", {}) or {}).items():
            for r in items.get("files", []):
                for m in r.get("matches", []):
                    findings.append(_f(m.get("type"), m.get("severity"), "njsscan",
                                       file=r.get("file_path"), line=m.get("line"),
                                       code=m.get("match"), detail=m.get("message")))
    except Exception as exc:
        log.warning("njsscan parse: %s", exc)
    return findings, _meta(res, "njsscan")


def osv_scanner(repo: Path, cfg):
    if not have_tool("osv-scanner"):
        return [], {"tool": "osv-scanner", "status": "missing"}
    res = run_cmd(["osv-scanner", "--format", "json", "-r", "."], cwd=repo, timeout=1200)
    findings = []
    try:
        for result in json.loads(res["out"] or "{}").get("results", []):
            for pkg in result.get("packages", []):
                p = pkg.get("package", {})
                for v in pkg.get("vulnerabilities", []):
                    findings.append(_f(f"{p.get('name')}: {v.get('summary') or v.get('id')}",
                                       v.get("database_specific", {}).get("severity") or "high",
                                       "osv-scanner", category="dependency",
                                       file=result.get("source", {}).get("path"),
                                       detail=(v.get("details") or "")[:1200],
                                       references=v.get("references") or []))
    except Exception as exc:
        log.warning("osv parse: %s", exc)
    return findings, _meta(res, "osv-scanner")


def pip_audit(repo: Path, cfg):
    if not have_tool("pip-audit") or not (repo / "requirements.txt").exists():
        return [], {"tool": "pip-audit", "status": "missing/skipped"}
    res = run_cmd(["pip-audit", "-r", "requirements.txt", "--format", "json"], cwd=repo, timeout=1200)
    findings = []
    try:
        for dep in json.loads(res["out"] or "[]"):
            for v in dep.get("vulns", []):
                findings.append(_f(f"{dep.get('name')}: {v.get('id')}", "high", "pip-audit",
                                   category="dependency", file="requirements.txt",
                                   detail=" ".join(v.get("description", "").split())[:1200],
                                   remediation=f"Upgrade to {v.get('fix_versions')}"))
    except Exception as exc:
        log.warning("pip-audit parse: %s", exc)
    return findings, _meta(res, "pip-audit")


def npm_audit(repo: Path, cfg):
    if not have_tool("npm") or not (repo / "package.json").exists():
        return [], {"tool": "npm-audit", "status": "missing/skipped"}
    res = run_cmd(["npm", "audit", "--json", "--omit=dev"], cwd=repo, timeout=1200)
    findings = []
    try:
        for name, adv in (json.loads(res["out"] or "{}").get("vulnerabilities") or {}).items():
            for via in adv.get("via", []):
                if isinstance(via, str):
                    continue
                findings.append(_f(f"{name}: {via.get('title')}", via.get("severity"), "npm-audit",
                                   category="dependency", detail=via.get("url", ""),
                                   references=[via["url"]] if via.get("url") else []))
    except Exception as exc:
        log.warning("npm audit parse: %s", exc)
    return findings, _meta(res, "npm-audit")


def trivy(repo: Path, cfg):
    if not have_tool("trivy"):
        return [], {"tool": "trivy", "status": "missing"}
    res = run_cmd(["trivy", "fs", "--format", "json", "--quiet",
                   "--scanners", "vuln,misconfig,secret", "."], cwd=repo, timeout=1800)
    findings = []
    try:
        for target in json.loads(res["out"] or "{}").get("Results", []):
            fp = target.get("Target")
            for v in target.get("Vulnerabilities") or []:
                findings.append(_f(f"{v.get('PkgName')}: {v.get('Title') or v.get('VulnerabilityID')}",
                                   v.get("Severity"), "trivy", category="dependency", file=fp,
                                   detail=v.get("Description", "")[:1200]))
            for m in target.get("Misconfigurations") or []:
                findings.append(_f(m.get("Title"), m.get("Severity"), "trivy",
                                   category="misconfig", file=fp,
                                   detail=m.get("Description", ""),
                                   remediation=m.get("Resolution", "")))
            for s in target.get("Secrets") or []:
                findings.append(_f(f"Secret: {s.get('Title')}", s.get("Severity", "high"),
                                   "trivy", category="secret", file=fp, line=s.get("StartLine")))
    except Exception as exc:
        log.warning("trivy parse: %s", exc)
    return findings, _meta(res, "trivy")


def gitleaks(repo: Path, cfg):
    if not have_tool("gitleaks"):
        return [], {"tool": "gitleaks", "status": "missing"}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out = tf.name
    res = run_cmd(["gitleaks", "detect", "--no-git", "--source", ".", "--report-format", "json",
                   "--report-path", out, "--redact"], cwd=repo, timeout=1200)
    if not Path(out).exists() or Path(out).stat().st_size == 0:
        res = run_cmd(["gitleaks", "dir", ".", "-f", "json", "-r", out], cwd=repo, timeout=900)
    findings = []
    try:
        for r in json.loads(Path(out).read_text(encoding="utf-8", errors="replace") or "[]"):
            findings.append(_f(f"Secret: {r.get('RuleID')}", "high", "gitleaks",
                               category="secret", file=r.get("File"), line=r.get("StartLine"),
                               code=r.get("Match", "")[:400], detail=r.get("Description", "")))
    except Exception as exc:
        log.warning("gitleaks parse: %s", exc)
    finally:
        Path(out).unlink(missing_ok=True)
    return findings, _meta(res, "gitleaks")


def trufflehog(repo: Path, cfg):
    if not have_tool("trufflehog"):
        return [], {"tool": "trufflehog", "status": "missing"}
    res = run_cmd(["trufflehog", "filesystem", ".", "--json", "--no-update"], cwd=repo, timeout=1800)
    findings = []
    for line in (res["out"] or "").splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        det = r.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        findings.append(_f(f"Secret: {r.get('DetectorName')}",
                           "critical" if r.get("Verified") else "high", "trufflehog",
                           category="secret", file=det.get("file"), line=det.get("line"),
                           code=(r.get("Raw") or "")[:200]))
    return findings, _meta(res, "trufflehog")


RUNNERS = {"semgrep": semgrep, "bandit": bandit, "gosec": gosec, "njsscan": njsscan,
           "osv_scanner": osv_scanner, "pip_audit": pip_audit, "npm_audit": npm_audit,
           "trivy": trivy, "gitleaks": gitleaks, "trufflehog": trufflehog}