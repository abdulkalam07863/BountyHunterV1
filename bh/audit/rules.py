"""Regex heuristics for classes of bug generic SAST misses."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    cwe: str
    confidence: str
    globs: tuple
    pattern: str
    detail: str
    remediation: str
    multiline: bool = False

    def compiled(self):
        flags = re.IGNORECASE | re.MULTILINE | (re.DOTALL if self.multiline else 0)
        return re.compile(self.pattern, flags)


PY, JS = ("*.py",), ("*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs")
PHP, GO, JAVA = ("*.php",), ("*.go",), ("*.java", "*.kt")
ANY = ("*",)

RULES = [
    Rule("SEC-AWS", "AWS access key ID", "critical", "secret", "CWE-798", "high", ANY,
         r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "Hardcoded AWS key ID.",
         "Rotate and load from secrets manager."),
    Rule("SEC-AWS-SECRET", "AWS secret access key", "critical", "secret", "CWE-798", "medium", ANY,
         r"aws_?secret_?access_?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}", "AWS secret in source.", "Rotate."),
    Rule("SEC-STRIPE", "Stripe live secret key", "critical", "secret", "CWE-798", "high", ANY,
         r"\bsk_live_[0-9A-Za-z]{24,}\b", "Live payment key.", "Rotate."),
    Rule("SEC-GOOGLE", "Google API key", "medium", "secret", "CWE-798", "medium", ANY,
         r"\bAIza[0-9A-Za-z\-_]{35}\b", "Often unrestricted key.", "Restrict by referrer."),
    Rule("SEC-GH", "GitHub token", "critical", "secret", "CWE-798", "high", ANY,
         r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "Repo access token.", "Revoke."),
    Rule("SEC-SLACK", "Slack token / webhook", "high", "secret", "CWE-798", "high", ANY,
         r"(xox[baprs]-[0-9A-Za-z\-]{10,}|hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)",
         "Message injection.", "Rotate."),
    Rule("SEC-PRIVKEY", "Embedded private key", "critical", "secret", "CWE-321", "high", ANY,
         r"-----BEGIN (RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----", "Key material committed.",
         "Move to secret store."),
    Rule("SEC-JWT", "Hardcoded JWT", "medium", "secret", "CWE-798", "low", ANY,
         r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
         "Static token.", "Check expiry and key."),
    Rule("INJ-SQL-CONCAT", "SQL built by concatenation", "high", "injection", "CWE-89", "medium",
         PY + PHP + JAVA,
         r"(?:execute|query|raw|createStatement)\s*\(\s*[fr]?['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'\"]*['\"]\s*(?:\+|%|\.format)",
         "Unparameterised SQL.", "Use bound parameters."),
    Rule("INJ-SQL-FSTRING", "f-string SQL query", "medium", "injection", "CWE-89", "medium", PY,
         r"f['\"][^'\"]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*\{", "Interpolated SQL.", "Bind params."),
    Rule("INJ-CMD-SHELL", "shell=True", "high", "injection", "CWE-78", "medium", PY,
         r"subprocess\.(?:run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True",
         "Shell reinterpretation.", "Pass a list."),
    Rule("INJ-OS-SYSTEM", "os.system / popen", "medium", "injection", "CWE-78", "medium", PY,
         r"\bos\.(?:system|popen)\s*\(", "Shell execution.", "Prefer subprocess list."),
    Rule("INJ-EVAL", "eval / exec on dynamic data", "high", "injection", "CWE-95", "medium", PY + JS,
         r"(?<![\w.])(eval|exec)\s*\(\s*(?!['\"][^'\"]*['\"]\s*\))", "Dynamic code.", "Use literal_eval."),
    Rule("INJ-PICKLE", "Unsafe deserialisation", "high", "injection", "CWE-502", "medium", PY,
         r"(pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader))", "Arbitrary constructors.",
         "Use json or safe_load."),
    Rule("INJ-NODE-DESER", "Node deserialisation sink", "high", "injection", "CWE-502", "medium", JS,
         r"(unserialize\s*\(|node-serialize|deserialize\s*\()", "RCE-prone.", "Use JSON."),
    Rule("INJ-TEMPLATE", "SSTI sink", "high", "injection", "CWE-1336", "low", PY,
         r"(render_template_string|Template\s*\(|\.from_string\s*\()", "User template source.",
         "Render data, not source."),
    Rule("SSRF-REQUESTS", "Outbound request to variable URL", "medium", "ssrf", "CWE-918", "low", PY,
         r"requests\.(?:get|post|put|request|head)\s*\(\s*(?!['\"])", "Check host allow-listing.",
         "Allow-list and block metadata IPs."),
    Rule("SSRF-URLOPEN", "urllib / httpx to variable URL", "medium", "ssrf", "CWE-918", "low", PY,
         r"(urllib\.request\.urlopen|httpx\.(?:get|post)|aiohttp\.ClientSession)", "Verify target.",
         "Allow-list."),
    Rule("REDIR-OPEN", "Open redirect candidate", "low", "redirect", "CWE-601", "low", PY + JS,
         r"(redirect\s*\(\s*(?:request|req)\.|window\.location\s*=\s*(?!['\"])|res\.redirect\s*\(\s*(?!['\"]))",
         "Target from request.", "Same-origin check."),
    Rule("AUTH-VERIFY-FALSE", "TLS verification disabled", "medium", "tls", "CWE-295", "high", PY,
         r"verify\s*=\s*False", "MITM trivial.", "Enable verification."),
    Rule("AUTH-JWT-NONE", "JWT algorithm not pinned", "high", "auth", "CWE-347", "low", PY + JS,
         r"(algorithms\s*=\s*\[\s*\]|jwt\.decode\s*\([^)]*verify\s*=\s*False)", "Alg confusion.",
         "Pin an allow-list."),
    Rule("AUTH-MD5", "MD5/SHA1 for security", "low", "crypto", "CWE-328", "medium", PY + JS + JAVA,
         r"(hashlib\.(?:md5|sha1)|createHash\(\s*['\"](?:md5|sha1))", "Weak digest.", "Use SHA-256/argon2."),
    Rule("AUTH-RANDOM", "Non-CSPRNG randomness", "medium", "crypto", "CWE-338", "medium", PY + JS,
         r"(random\.random\(\)|Math\.random\(\))", "Predictable tokens.", "Use secrets."),
    Rule("AUTH-HARDCODED-PASS", "Hardcoded credential compare", "medium", "auth", "CWE-259", "low", ANY,
         r"(password|passwd|secret|api_?key)\s*(?:==|===|!=|!==)\s*['\"][^'\"]{4,}['\"]",
         "Literal credential.", "Load from config."),
    Rule("AUTH-DEBUG", "Debug mode enabled", "medium", "misconfig", "CWE-489", "high", PY,
         r"(debug\s*=\s*True|DEBUG\s*=\s*True)", "Console exposed.", "Disable in prod."),
    Rule("WEB-CORS-STAR", "Permissive CORS", "medium", "misconfig", "CWE-942", "medium", ANY,
         r"(Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]?\*|origin\s*:\s*['\"]\*['\"])",
         "Wildcard origin.", "Echo validated origin."),
    Rule("WEB-XSS-INNERHTML", "innerHTML assignment", "medium", "xss", "CWE-79", "low", JS,
         r"\.innerHTML\s*=\s*(?!['\"`][^'\"`$]*['\"`]\s*;)", "Dynamic HTML sink.", "textContent or sanitise."),
    Rule("WEB-XSS-HTML", "Raw HTML render", "medium", "xss", "CWE-79", "low", PY,
         r"(\|\s*safe\b|Markup\(|dangerouslySetInnerHTML)", "Trusted markup.", "Sanitise."),
    Rule("WEB-CSRF", "State-changing route", "low", "csrf", "CWE-352", "low", PY,
         r"@app\.(?:post|put|delete)\(|@router\.(?:post|put|delete)\(", "Verify CSRF.", "CSRF token."),
    Rule("WEB-PROTO-POLLUTE", "Prototype pollution sink", "medium", "injection", "CWE-1321", "low", JS,
         r"(Object\.assign\s*\(\s*\w+\s*,\s*(?:req\.|body)|merge\s*\(\s*\w+\s*,\s*(?:req\.|body))",
         "Deep merge of request data.", "Hardened merge."),
    Rule("WEB-PATH-TRAV", "File open with variable path", "medium", "traversal", "CWE-22", "low", PY + JS,
         r"(open\s*\(\s*(?:os\.path\.join|path\.join|f['\"])|readFile(?:Sync)?\s*\(\s*(?:path\.join|req\.))",
         "Check ../ escape.", "Confine to base dir."),
    Rule("WEB-GRAPHQL-INTRO", "GraphQL introspection on", "low", "misconfig", "CWE-200", "low", ANY,
         r"(introspection\s*:\s*true|__schema)", "Schema disclosure.", "Disable in prod."),
    Rule("WEB-ACTUATOR", "Spring actuator exposure", "medium", "misconfig", "CWE-200", "medium", ANY,
         r"(management\.endpoints\.web\.exposure|/actuator/env)", "Leaks env.", "Restrict internally."),
    Rule("INFRA-DOCKER-ROOT", "Container runs as root", "low", "misconfig", "CWE-250", "medium",
         ("Dockerfile", "*.Dockerfile"), r"^(?!.*\bUSER\b)", "No USER directive.", "Add non-root USER."),
    Rule("INFRA-GHA-PWN", "Actions script injection", "high", "ci", "CWE-94", "medium",
         (".github/workflows/*.yml",), r"run:.*\$\{\{\s*github\.event\.(?:issue|pull_request|comment)\.(?:title|body)",
         "Attacker text in shell step.", "Use env: and $VAR."),
    Rule("INFRA-GHA-UNPINNED", "Unpinned action", "low", "supply-chain", "CWE-1357", "low",
         (".github/workflows/*.yml",), r"uses:\s*(?!actions/)[\w.\-]+/[\w.\-]+@(?:main|master|v\d+)\b",
         "Mutable tag.", "Pin to SHA."),
    Rule("INFRA-TF-PUBLIC", "Public bucket / open SG", "high", "cloud", "CWE-284", "medium", ("*.tf",),
         r"(acl\s*=\s*\"public-read\"|0\.0\.0\.0/0)", "World reachable.", "Narrow CIDR/ACL."),
    Rule("HYG-TODO-SEC", "Security TODO", "low", "hygiene", "CWE-1059", "low", ANY,
         r"(TODO|FIXME|XXX|HACK)[^\n]{0,80}(secur|auth|valid|sanitis|sanitiz|escape|token|password)",
         "Incomplete control.", "Track and verify."),
    Rule("HYG-ENV-COMMITTED", ".env tracked", "high", "secret", "CWE-538", "high",
         (".env", "*.env", ".env.*"), r"\S+=\S+", "Env file in git.", "Add to .gitignore."),
]

SKIP_DIRS = {"node_modules", "vendor", ".git", "dist", "build", "target", ".venv", "venv",
             "__pycache__", "coverage", ".next", ".nuxt", "bower_components", "third_party",
             "Pods", ".terraform"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".woff", ".woff2",
            ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".gz", ".pdf", ".map", ".lock"}
