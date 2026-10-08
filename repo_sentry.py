#!/usr/bin/env python3
"""repo_sentry - a zero-dependency static analysis and architecture-audit CLI.

Pure Python 3.9+ standard library. Run ``python repo_sentry.py --help`` for
usage, ``--list-rules`` for the rule catalog and ``--self-test`` to execute
the embedded unittest suite.
"""
from __future__ import annotations

import argparse
import ast
import bisect
import collections
import contextlib
import dataclasses
import fnmatch
import hashlib
import io
import json
import math
import os
import posixpath
import re
import stat as statmod
import subprocess
import sys
import tempfile
import unittest
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

__version__ = "1.2.0"
TOOL_NAME = "repo_sentry"

SEVERITIES: Tuple[str, ...] = ("low", "medium", "high", "critical")
SEVERITY_RANK: Dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}
CONFIDENCES: Tuple[str, ...] = ("low", "medium", "high")

# Newer AST node types, guarded so the tool still runs on Python 3.9.
_AST_MATCH = getattr(ast, "Match", None)
_AST_MATCH_CASE = getattr(ast, "match_case", None)
_AST_TRYSTAR = getattr(ast, "TryStar", None)
_TRY_TYPES: Tuple[type, ...] = (ast.Try,) + ((_AST_TRYSTAR,) if _AST_TRYSTAR else ())
_FUNC_TYPES: Tuple[type, ...] = (ast.FunctionDef, ast.AsyncFunctionDef)
_BLOCK_TYPES: Tuple[type, ...] = (
    (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)
    + _TRY_TYPES
    + ((_AST_MATCH,) if _AST_MATCH else ())
)
_STDLIB_NAMES = frozenset(getattr(sys, "stdlib_module_names", ()))


# --------------------------------------------------------------------------
# Rule catalog
# --------------------------------------------------------------------------
class Rule:
    __slots__ = ("id", "title", "severity", "category", "description", "remediation", "languages")

    def __init__(self, rule_id: str, title: str, severity: str, category: str,
                 description: str, remediation: str, languages: str) -> None:
        self.id = rule_id
        self.title = title
        self.severity = severity
        self.category = category
        self.description = description
        self.remediation = remediation
        self.languages = languages


RULES: Dict[str, Rule] = collections.OrderedDict()
for _r in (
    Rule("RS-ARCH-001", "Circular import", "high", "architecture",
         "Strongly connected components of size > 1 (and self-imports) in the local "
         "module import graph. Cycles that exist only through soft imports (inside "
         "functions or under `if TYPE_CHECKING:`) are reported as low.",
         "Break the cycle: move shared code into a lower-level module, invert the "
         "dependency, or defer the import into the function that needs it.",
         "python"),
    Rule("RS-ARCH-002", "Layer or forbidden-import violation", "high", "architecture",
         "A module in a lower layer imports a higher layer (layers are ordered from "
         "outermost to innermost), or an import matches a `forbidden_imports` rule.",
         "Depend inward only: expose the needed behaviour through an interface in the "
         "lower layer, or move the code to the layer that owns it.",
         "python"),
    Rule("RS-ASYNC-001", "Blocking call inside async def", "high", "async",
         "A synchronous, blocking call (time.sleep, requests.*, urlopen, subprocess, "
         "open()/file reads, blocking socket calls, input()) executed directly in a "
         "coroutine blocks the whole event loop.",
         "Use the async equivalent (asyncio.sleep, aiohttp/httpx.AsyncClient, "
         "asyncio.create_subprocess_exec, aiofiles) or offload with "
         "`await asyncio.to_thread(...)` / `loop.run_in_executor(...)`.",
         "python"),
    Rule("RS-ASYNC-002", "Fire-and-forget task", "medium", "async",
         "asyncio.create_task / ensure_future / loop.create_task whose result is "
         "discarded or stored in a variable that is never awaited, gathered, returned "
         "or given add_done_callback. Such tasks can be garbage-collected mid-flight and "
         "their exceptions are silently lost.",
         "Keep a strong reference and await/gather the task, use asyncio.TaskGroup, or "
         "attach add_done_callback to surface exceptions.",
         "python"),
    Rule("RS-ASYNC-003", "Unprotected shared mutable state", "medium", "async",
         "A module-level list/dict/set is mutated inside an async def with no "
         "asyncio.Lock/threading.Lock held in scope. Concurrent coroutines can "
         "interleave between awaits and corrupt the structure.",
         "Guard the mutation with `async with lock:` or move the state into an object "
         "that owns its own lock.",
         "python"),
    Rule("RS-RES-001", "Unmanaged resource", "medium", "resources",
         "open(), socket.socket, urlopen, sqlite3.connect, tempfile.*TemporaryFile, "
         "subprocess.Popen or zipfile.ZipFile used outside `with`/`async with`, "
         "contextlib.closing, ExitStack.enter_context or a try/finally close(). Returned, "
         "yielded or stored resources are exempt.",
         "Wrap the resource in a `with` block or close it in a `finally` clause.",
         "python"),
    Rule("RS-QUAL-001", "Cyclomatic complexity too high", "medium", "quality",
         "McCabe complexity above `max_cyclomatic_complexity` (default 10); high when "
         "above twice the threshold. Nested functions are scored separately.",
         "Split the function into smaller units, replace branch ladders with lookup "
         "tables or polymorphism, and extract guard clauses.",
         "python"),
    Rule("RS-QUAL-002", "Nesting too deep", "low", "quality",
         "Nested if/for/while/try/with/match deeper than `max_nesting_depth` (default 4).",
         "Flatten with early returns/continues, extract helper functions, or invert "
         "conditions.",
         "python"),
    Rule("RS-QUAL-003", "Bare except", "medium", "quality",
         "`except:` catches everything including KeyboardInterrupt and SystemExit.",
         "Catch the specific exception types you can handle, or at least `except "
         "Exception:` and re-raise what you cannot handle.",
         "python"),
    Rule("RS-QUAL-004", "Swallowed exception", "medium", "quality",
         "`except Exception`/`BaseException` whose body only passes, `...` or continues "
         "silently discards errors.",
         "Log the exception, handle it, or narrow the exception type and re-raise.",
         "python"),
    Rule("RS-SEC-001", "Hardcoded secret (known pattern)", "critical", "security",
         "AWS access keys, GitHub/Slack/Stripe/Google tokens, JWTs, PEM private key "
         "blocks, URLs with embedded credentials and hardcoded password/secret/api_key/"
         "token assignments. Critical for provider keys, high for the rest. Output is "
         "always redacted.",
         "Remove the secret from the repository, rotate it immediately and load it "
         "from an environment variable or secret manager. Purge it from git history.",
         "all"),
    Rule("RS-SEC-002", "High-entropy string", "medium", "security",
         "Quoted or assignment-adjacent tokens of at least `min_secret_length` whose "
         "Shannon entropy exceeds the charset-specific threshold (hex/base64/mixed). "
         "UUIDs, commit hashes, placeholders, URLs, import paths, lockfiles and minified "
         "files are skipped.",
         "If this is a credential, rotate it and move it out of source. If it is not, "
         "suppress with `reposentry: ignore RS-SEC-002`.",
         "all"),
    Rule("RS-SEC-003", "Command injection sink", "high", "security",
         "os.system, os.popen, subprocess.* with shell=True, commands.getoutput; JS "
         "child_process.exec/execSync; C system()/popen(); shell eval and `curl | sh`. "
         "Critical when the command is non-constant, medium for a constant string.",
         "Avoid the shell: pass an argument list to subprocess.run/execFile, validate "
         "and escape inputs (shlex.quote), and never pipe downloads into a shell.",
         "python, js, c, shell"),
    Rule("RS-SEC-004", "Dynamic code execution / unsafe deserialization", "high", "security",
         "eval/exec/compile/__import__ on non-constants, pickle.loads, yaml.load without "
         "SafeLoader, marshal.loads; JS eval/new Function/setTimeout(string)/innerHTML=; "
         "C gets/strcpy/strcat/sprintf. Critical when the input is non-constant.",
         "Use ast.literal_eval, json, yaml.safe_load, importlib.import_module with an "
         "allow-list, textContent instead of innerHTML, and bounded string functions.",
         "python, js, c"),
    Rule("RS-SEC-005", "Secret in git history", "high", "security",
         "A known secret pattern was added in an earlier commit and is no longer present in the working tree "
         "(enable with --history). Deleting a secret from the latest commit does not revoke it.",
         "Rotate the credential immediately; rewriting history (git filter-repo / BFG) is optional and "
         "only helps if no one has cloned the repo.",
         "all"),
    Rule("RS-SEC-006", "Insecure configuration (JS/TS)", "medium", "security",
         "JS/TS: pattern-based, approximate. TLS verification disabled (rejectUnauthorized: false, "
         "NODE_TLS_REJECT_UNAUTHORIZED='0') [high]; createHash('md5'|'sha1') [medium; fine for non-security "
         "checksums]; Math.random() near token/secret/password/nonce/session/csrf/otp identifiers [medium]; "
         "JWT algorithms containing 'none' [high]; CORS origin '*' with credentials: true [medium]; "
         "dangerouslySetInnerHTML with non-constant __html [high] (constant: low); fs paths built from "
         "req/params/query/body/argv [medium, low confidence]; new RegExp() from request data [low]. "
         "Severity is downgraded one level in test files.",
         "Keep TLS verification on, hash credentials with bcrypt/scrypt/argon2, generate secrets with "
         "crypto.randomBytes, pin JWT algorithms, avoid wildcard CORS with credentials, sanitize HTML, "
         "and validate user-controlled paths and patterns.",
         "js"),
    Rule("RS-SYS-001", "File could not be parsed", "low", "system",
         "The file could not be read, decoded or parsed (SyntaxError, encoding error). "
         "The scan continues; the file is still pattern-scanned for secrets.",
         "Fix the syntax or encoding, or exclude the file with `ignore_globs`.",
         "all"),
):
    RULES[_r.id] = _r
del _r

RULE_ID_RE = re.compile(r"RS-[A-Z]+-\d{3}")


# --------------------------------------------------------------------------
# Finding model
# --------------------------------------------------------------------------
@dataclasses.dataclass
class Finding:
    rule_id: str
    severity: str
    confidence: str
    file: str
    line: int
    col: int
    message: str
    snippet: str
    remediation: str

    def to_dict(self) -> Dict[str, object]:
        return collections.OrderedDict((
            ("rule_id", self.rule_id),
            ("severity", self.severity),
            ("confidence", self.confidence),
            ("file", self.file),
            ("line", self.line),
            ("col", self.col),
            ("message", self.message),
            ("snippet", self.snippet),
            ("remediation", self.remediation),
        ))

    def sort_key(self) -> Tuple[int, str, int, str, int, str]:
        return (-SEVERITY_RANK[self.severity], self.file, self.line, self.rule_id, self.col, self.message)

    def fingerprint(self) -> str:
        normalized = " ".join(self.snippet.split())
        raw = "%s|%s|%s" % (self.rule_id, self.file, normalized)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def redact_secret(secret: str) -> str:
    """Never print a full secret: first 4 characters, ****, and the length."""
    return "%s****[len=%d]" % (secret[:4], len(secret))


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
class ConfigError(Exception):
    """Invalid configuration, baseline or usage (exit code 2)."""


DEFAULT_THRESHOLDS: Dict[str, float] = {
    "max_cyclomatic_complexity": 10,
    "max_nesting_depth": 4,
    "entropy_hex": 3.0,
    "entropy_base64": 4.5,
    "min_secret_length": 20,
}
DEFAULT_IGNORE_DIRS: List[str] = [".git", "venv", ".venv", "node_modules", "__pycache__", "dist", "build",
                                  "coverage", ".next", ".nuxt", "out"]
DEFAULT_IGNORE_GLOBS: List[str] = ["*.min.js", "*.min.css", "*.map", "*.lock"]
DEFAULT_PACKAGE_ROOTS: List[str] = ["src", "."]
CONFIG_KEYS = {
    "ignore_dirs", "ignore_globs", "respect_gitignore", "thresholds", "severity_overrides",
    "layers", "forbidden_imports", "package_roots", "extra_blocking_calls", "extra_dangerous_sinks",
}


@dataclasses.dataclass
class Config:
    ignore_dirs: List[str] = dataclasses.field(default_factory=lambda: list(DEFAULT_IGNORE_DIRS))
    ignore_globs: List[str] = dataclasses.field(default_factory=lambda: list(DEFAULT_IGNORE_GLOBS))
    respect_gitignore: bool = True
    thresholds: Dict[str, float] = dataclasses.field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))
    severity_overrides: Dict[str, str] = dataclasses.field(default_factory=dict)
    layers: List[str] = dataclasses.field(default_factory=list)
    forbidden_imports: List[Dict[str, str]] = dataclasses.field(default_factory=list)
    package_roots: List[str] = dataclasses.field(default_factory=lambda: list(DEFAULT_PACKAGE_ROOTS))
    extra_blocking_calls: List[str] = dataclasses.field(default_factory=list)
    extra_dangerous_sinks: List[str] = dataclasses.field(default_factory=list)
    max_file_bytes: int = 1024 * 1024


def _expect_str_list(value: object, key: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError("config key '%s' must be a list of strings" % key)
    return list(value)


def config_from_dict(data: object, source: str = "<config>") -> Tuple[Config, List[str]]:
    """Build a Config from a parsed JSON object. Unknown keys become warnings,
    invalid values raise ConfigError."""
    if not isinstance(data, dict):
        raise ConfigError("%s: top-level value must be a JSON object" % source)
    warnings: List[str] = []
    cfg = Config()
    for key in data:
        if key not in CONFIG_KEYS:
            warnings.append("%s: unknown config key '%s' ignored" % (source, key))
    if "ignore_dirs" in data:
        cfg.ignore_dirs = _expect_str_list(data["ignore_dirs"], "ignore_dirs")
    if "ignore_globs" in data:
        cfg.ignore_globs = _expect_str_list(data["ignore_globs"], "ignore_globs")
    if "respect_gitignore" in data:
        if not isinstance(data["respect_gitignore"], bool):
            raise ConfigError("config key 'respect_gitignore' must be a boolean")
        cfg.respect_gitignore = data["respect_gitignore"]
    if "thresholds" in data:
        th = data["thresholds"]
        if not isinstance(th, dict):
            raise ConfigError("config key 'thresholds' must be an object")
        for name, value in th.items():
            if name not in DEFAULT_THRESHOLDS:
                warnings.append("%s: unknown threshold '%s' ignored" % (source, name))
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                raise ConfigError("threshold '%s' must be a non-negative number" % name)
            cfg.thresholds[name] = value
    if "severity_overrides" in data:
        ov = data["severity_overrides"]
        if not isinstance(ov, dict):
            raise ConfigError("config key 'severity_overrides' must be an object")
        for rule_id, sev in ov.items():
            if not isinstance(sev, str) or sev not in SEVERITIES:
                raise ConfigError("severity override for '%s' must be one of %s" % (rule_id, ", ".join(SEVERITIES)))
            if rule_id not in RULES:
                warnings.append("%s: severity override for unknown rule '%s' ignored" % (source, rule_id))
                continue
            cfg.severity_overrides[rule_id] = sev
    if "layers" in data:
        cfg.layers = _expect_str_list(data["layers"], "layers")
    if "forbidden_imports" in data:
        fi = data["forbidden_imports"]
        if not isinstance(fi, list):
            raise ConfigError("config key 'forbidden_imports' must be a list")
        for item in fi:
            if (not isinstance(item, dict) or not isinstance(item.get("from"), str)
                    or not isinstance(item.get("to"), str)):
                raise ConfigError("each forbidden_imports entry must be {\"from\": str, \"to\": str}")
            cfg.forbidden_imports.append({"from": item["from"], "to": item["to"]})
    if "package_roots" in data:
        cfg.package_roots = _expect_str_list(data["package_roots"], "package_roots") or ["."]
    if "extra_blocking_calls" in data:
        cfg.extra_blocking_calls = _expect_str_list(data["extra_blocking_calls"], "extra_blocking_calls")
    if "extra_dangerous_sinks" in data:
        cfg.extra_dangerous_sinks = _expect_str_list(data["extra_dangerous_sinks"], "extra_dangerous_sinks")
    return cfg, warnings


def load_config(path: str) -> Tuple[Config, List[str]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise ConfigError("cannot read config %s: %s" % (path, exc))
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ConfigError("invalid JSON in config %s: %s" % (path, exc))
    return config_from_dict(data, path)


# --------------------------------------------------------------------------
# File discovery
# --------------------------------------------------------------------------
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tif", ".tiff", ".svgz", ".psd",
    ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".jar", ".war", ".whl",
    ".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe", ".o", ".a", ".lib", ".obj", ".class", ".wasm",
    ".mp3", ".mp4", ".wav", ".ogg", ".avi", ".mov", ".mkv", ".flac", ".woff", ".woff2", ".ttf",
    ".otf", ".eot", ".sqlite", ".db", ".bin", ".dat", ".iso", ".img", ".dmg", ".pkl", ".pickle",
    ".npy", ".npz", ".parquet", ".ds_store",
}
LOCKFILE_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "pipfile.lock", "cargo.lock", "go.sum", "composer.lock", "gemfile.lock", "packages.lock.json",
    "flake.lock", "bun.lockb", "uv.lock", "pdm.lock", "mix.lock", "pubspec.lock",
}
PY_EXTS = {".py", ".pyw", ".pyi"}
JS_EXTS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
C_EXTS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".ipp"}
SHELL_EXTS = {".sh", ".bash", ".zsh", ".ksh"}


def _gitglob_to_regex(pattern: str) -> str:
    out: List[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern.startswith("**", i):
                if pattern.startswith("**/", i):
                    out.append("(?:.*/)?")
                    i += 3
                    continue
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
            else:
                cls = pattern[i + 1:j]
                if cls.startswith("!"):
                    cls = "^" + cls[1:]
                out.append("[" + cls.replace("\\", "\\\\") + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


class GitIgnore:
    """A small .gitignore matcher: comments, negation, directory-only patterns,
    anchored patterns, `*`, `?`, `[...]` and `**`. Last matching rule wins."""

    def __init__(self) -> None:
        self._rules: List[Tuple[str, "re.Pattern[str]", bool, bool]] = []

    def load(self, base_rel: str, text: str) -> None:
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            negate = line.startswith("!")
            if negate:
                line = line[1:]
            if line.startswith("\\"):
                line = line[1:]
            dir_only = line.endswith("/")
            line = line.rstrip("/")
            if not line:
                continue
            anchored = "/" in line
            if line.startswith("/"):
                line = line.lstrip("/")
            body = _gitglob_to_regex(line)
            prefix = "^" if anchored else "(?:^|.*/)"
            try:
                rx = re.compile(prefix + "(?P<m>" + body + ")(?P<rest>/.*)?$")
            except re.error:
                continue
            self._rules.append((base_rel, rx, negate, dir_only))

    def is_ignored(self, rel_path: str, is_dir: bool) -> bool:
        result = False
        for base, rx, negate, dir_only in self._rules:
            if base:
                if not rel_path.startswith(base + "/"):
                    continue
                sub = rel_path[len(base) + 1:]
            else:
                sub = rel_path
            m = rx.match(sub)
            if not m:
                continue
            if dir_only and not m.group("rest") and not is_dir:
                continue
            result = not negate
        return result


@dataclasses.dataclass
class FileEntry:
    rel: str
    path: str
    size: int


def _rel_join(rel_dir: str, name: str) -> str:
    return name if not rel_dir else rel_dir + "/" + name


def discover_files(root: str, config: Config, warnings: List[str]) -> List[FileEntry]:
    """Deterministic, symlink-safe walk honouring ignore_dirs, ignore_globs,
    .gitignore (when enabled) and the file size cap."""
    entries: List[FileEntry] = []
    if os.path.isfile(root):
        st = os.stat(root)
        if st.st_size <= config.max_file_bytes:
            entries.append(FileEntry(os.path.basename(root).replace(os.sep, "/"), root, st.st_size))
        return entries
    gi = GitIgnore() if config.respect_gitignore else None
    ignore_dirs = set(config.ignore_dirs)
    globs = list(config.ignore_globs)
    seen_real: Set[str] = set()

    def _on_error(exc: OSError) -> None:
        warnings.append("cannot list %s: %s" % (getattr(exc, "filename", "?"), exc.strerror or exc))

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=_on_error, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        if rel_dir == ".":
            rel_dir = ""
        if gi is not None and ".gitignore" in filenames:
            try:
                with open(os.path.join(dirpath, ".gitignore"), "r", encoding="utf-8", errors="replace") as fh:
                    gi.load(rel_dir, fh.read())
            except OSError:
                pass
        kept: List[str] = []
        for d in sorted(dirnames):
            rel = _rel_join(rel_dir, d)
            if d in ignore_dirs or rel in ignore_dirs:
                continue
            if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(d, g) for g in globs):
                continue
            if os.path.islink(os.path.join(dirpath, d)):
                continue
            if gi is not None and gi.is_ignored(rel, True):
                continue
            kept.append(d)
        dirnames[:] = kept
        for name in sorted(filenames):
            rel = _rel_join(rel_dir, name)
            full = os.path.join(dirpath, name)
            if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(name, g) for g in globs):
                continue
            if gi is not None and gi.is_ignored(rel, False):
                continue
            try:
                real = os.path.realpath(full)
                st = os.stat(full)
            except OSError as exc:
                warnings.append("cannot stat %s: %s" % (rel, exc.strerror or exc))
                continue
            if not statmod.S_ISREG(st.st_mode):
                continue
            if real in seen_real:
                continue
            seen_real.add(real)
            if st.st_size > config.max_file_bytes:
                continue
            entries.append(FileEntry(rel, full, st.st_size))
    return entries


def detect_language(rel: str, first_line: str) -> str:
    ext = os.path.splitext(rel)[1].lower()
    if ext in PY_EXTS:
        return "python"
    if ext in JS_EXTS:
        return "js"
    if ext in C_EXTS:
        return "c"
    if ext in SHELL_EXTS:
        return "shell"
    if first_line.startswith("#!"):
        shebang = first_line.lower()
        if "python" in shebang:
            return "python"
        if "node" in shebang or "deno" in shebang or "bun" in shebang:
            return "js"
        if re.search(r"\b(ba|z|k|da|a)?sh\b", shebang):
            return "shell"
    return "text"


def is_lockfile(rel: str) -> bool:
    base = os.path.basename(rel).lower()
    return base in LOCKFILE_NAMES or base.endswith(".lock") or base.endswith("-lock.json") or base.endswith(".lock.json")


def is_minified(rel: str, lines: Sequence[str]) -> bool:
    base = os.path.basename(rel).lower()
    if ".min." in base or base.endswith(".bundle.js"):
        return True
    return any(len(line) > 2000 for line in lines)


# --------------------------------------------------------------------------
# Source file holder with secret redaction
# --------------------------------------------------------------------------
DIRECTIVE_RE = re.compile(r"reposentry:\s*ignore\b((?:\s*,?\s*RS-[A-Z]+-\d{3})*)", re.IGNORECASE)


class SourceFile:
    def __init__(self, rel: str, path: str, text: str, lang: str) -> None:
        self.rel = rel
        self.path = path
        self.text = text
        self.lines: List[str] = text.splitlines()
        self.lang = lang
        self.redactions: Dict[int, List[Tuple[int, int]]] = {}
        self.redacted_lines: Set[int] = set()
        self.directives: Dict[int, Set[str]] = {}
        for idx, line in enumerate(self.lines, 1):
            if "reposentry" in line.lower():
                m = DIRECTIVE_RE.search(line)
                if m:
                    ids = set(RULE_ID_RE.findall(m.group(1) or ""))
                    self.directives[idx] = {i.upper() for i in ids} if ids else {"*"}

    def add_redaction(self, line: int, start: int, end: int) -> None:
        self.redactions.setdefault(line, []).append((start, end))

    def raw_line(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1]
        return ""

    def redacted_line(self, line: int) -> str:
        text = self.raw_line(line)
        if line in self.redacted_lines:
            return redact_secret(text.strip()) if text.strip() else ""
        spans = self.redactions.get(line)
        if not spans:
            return text
        merged: List[List[int]] = []
        for start, end in sorted(spans):
            if merged and start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        out = text
        for start, end in reversed(merged):
            out = out[:start] + redact_secret(text[start:end]) + out[end:]
        return out

    def snippet(self, line: int, max_len: int = 160) -> str:
        s = self.redacted_line(line).strip()
        if len(s) > max_len:
            s = s[:max_len - 1] + "…"
        return s

    def is_suppressed(self, line: int, rule_id: str) -> bool:
        for ln in (line, line - 1):
            ids = self.directives.get(ln)
            if ids and ("*" in ids or rule_id in ids):
                return True
        return False


# --------------------------------------------------------------------------
# Secret scanning (all text files)
# --------------------------------------------------------------------------
SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]", str]] = [
    ("AWS access key ID", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"), "critical"),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36,}\b"), "critical"),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "critical"),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])"), "critical"),
    ("Slack webhook URL", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"), "high"),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"), "critical"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"), "high"),
    ("JSON Web Token", re.compile(r"(?<![A-Za-z0-9_\-./])eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}(?![A-Za-z0-9_\-])"), "high"),
    ("URL with embedded credentials", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s/:@'\"]+:[^\s@/'\"]{3,}@[^\s'\"]+"), "high"),
]
PEM_BEGIN_RE = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
PEM_END_RE = re.compile(r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
PEM_MAX_LINES = 200  # a real private key body is well under this; beyond it the BEGIN marker is just text
_SECRET_KEYWORD = (r"(?<![A-Za-z0-9])(password|passwd|secret|api[_\-]?key|apikey|auth[_\-]?token|"
                   r"access[_\-]?token|access[_\-]?key|secret[_\-]?key|private[_\-]?key|client[_\-]?secret|"
                   r"token)(?![A-Za-z0-9])")
ASSIGN_SECRET_RE = re.compile(_SECRET_KEYWORD + r"""["']?\s*(?:=>|[:=])\s*(["'])([^"'\n]{8,})\2""", re.IGNORECASE)
ENV_SECRET_RE = re.compile(r"^\s*(?:export\s+)?([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*=\s*([^\s\"'#]{8,})\s*(?:#.*)?$")
YAML_SECRET_RE = re.compile(r"^\s*-?\s*([\w\-]*(?:password|passwd|secret|token|api[_\-]?key|apikey)[\w\-]*)\s*:\s+([^\s\"'#{$%<][^\s#]{7,})\s*(?:#.*)?$", re.IGNORECASE)
ENV_STYLE_EXTS = {".env", ".sh", ".bash", ".zsh", ".ksh", ".ini", ".cfg", ".conf", ".properties", ".txt", ""}
YAML_EXTS = {".yaml", ".yml"}
PLACEHOLDER_WORDS = ("example", "changeme", "change_me", "change-me", "xxxx", "your_", "your-", "<", ">",
                     "dummy", "test", "sample", "placeholder", "todo", "fixme", "replace", "insert",
                     "password", "secret", "redacted", "lorem", "null", "none", "fake", "mock")
KNOWN_DEFAULT_SECRETS = frozenset((
    "youshallnotpass", "admin", "administrator", "adminadmin", "root", "toor", "guest", "default", "changeit",
    "letmein", "qwerty12", "password1", "password123", "secret123", "12345678", "123456789", "1234567890",
    "welcome1", "p@ssw0rd", "passw0rd", "pass1234"))
EXAMPLE_FILE_RE = re.compile(r"(?:^|[.\-_])(?:example|sample|template|dist|tmpl)(?:[.\-_]|$)", re.IGNORECASE)


def is_example_file(rel: str) -> bool:
    """.env.example, application.example.yml, config.sample.json ... -- files meant to hold placeholders."""
    return bool(EXAMPLE_FILE_RE.search(os.path.basename(rel)))


UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_\-]+$")
PATHLIKE_RE = re.compile(r"^(?:\.{0,2}/|[A-Za-z0-9_\-]+(?:/[A-Za-z0-9_.\-]+)+/?$)")
HASH_CONTEXT_WORDS = ("sha256", "sha512", "sha1", "sha-", "integrity", "checksum", "digest", "md5",
                      "commit", "revision", "fingerprint", "hash", "blake2", "crc")
# cheap prefilters so the expensive per-pattern regexes only run on candidate lines
SECRET_TRIGGER_RE = re.compile(r"AKIA|ASIA|gh[opsur]_|github_pat_|xox[abprs]-|hooks\.slack\.com|_live_|AIza|eyJ|://")
ASSIGN_TRIGGER_RE = re.compile(r"password|passwd|secret|key|token", re.IGNORECASE)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = float(len(s))
    return -sum((c / n) * math.log2(c / n) for c in collections.Counter(s).values())


def looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    if len(set(low)) <= 2:
        return True
    if any(w in low for w in PLACEHOLDER_WORDS):
        return True
    if any(t in value for t in ("${", "{{", "%s", "%(", "$(", "{0}", "os.environ", "getenv", "process.env", "env(")):
        return True
    if value.startswith(("$", "{", "%", "@", "`")):
        return True
    return False


def _entropy_token_regexes(min_len: int) -> Tuple["re.Pattern[str]", "re.Pattern[str]", "re.Pattern[str]"]:
    quoted = re.compile(r"""(["'`])([A-Za-z0-9+/=_\-]{%d,})\1""" % min_len)
    adjacent = re.compile(r"""(?:=>|[=:])\s*([A-Za-z0-9+/=_\-]{%d,})(?![A-Za-z0-9+/=_\-])""" % min_len)
    trigger = re.compile(r"[A-Za-z0-9+/=_\-]{%d,}" % min_len)
    return quoted, adjacent, trigger


_ENTROPY_RE_CACHE: Dict[int, Tuple["re.Pattern[str]", "re.Pattern[str]", "re.Pattern[str]"]] = {}


def scan_secrets(sf: SourceFile, config: Config, emit, entropy_enabled: bool) -> None:
    """RS-SEC-001 (known patterns, every text file) and RS-SEC-002 (entropy,
    unless lockfile/minified). Registers redaction spans on the SourceFile so
    that every snippet of a secret-bearing line is redacted."""
    th = config.thresholds
    min_len = int(th.get("min_secret_length", 20))
    regs = _ENTROPY_RE_CACHE.get(min_len)
    if regs is None:
        regs = _ENTROPY_RE_CACHE[min_len] = _entropy_token_regexes(min_len)
    quoted_re, adjacent_re, entropy_trigger_re = regs
    ext = os.path.splitext(sf.rel)[1].lower()
    base = os.path.basename(sf.rel).lower()
    env_style = ext in ENV_STYLE_EXTS or base.startswith(".env") or base == "dockerfile"
    yaml_style = ext in YAML_EXTS
    remediation = RULES["RS-SEC-001"].remediation
    total = len(sf.lines)
    example_file = is_example_file(sf.rel)
    if example_file:
        entropy_enabled = False

    def report_pattern(lineno: int, col: int, label: str, secret: str, severity: str, confidence: str) -> None:
        emit(Finding("RS-SEC-001", severity, confidence, sf.rel, lineno, col,
                     "%s detected: %s" % (label, redact_secret(secret)), sf.snippet(lineno), remediation))

    def report_generic(lineno: int, col: int, label: str, value: str) -> None:
        """Heuristic (non-token) findings: skipped for well-known defaults in example files, low in other example
        files, labelled when a well-known default is used in a real file."""
        default = value.strip("'\"").lower() in KNOWN_DEFAULT_SECRETS
        if example_file:
            if default:
                return
            report_pattern(lineno, col, label + " (example file)", value, "low", "low")
            return
        report_pattern(lineno, col, label + (" (well-known default value)" if default else ""), value, "high", "medium")

    idx = 0
    while idx < total:
        line = sf.lines[idx]
        lineno = idx + 1
        idx += 1
        m = PEM_BEGIN_RE.search(line)
        if m:
            end_same = PEM_END_RE.search(line, m.end())
            if end_same:
                sf.add_redaction(lineno, m.start(), end_same.end())
                report_pattern(lineno, m.start() + 1, "PEM private key block (single line)",
                               line[m.start():end_same.end()], "critical", "high")
                continue
            end_idx = None
            for j in range(idx, min(total, idx + PEM_MAX_LINES)):
                if PEM_END_RE.search(sf.lines[j]):
                    end_idx = j
                    break
            if end_idx is None:
                sf.add_redaction(lineno, m.start(), m.end())
                emit(Finding("RS-SEC-001", "high", "low", sf.rel, lineno, m.start() + 1,
                             "PEM private key marker without a terminating END line (redacted)",
                             sf.snippet(lineno), remediation))
                continue
            for j in range(idx - 1, end_idx + 1):
                sf.redacted_lines.add(j + 1)
            n_lines = end_idx - idx + 2
            emit(Finding("RS-SEC-001", "critical", "high", sf.rel, lineno, m.start() + 1,
                         "PEM private key block detected (%d lines, redacted)" % n_lines,  # reposentry: ignore RS-SEC-001
                         "-----BEGIN PRIVATE KEY----- … %d line(s) redacted … -----END PRIVATE KEY-----" % n_lines,
                         remediation))
            idx = end_idx + 1
            continue
        if len(line) < 8:
            continue
        spans: List[Tuple[int, int]] = []
        if SECRET_TRIGGER_RE.search(line):
            hits: List[Tuple[str, "re.Match[str]", str]] = []
            for label, rx, severity in SECRET_PATTERNS:
                for m in rx.finditer(line):
                    sf.add_redaction(lineno, m.start(), m.end())
                    spans.append((m.start(), m.end()))
                    hits.append((label, m, severity))
            for label, m, severity in hits:
                report_pattern(lineno, m.start() + 1, label, m.group(0), severity, "high")
        for m in (ASSIGN_SECRET_RE.finditer(line) if ASSIGN_TRIGGER_RE.search(line) else ()):
            value = m.group(3)
            if looks_like_placeholder(value) or value.count(" ") >= 2:  # prose, not a credential
                continue
            if any(s <= m.start(3) < e for s, e in spans):
                continue
            sf.add_redaction(lineno, m.start(3), m.end(3))
            spans.append((m.start(3), m.end(3)))
            report_generic(lineno, m.start(3) + 1, "Hardcoded %s assignment" % m.group(1).lower(), value)
        if env_style:
            m = ENV_SECRET_RE.match(line)
            if m and not looks_like_placeholder(m.group(2)) and not any(s <= m.start(2) < e for s, e in spans):
                sf.add_redaction(lineno, m.start(2), m.end(2))
                spans.append((m.start(2), m.end(2)))
                report_generic(lineno, m.start(2) + 1, "Hardcoded %s value" % m.group(1), m.group(2))
        if yaml_style:
            m = YAML_SECRET_RE.match(line)
            if m and not looks_like_placeholder(m.group(2)) and not any(s <= m.start(2) < e for s, e in spans):
                sf.add_redaction(lineno, m.start(2), m.end(2))
                spans.append((m.start(2), m.end(2)))
                report_generic(lineno, m.start(2) + 1, "Hardcoded %s value" % m.group(1), m.group(2))
        if not entropy_enabled or len(line) < min_len or not entropy_trigger_re.search(line):
            continue
        low = line.lower()
        if any(w in low for w in HASH_CONTEXT_WORDS):
            continue
        candidates: List[Tuple[int, int, str]] = []
        for m in quoted_re.finditer(line):
            candidates.append((m.start(2), m.end(2), m.group(2)))
        for m in adjacent_re.finditer(line):
            candidates.append((m.start(1), m.end(1), m.group(1)))
        seen_spans: Set[Tuple[int, int]] = set()
        for start, end, token in candidates:
            if (start, end) in seen_spans or any(s <= start < e or s < end <= e for s, e in spans):
                continue
            seen_spans.add((start, end))
            verdict = _entropy_verdict(token, th)
            if verdict is None:
                continue
            entropy, charset, confidence = verdict
            sf.add_redaction(lineno, start, end)
            spans.append((start, end))
            emit(Finding("RS-SEC-002", "medium", confidence, sf.rel, lineno, start + 1,
                         "High-entropy %s string (entropy %.2f bits/char, length %d): %s"
                         % (charset, entropy, len(token), redact_secret(token)),
                         sf.snippet(lineno), RULES["RS-SEC-002"].remediation))


def _has_sequential_run(token: str, min_run: int = 6) -> bool:
    """True for alphabet/keyboard-style sequences (abcdefgh, 01234567, ZYXWVU)
    which are high-entropy but obviously not secrets."""
    run = 1
    for i in range(1, len(token)):
        if abs(ord(token[i]) - ord(token[i - 1])) == 1:
            run += 1
            if run >= min_run:
                return True
        else:
            run = 1
    return False


def _entropy_verdict(token: str, th: Dict[str, float]) -> Optional[Tuple[float, str, str]]:
    if UUID_RE.match(token) or token.isdigit() or len(set(token)) <= 4:
        return None
    if PATHLIKE_RE.match(token) or token.startswith(("./", "../", "/")):
        return None
    if looks_like_placeholder(token) or _has_sequential_run(token):
        return None
    if HEX_RE.match(token):
        charset, threshold = "hex", float(th.get("entropy_hex", 3.0))
    elif BASE64_RE.match(token) or BASE64URL_RE.match(token):
        charset, threshold = "base64", float(th.get("entropy_base64", 4.5))
    else:
        charset, threshold = "mixed", float(th.get("entropy_base64", 4.5))
    entropy = shannon_entropy(token)
    if entropy <= threshold:
        return None
    confidence = "medium" if entropy >= threshold + 0.25 else "low"
    return entropy, charset, confidence


# --------------------------------------------------------------------------
# Comment stripping for pattern-based languages (JS/TS, C/C++, shell)
# --------------------------------------------------------------------------
def strip_comments(text: str, lang: str) -> str:
    """Replace comment characters with spaces, preserving length and newlines
    so line and column numbers stay aligned with the original source."""
    out: List[str] = []
    n = len(text)
    i = 0
    state = "code"
    quote = ""
    if lang == "shell":
        while i < n:
            c = text[i]
            if state == "code":
                if c in ("'", '"'):
                    state, quote = "str", c
                    out.append(c)
                elif c == "#" and (i == 0 or text[i - 1] in " \t\n;(|&"):
                    state = "line"
                    out.append(" ")
                else:
                    out.append(c)
            elif state == "str":
                out.append(c)
                if c == "\\" and quote == '"' and i + 1 < n:
                    out.append(text[i + 1])
                    i += 1
                elif c == quote:
                    state = "code"
            else:  # line comment
                if c == "\n":
                    state = "code"
                    out.append(c)
                else:
                    out.append(" ")
            i += 1
        return "".join(out)
    quotes = "'\"`" if lang == "js" else "'\""
    while i < n:
        c = text[i]
        if state == "code":
            if c in quotes:
                state, quote = "str", c
                out.append(c)
            elif c == "/" and i + 1 < n and text[i + 1] == "/":
                state = "line"
                out.append("  ")
                i += 1
            elif c == "/" and i + 1 < n and text[i + 1] == "*":
                state = "block"
                out.append("  ")
                i += 1
            else:
                out.append(c)
        elif state == "str":
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1] if text[i + 1] == "\n" else " ")
                i += 1
            elif c == quote:
                state = "code"
            elif c == "\n" and quote != "`":
                state = "code"
        elif state == "line":
            if c == "\n":
                state = "code"
                out.append(c)
            else:
                out.append(" ")
        else:  # block comment
            if c == "*" and i + 1 < n and text[i + 1] == "/":
                state = "code"
                out.append("  ")
                i += 1
            elif c == "\n":
                out.append(c)
            else:
                out.append(" ")
        i += 1
    return "".join(out)


# --------------------------------------------------------------------------
# Pattern-based sink rules (JS/TS, C/C++, shell)
# --------------------------------------------------------------------------
def _extract_first_arg(line: str, pos: int) -> str:
    """Return the text of the first argument of a call whose '(' is at `pos`."""
    depth = 0
    i = pos
    quote = ""
    start = pos + 1
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "\"'`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return line[start:i].strip()
        elif c == "," and depth == 1:
            return line[start:i].strip()
        i += 1
    return line[start:].strip()


def _is_literal_arg(arg: str) -> bool:
    if len(arg) < 2:
        return False
    q = arg[0]
    if q not in "\"'`" or arg[-1] != q:
        return False
    inner = arg[1:-1]
    if q == "`" and "${" in inner:
        return False
    # an unescaped closing quote inside means concatenation like "a" + x + "b"
    i = 0
    while i < len(inner):
        if inner[i] == "\\":
            i += 2
            continue
        if inner[i] == q:
            return False
        i += 1
    return True


JS_EXEC_RE = re.compile(r"(?<![\w$.])(?:(?:child_process|cp|childProcess|proc|sh|shell|shelljs|execa)\s*\.\s*)?(exec|execSync)\s*\(")
JS_EXEC_MEMBER_RE = re.compile(r"\.\s*(exec|execSync)\s*\(")
JS_SPAWN_RE = re.compile(r"(?<![\w$.])(spawn|spawnSync|execFile|execFileSync)\s*\(")
JS_EVAL_RE = re.compile(r"(?<![\w$.])eval\s*\(")
JS_FUNCTION_RE = re.compile(r"\bnew\s+Function\s*\(")
JS_TIMER_RE = re.compile(r"(?<![\w$.])(setTimeout|setInterval)\s*\(\s*([\"'`])")
JS_INNERHTML_RE = re.compile(r"\.\s*(innerHTML|outerHTML)\s*(?:\+?=)(?!=)\s*")
JS_DOCWRITE_RE = re.compile(r"\bdocument\s*\.\s*(write|writeln)\s*\(")
JS_INSERTHTML_RE = re.compile(r"\.\s*insertAdjacentHTML\s*\(")
C_SHELL_RE = re.compile(r"(?<![\w.>])(system|popen|_popen|wpopen)\s*\(")
C_UNSAFE_RE = re.compile(r"(?<![\w.>])(gets|strcpy|strcat|sprintf|vsprintf|wcscpy|wcscat)\s*\(")
SH_EVAL_RE = re.compile(r"(?:^|[\s;|&(`{])eval\s+(.*)$")
SH_PIPE_RE = re.compile(r"\b(curl|wget)\b[^|\n]*\|\s*(?:sudo\s+(?:-\w+\s+)*)?(?:ba|z|k|da|a)?sh\b")
SH_RCE_RE = re.compile(r"\b(?:ba|z|k|da)?sh\s+-c\s+\"[^\"]*\$")


def _sev_for_arg(constant: bool) -> str:
    return "medium" if constant else "critical"


def scan_pattern_sinks(sf: SourceFile, emit, masked: Optional[str] = None) -> None:
    """RS-SEC-003 / RS-SEC-004 for non-Python languages. Pattern-based,
    confidence is low or medium by design. JS/TS runs on lexically masked
    text (comments, strings, template text and regex bodies blanked)."""
    if sf.lang == "js":
        stripped = (masked if masked is not None else js_mask(sf.text, jsx=js_allows_jsx(sf.rel))).splitlines()
    else:
        stripped = strip_comments(sf.text, sf.lang).splitlines()
    rem3 = RULES["RS-SEC-003"].remediation
    rem4 = RULES["RS-SEC-004"].remediation
    file_text = sf.text
    if sf.lang == "js":
        uses_child_process = bool(_JS_SHELL_IMPORT_RE.search(file_text))
        for lineno, line in enumerate(stripped, 1):
            if not line.strip():
                continue
            if uses_child_process:
                for m in JS_EXEC_RE.finditer(line):
                    arg = _extract_first_arg(line, m.end() - 1)
                    const = _is_literal_arg(arg)
                    emit(Finding("RS-SEC-003", _sev_for_arg(const), "medium", sf.rel, lineno, m.start(1) + 1,
                                 "Shell command execution via child_process.%s() with %s argument"
                                 % (m.group(1), "constant" if const else "non-constant"), sf.snippet(lineno), rem3))
                for m in JS_SPAWN_RE.finditer(line):
                    if re.search(r"shell\s*:\s*true", line):
                        arg = _extract_first_arg(line, m.end() - 1)
                        const = _is_literal_arg(arg)
                        emit(Finding("RS-SEC-003", _sev_for_arg(const), "medium", sf.rel, lineno, m.start(1) + 1,
                                     "child_process.%s() with shell: true and %s command"
                                     % (m.group(1), "constant" if const else "non-constant"), sf.snippet(lineno), rem3))
            for m in JS_EVAL_RE.finditer(line):
                arg = _extract_first_arg(line, m.end() - 1)
                const = _is_literal_arg(arg)
                emit(Finding("RS-SEC-004", _sev_for_arg(const), "medium", sf.rel, lineno, m.start() + 1,
                             "eval() on a %s expression" % ("constant" if const else "non-constant"),
                             sf.snippet(lineno), rem4))
            for m in JS_FUNCTION_RE.finditer(line):
                arg = _extract_first_arg(line, m.end() - 1)
                const = _is_literal_arg(arg) if arg else True
                emit(Finding("RS-SEC-004", _sev_for_arg(const), "medium", sf.rel, lineno, m.start() + 1,
                             "new Function() builds code from a %s string" % ("constant" if const else "non-constant"),
                             sf.snippet(lineno), rem4))
            for m in JS_TIMER_RE.finditer(line):
                arg = _extract_first_arg(line, line.index("(", m.start()))
                const = _is_literal_arg(arg)
                emit(Finding("RS-SEC-004", _sev_for_arg(const), "low", sf.rel, lineno, m.start(1) + 1,
                             "%s() with a string argument is an implicit eval (%s)"
                             % (m.group(1), "constant" if const else "non-constant"), sf.snippet(lineno), rem4))
            for m in JS_INNERHTML_RE.finditer(line):
                rhs = line[m.end():].strip().rstrip(";")
                const = _is_literal_arg(rhs)
                emit(Finding("RS-SEC-004", "medium" if const else "high", "low", sf.rel, lineno, m.start(1) + 1,
                             "Assignment to %s with %s HTML (XSS sink)" % (m.group(1), "constant" if const else "non-constant"),
                             sf.snippet(lineno), rem4))
            for m in JS_DOCWRITE_RE.finditer(line):
                arg = _extract_first_arg(line, m.end() - 1)
                const = _is_literal_arg(arg)
                emit(Finding("RS-SEC-004", "medium" if const else "high", "low", sf.rel, lineno, m.start() + 1,
                             "document.%s() with %s HTML (XSS sink)" % (m.group(1), "constant" if const else "non-constant"),
                             sf.snippet(lineno), rem4))
            for m in JS_INSERTHTML_RE.finditer(line):
                emit(Finding("RS-SEC-004", "high", "low", sf.rel, lineno, m.start() + 1,
                             "insertAdjacentHTML() injects raw HTML (XSS sink)", sf.snippet(lineno), rem4))
    elif sf.lang == "c":
        for lineno, line in enumerate(stripped, 1):
            if not line.strip() or line.lstrip().startswith("#include"):
                continue
            for m in C_SHELL_RE.finditer(line):
                arg = _extract_first_arg(line, m.end() - 1)
                const = _is_literal_arg(arg)
                emit(Finding("RS-SEC-003", _sev_for_arg(const), "medium", sf.rel, lineno, m.start(1) + 1,
                             "%s() runs a shell with a %s command" % (m.group(1), "constant" if const else "non-constant"),
                             sf.snippet(lineno), rem3))
            for m in C_UNSAFE_RE.finditer(line):
                fn = m.group(1)
                emit(Finding("RS-SEC-004", "high", "medium", sf.rel, lineno, m.start(1) + 1,
                             "%s() has no bounds checking (buffer overflow sink)" % fn, sf.snippet(lineno),
                             "Use fgets/strncpy/strncat/snprintf (or safer string APIs) with explicit sizes."))
    elif sf.lang == "shell":
        for lineno, line in enumerate(stripped, 1):
            if not line.strip():
                continue
            m = SH_EVAL_RE.search(line)
            if m:
                rest = m.group(1)
                const = not ("$" in rest or "`" in rest)
                emit(Finding("RS-SEC-003", _sev_for_arg(const), "medium", sf.rel, lineno, m.start(1) - 4,
                             "shell eval of a %s string" % ("constant" if const else "non-constant"),
                             sf.snippet(lineno), rem3))
            for m in SH_PIPE_RE.finditer(line):
                emit(Finding("RS-SEC-003", "critical", "medium", sf.rel, lineno, m.start() + 1,
                             "Remote content piped into a shell (%s | sh)" % m.group(1), sf.snippet(lineno),
                             "Download to a file, verify its checksum or signature, then execute it."))
            for m in SH_RCE_RE.finditer(line):
                emit(Finding("RS-SEC-003", "critical", "low", sf.rel, lineno, m.start() + 1,
                             "sh -c with variable interpolation", sf.snippet(lineno), rem3))


# --------------------------------------------------------------------------
# JavaScript / TypeScript: lexical masking (foundation for all JS/TS rules)
# --------------------------------------------------------------------------
# Identifiers after which a `/` starts a regex literal rather than a division.
_JS_REGEX_KEYWORDS = frozenset((
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case",
    "do", "else", "yield", "await", "extends", "export", "default",
))
_JS_EXPR_CHUNK_RE = re.compile(r"[^'\"`/{}<]+")
_JS_JSX_TEXT_CHUNK_RE = re.compile(r"[^<{\r\n]+")
_JS_JSX_TAG_CHUNK_RE = re.compile(r"[^'\"{}<>/]+")
_JS_TPL_CHUNK_RE = re.compile(r"[^`$\\\r\n]+")
_JS_JSX_TAG_RE = re.compile(r"<(>|[A-Za-z_$][\w$.:\-]*)")
_JS_NOT_NEWLINE_RE = re.compile(r"[^\r\n]")


def _js_prev_is_value(text: str, last: int) -> bool:
    """True when the last significant code character ends a value (so a
    following `/` is a division), False when an operand is expected (regex)."""
    if last < 0:
        return False
    ch = text[last]
    if ch in ")]}":
        return True
    if ch.isalnum() or ch in "_$":
        k = last
        while k > 0 and (text[k - 1].isalnum() or text[k - 1] in "_$"):
            k -= 1
        word = text[k:last + 1]
        if word[0].isdigit():
            return True
        return word not in _JS_REGEX_KEYWORDS
    return False


def _js_looks_like_jsx(text: str, i: int) -> bool:
    """Cheap JSX heuristic at a `<` in expression position: `<>`, or `<Tag`
    followed by `>`, `/`, `{`, an attribute name or a line break. `<T,>`,
    `a < b` and `Array<string>` are rejected."""
    m = _JS_JSX_TAG_RE.match(text, i)
    if not m:
        return False
    if m.group(1) == ">":
        return True
    k = m.end()
    n = len(text)
    while k < n and text[k] in " \t\r\n":
        k += 1
    if k >= n:
        return True
    nxt = text[k]
    return nxt in ">/{" or nxt.isalpha() or nxt in "_$"


def js_allows_jsx(rel: str) -> bool:
    """JSX is possible in .js/.jsx/.mjs/.cjs/.tsx; plain .ts/.mts/.cts use
    `<Type>value` assertions instead, so JSX detection is off there."""
    return os.path.splitext(rel)[1].lower() not in (".ts", ".mts", ".cts")


def js_mask(text: str, jsx: bool = True) -> str:
    """Return `text` with the contents of comments, string literals, template
    literal text, regex literals and JSX text replaced by spaces. Length and
    every line break are preserved exactly; delimiters (quotes, backticks,
    regex slashes, `${` `}`) are kept. Code inside `${ ... }` stays visible
    and is masked recursively. Never raises; an unterminated template,
    comment or JSX element is masked to the end of the file, an unterminated
    string or regex to the end of its line. Linear time."""
    n = len(text)
    out = list(text)

    def blank(a: int, b: int) -> None:
        if b > a:
            out[a:b] = list(_JS_NOT_NEWLINE_RE.sub(" ", text[a:b]))

    # context stack entries: ["expr", brace_depth] | ["tpl"] | ["jsx", element_depth, mode]
    stack: List[List[object]] = [["expr", 0]]
    i = 0
    last = -1  # index of the last significant (unmasked, non-space) code character
    while i < n:
        ctx = stack[-1]
        kind = ctx[0]
        c = text[i]
        if kind == "tpl":
            if c == "`":
                stack.pop()
                last = i
                i += 1
            elif c == "\\":
                blank(i, min(n, i + 2))
                i += 2
            elif c == "$" and i + 1 < n and text[i + 1] == "{":
                stack.append(["expr", 0])
                i += 2
            elif c in "\r\n":
                i += 1
            else:
                m = _JS_TPL_CHUNK_RE.match(text, i)
                j = m.end() if m else i + 1
                blank(i, j)
                i = j
            continue
        if kind == "jsx":
            mode = ctx[2]
            if mode == "text":
                if c == "{":
                    stack.append(["expr", 0])
                    i += 1
                elif c == "<":
                    if text.startswith("</", i):
                        ctx[2] = "close"
                        i += 2
                    else:
                        ctx[2] = "tag"
                        i += 1
                elif c in "\r\n":
                    i += 1
                else:
                    m = _JS_JSX_TEXT_CHUNK_RE.match(text, i)
                    j = m.end() if m else i + 1
                    blank(i, j)
                    i = j
                continue
            if mode == "close":
                j = text.find(">", i)
                if j == -1:
                    j = n - 1
                i = j + 1
                ctx[1] = int(ctx[1]) - 1  # type: ignore[call-overload]
                if int(ctx[1]) <= 0:  # type: ignore[call-overload]
                    stack.pop()
                    last = j
                else:
                    ctx[2] = "text"
                continue
            # mode == "tag": inside `<Tag ... >`
            if c in "'\"":
                j = i + 1
                while j < n and text[j] != c:
                    j += 1
                blank(i + 1, j)
                i = j + 1
            elif c == "{":
                stack.append(["expr", 0])
                i += 1
            elif c == "/" and i + 1 < n and text[i + 1] == ">":
                i += 2
                if int(ctx[1]) <= 0:  # type: ignore[call-overload]
                    stack.pop()
                    last = i - 1
                else:
                    ctx[2] = "text"
            elif c == ">":
                i += 1
                ctx[1] = int(ctx[1]) + 1  # type: ignore[call-overload]
                ctx[2] = "text"
            elif c in "<}/":
                i += 1
            else:
                m = _JS_JSX_TAG_CHUNK_RE.match(text, i)
                i = m.end() if m else i + 1
            continue
        # kind == "expr"
        if c == "'" or c == '"':
            j = i + 1
            while j < n:
                ch = text[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == c or ch == "\n" or ch == "\r":
                    break
                j += 1
            if j >= n:
                blank(i + 1, n)
                i = n
            elif text[j] == c:
                blank(i + 1, j)
                last = j
                i = j + 1
            else:  # unterminated string: masked to the end of its line
                blank(i + 1, j)
                last = j - 1
                i = j
        elif c == "`":
            stack.append(["tpl"])
            i += 1
        elif c == "/":
            nxt = text[i + 1] if i + 1 < n else ""
            if nxt == "/":
                j = text.find("\n", i)
                if j == -1:
                    j = n
                blank(i, j)
                i = j
            elif nxt == "*":
                j = text.find("*/", i + 2)
                j = n if j == -1 else j + 2
                blank(i, j)
                i = j
            elif _js_prev_is_value(text, last):
                last = i
                i += 1
            else:  # regex literal
                j = i + 1
                in_class = False
                while j < n:
                    ch = text[j]
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == "\n" or ch == "\r":
                        break
                    if in_class:
                        if ch == "]":
                            in_class = False
                    elif ch == "[":
                        in_class = True
                    elif ch == "/":
                        break
                    j += 1
                if j < n and text[j] == "/":
                    blank(i + 1, j)
                    k = j + 1
                    while k < n and (text[k].isalpha() or text[k] in "_$"):
                        k += 1
                    last = k - 1
                    i = k
                else:
                    j = min(j, n)
                    blank(i + 1, j)
                    last = j - 1
                    i = j
        elif c == "{":
            ctx[1] = int(ctx[1]) + 1  # type: ignore[call-overload]
            last = i
            i += 1
        elif c == "}":
            if int(ctx[1]) > 0:  # type: ignore[call-overload]
                ctx[1] = int(ctx[1]) - 1  # type: ignore[call-overload]
                last = i
            elif len(stack) > 1:
                stack.pop()
            else:
                last = i
            i += 1
        elif c == "<":
            if jsx and not _js_prev_is_value(text, last) and _js_looks_like_jsx(text, i):
                stack.append(["jsx", 0, "tag"])
                i += 1
            else:
                last = i
                i += 1
        else:
            m = _JS_EXPR_CHUNK_RE.match(text, i)
            j = m.end() if m else i + 1
            stripped = text[i:j].rstrip()
            if stripped:
                last = i + len(stripped) - 1
            i = j
    return "".join(out)


# --------------------------------------------------------------------------
# JavaScript / TypeScript: approximate function discovery and metrics
# --------------------------------------------------------------------------
_JS_CONTROL_WORDS = frozenset((
    "if", "for", "while", "switch", "catch", "with", "function", "return", "else", "do", "try",
    "finally", "new", "typeof", "await", "yield", "delete", "void", "throw", "in", "of", "instanceof",
    "case", "default", "import", "export", "class", "extends", "super", "async", "this", "let", "const",
    "var", "type", "interface", "enum", "declare", "namespace", "module", "satisfies", "as", "is",
))
_JS_FUNC_KW_RE = re.compile(r"(?<![\w$.@])(?:async\s+)?function\b\s*\*?\s*(?:([A-Za-z_$][\w$]*)\s*)?(?:<[^<>()]*>\s*)?\(")
_JS_ARROW_RE = re.compile(r"=>\s*\{")
_JS_METHOD_RE = re.compile(
    r"(?<![\w$.@#])(?:(?:public|private|protected|static|async|readonly|override|abstract|declare|get|set)\s+)*"
    r"\*?\s*(#?[A-Za-z_$][\w$]*)\s*\??\s*(?:<[^<>()]*>\s*)?\(")
_JS_EXPORT_DEFAULT_TAIL_RE = re.compile(r"export\s+default\s*$")
_JS_ARROW_NAME_RES = (
    re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]*)?=\s*$"),
    re.compile(r"([A-Za-z_$][\w$.]*)\s*(?::[^=:]*)?=\s*$"),
    re.compile(r"([A-Za-z_$][\w$]*)\s*:\s*$"),
)
_JS_CC_IF_RE = re.compile(r"(?<![\w$.])if\s*\(")
_JS_CC_FOR_RE = re.compile(r"(?<![\w$.])for\s*(?:await\s*)?\(")
_JS_CC_WHILE_RE = re.compile(r"(?<![\w$.])while\s*\(")
_JS_CC_CASE_RE = re.compile(r"(?<![\w$.])case\b")
_JS_CC_CATCH_RE = re.compile(r"(?<![\w$.])catch\b")
_JS_CC_LOGIC_RE = re.compile(r"&&|\|\||\?\?")
_JS_CC_TERNARY_RE = re.compile(r"(?<![?])\?(?![.?:,)\]>])")
_JS_BLOCK_KW_RE = re.compile(r"(?<![\w$.])(if|for|while|do|switch|try)\b")
_JS_EMPTY_CATCH_RE = re.compile(r"(?<![\w$.])catch\s*(?:\([^()]*\))?\s*\{\s*\}")
_JS_TEST_FILE_RE = re.compile(r"(?:^|/)(?:__tests__|__mocks__)/|\.(?:test|spec)\.[cm]?[jt]sx?$", re.IGNORECASE)
# RS-SEC-006 patterns (run on masked text unless noted)
_JS_SEC_TLS_RE = re.compile(r"(?<![\w$])rejectUnauthorized\s*:\s*false(?![\w$])")
_JS_SEC_TLS_ENV_RE = re.compile(  # original text; the value is a string literal
    r"process\s*\.\s*env\s*(?:\.\s*NODE_TLS_REJECT_UNAUTHORIZED|\[\s*['\"]NODE_TLS_REJECT_UNAUTHORIZED['\"]\s*\])"
    r"\s*=\s*(['\"])0\1")
_JS_SEC_HASH_RE = re.compile(r"(?<![\w$])createHash\s*\(\s*(['\"])")
_JS_SEC_RANDOM_RE = re.compile(r"(?<![\w$.])Math\s*\.\s*random\s*\(")
_JS_SEC_SECRET_IDENT_RE = re.compile(r"(?<![\w$])[\w$]*(?:token|secret|password|nonce|session|csrf|otp)[\w$]*", re.IGNORECASE)
_JS_SEC_JWT_ALG_RE = re.compile(r"(?<![\w$])algorithms\s*:\s*\[")
_JS_SEC_JWT_NONE_RE = re.compile(r"['\"]none['\"]", re.IGNORECASE)
_JS_SEC_CORS_ORIGIN_RE = re.compile(r"(?<![\w$])origin\s*:\s*(['\"])")
_JS_SEC_CORS_CRED_RE = re.compile(r"(?<![\w$])credentials\s*:\s*true(?![\w$])")
_JS_SEC_DSIH_RE = re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*")
_JS_SEC_FS_IMPORT_RE = re.compile(r"['\"](?:node:)?fs(?:/promises)?['\"]|\bfs\s*\.\s*promises\b")
_JS_SEC_FS_CALL_RE = re.compile(
    r"(?<![\w$])(readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|"
    r"appendFileSync|unlink|unlinkSync|readdir|readdirSync|rm|rmSync|rmdir|rmdirSync)\s*\(")
_JS_SEC_REQ_DATA_RE = re.compile(r"(?<![\w$])(?:req|request)\s*\.|(?<![\w$.])(?:params|query|body|argv)(?![\w$])")
_JS_SEC_REGEXP_RE = re.compile(r"(?<![\w$.])new\s+RegExp\s*\(")
_JS_SHELL_IMPORT_RE = re.compile(r"['\"](?:node:)?child_process['\"]|['\"](?:execa|shelljs)['\"]")


def _downgrade(severity: str) -> str:
    return SEVERITIES[max(0, SEVERITY_RANK[severity] - 1)]


def js_is_test_file(rel: str) -> bool:
    return bool(_JS_TEST_FILE_RE.search(rel))


def js_is_declaration_file(rel: str) -> bool:
    return rel.lower().endswith((".d.ts", ".d.mts", ".d.cts"))


def js_line_starts(text: str) -> List[int]:
    starts = [0]
    pos = text.find("\n")
    while pos != -1:
        starts.append(pos + 1)
        pos = text.find("\n", pos + 1)
    return starts


def js_line_col(starts: Sequence[int], offset: int) -> Tuple[int, int]:
    line = bisect.bisect_right(starts, offset)
    return line, offset - starts[line - 1] + 1


def _js_match_forward(text: str, i: int, open_ch: str, close_ch: str) -> int:
    """Index of the bracket matching text[i] (which must be open_ch), or
    len(text) when unterminated. Linear, on masked text."""
    depth = 0
    n = len(text)
    k = i
    while k < n:
        ch = text[k]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return k
        k += 1
    return n


def _js_match_backward(text: str, k: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    while k >= 0:
        ch = text[k]
        if ch == close_ch:
            depth += 1
        elif ch == open_ch:
            depth -= 1
            if depth == 0:
                return k
        k -= 1
    return 0


def _js_body_after_params(text: str, close_paren: int) -> int:
    """Index of the `{` opening a function body after its `)` (skipping a TS
    return type annotation), or -1 when there is no body (signature only)."""
    n = len(text)
    k = close_paren + 1
    while k < n and text[k] in " \t\r\n":
        k += 1
    if k >= n:
        return -1
    if text[k] == "{":
        return k
    if text[k] != ":":
        return -1
    k += 1
    depth = 0
    prev = ":"
    arrow = False  # the previous significant token was `=>`
    while k < n:
        ch = text[k]
        if ch in " \t\r\n":
            k += 1
            continue
        if ch in "([<":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == ">":
            if prev == "=":
                arrow = True
                prev = ch
                k += 1
                continue
            depth -= 1
        elif ch == "{":
            if depth <= 0:
                if arrow or prev in ":|&,(<=":
                    k = _js_match_forward(text, k, "{", "}") + 1
                    prev = "}"
                    arrow = False
                    continue
                return k
        elif ch == ";" and depth <= 0:
            return -1
        prev = ch
        arrow = False
        k += 1
    return -1


def _js_arrow_name(text: str, params_start: int) -> str:
    pre = text[max(0, params_start - 240):params_start].rstrip()
    if pre.endswith("async"):
        pre = pre[:-5].rstrip()
    if _JS_EXPORT_DEFAULT_TAIL_RE.search(pre):
        return "default"
    for rx in _JS_ARROW_NAME_RES:
        m = rx.search(pre)
        if m:
            return m.group(1).split(".")[-1]
    return "<anonymous>"


@dataclasses.dataclass
class JsFunction:
    name: str
    start: int        # offset of the header (keyword, name or parameter list)
    body_start: int   # offset of the `{`
    body_end: int     # offset of the matching `}` (len(text) if unterminated)
    children: List["JsFunction"] = dataclasses.field(default_factory=list)


def js_discover_functions(masked: str) -> List[JsFunction]:
    """Approximate function discovery on masked text: `function` declarations
    and expressions, arrow functions with block bodies, class/object methods,
    getters/setters, constructors. Returns functions sorted by body start
    with parent/child nesting resolved."""
    found: Dict[int, JsFunction] = {}

    def add(name: str, start: int, body: int) -> None:
        if body in found:
            return
        found[body] = JsFunction(name, start, body, _js_match_forward(masked, body, "{", "}"))

    for m in _JS_FUNC_KW_RE.finditer(masked):
        close = _js_match_forward(masked, m.end() - 1, "(", ")")
        body = _js_body_after_params(masked, close)
        if body < 0:
            continue
        name = m.group(1)
        if not name:  # function expression: take the name from `key:`, `x =`, `const x =` or `export default`
            name = _js_arrow_name(masked, m.start())
        add(name, m.start(), body)
    for m in _JS_METHOD_RE.finditer(masked):
        name = m.group(1)
        if name.lstrip("#") in _JS_CONTROL_WORDS:
            continue
        close = _js_match_forward(masked, m.end() - 1, "(", ")")
        body = _js_body_after_params(masked, close)
        if body < 0 or body in found:
            continue
        add(name, m.start(), body)
    for m in _JS_ARROW_RE.finditer(masked):
        body = m.end() - 1
        if body in found:
            continue
        k = m.start() - 1
        while k >= 0 and masked[k] in " \t\r\n":
            k -= 1
        if k < 0:
            continue
        if masked[k] == ")":
            ps = _js_match_backward(masked, k, "(", ")")
        elif masked[k].isalnum() or masked[k] in "_$":
            ps = k
            while ps > 0 and (masked[ps - 1].isalnum() or masked[ps - 1] in "_$"):
                ps -= 1
        else:
            continue
        add(_js_arrow_name(masked, ps), ps, body)
    funcs = sorted(found.values(), key=lambda f: f.body_start)
    stack: List[JsFunction] = []
    for f in funcs:
        while stack and stack[-1].body_end < f.body_start:
            stack.pop()
        if stack:
            stack[-1].children.append(f)
        stack.append(f)
    return funcs


def js_own_text(masked: str, start: int, end: int, children: Sequence[JsFunction]) -> str:
    """masked[start:end] with the spans of nested functions blanked out."""
    pieces: List[str] = []
    pos = start
    for child in children:
        a = max(child.start, pos)
        b = min(child.body_end + 1, end)
        if a < pos or a >= end:
            continue
        pieces.append(masked[pos:a])
        pieces.append(_JS_NOT_NEWLINE_RE.sub(" ", masked[a:b]))
        pos = b
    pieces.append(masked[pos:end])
    return "".join(pieces)


def js_complexity(own: str) -> int:
    """Approximate McCabe complexity of a function's own (masked) text:
    1 + if + for + while + case + catch + each && || ?? + each ternary."""
    score = 1
    for rx in (_JS_CC_IF_RE, _JS_CC_FOR_RE, _JS_CC_WHILE_RE, _JS_CC_CASE_RE, _JS_CC_CATCH_RE, _JS_CC_LOGIC_RE,
               _JS_CC_TERNARY_RE):
        score += len(rx.findall(own))
    return score


def js_max_nesting(own: str) -> Tuple[int, int]:
    """(max depth, offset of the deepest block keyword) for if/for/while/do/
    switch/try blocks; else/catch/finally do not add depth."""
    n = len(own)
    spans: List[Tuple[int, int, int]] = []
    for m in _JS_BLOCK_KW_RE.finditer(own):
        k = m.end()
        while k < n and own[k] in " \t\r\n":
            k += 1
        if k >= n:
            continue
        if m.group(1) in ("do", "try"):
            if own[k] != "{":
                continue
        else:
            if own[k] != "(":
                continue
            k = _js_match_forward(own, k, "(", ")") + 1
            while k < n and own[k] in " \t\r\n":
                k += 1
            if k >= n or own[k] != "{":
                continue
        spans.append((k, _js_match_forward(own, k, "{", "}"), m.start()))
    spans.sort()
    stack: List[int] = []
    best_depth, best_pos = 0, -1
    for b, e, pos in spans:
        while stack and stack[-1] <= b:
            stack.pop()
        depth = len(stack) + 1
        if depth > best_depth:
            best_depth, best_pos = depth, pos
        stack.append(e)
    return best_depth, best_pos


class JsAnalyzer:
    """Approximate structural analysis of one JS/TS file on its masked text."""

    def __init__(self, sf: SourceFile, config: Config, emit, enabled: Set[str]) -> None:
        self.sf = sf
        self.config = config
        self.emit = emit
        self.enabled = enabled
        self.masked = js_mask(sf.text, jsx=js_allows_jsx(sf.rel))
        self.starts = js_line_starts(sf.text)
        self.funcs = js_discover_functions(self.masked)
        self.test_file = js_is_test_file(sf.rel)

    def _finding(self, rule_id: str, severity: str, confidence: str, offset: int, message: str,
                 remediation: Optional[str] = None) -> None:
        line, col = js_line_col(self.starts, offset)
        self.emit(Finding(rule_id, severity, confidence, self.sf.rel, line, col, message,
                          self.sf.snippet(line), remediation or RULES[rule_id].remediation))

    def run_quality(self) -> None:
        th = self.config.thresholds
        max_cc = th.get("max_cyclomatic_complexity", 10)
        max_depth = th.get("max_nesting_depth", 4)
        want_cc = "RS-QUAL-001" in self.enabled
        want_depth = "RS-QUAL-002" in self.enabled
        if (want_cc or want_depth) and not self.test_file:
            for f in self.funcs:
                own = js_own_text(self.masked, f.body_start + 1, f.body_end, f.children)
                if want_cc:
                    cc = js_complexity(own)
                    if cc > max_cc:
                        severity = "high" if cc > 2 * max_cc else "medium"
                        self._finding("RS-QUAL-001", severity, "medium", f.start,
                                      "Function '%s' has cyclomatic complexity %d (threshold %d; approximate JS/TS estimate)"
                                      % (f.name, cc, max_cc))
                if want_depth:
                    depth, pos = js_max_nesting(own)
                    if depth > max_depth and pos >= 0:
                        self._finding("RS-QUAL-002", RULES["RS-QUAL-002"].severity, "medium", f.body_start + 1 + pos,
                                      "Nesting depth %d exceeds %d in function '%s' (approximate JS/TS estimate)"
                                      % (depth, max_depth, f.name))
            if want_depth:
                top = [f for f in self.funcs if not any(f is c for p in self.funcs for c in p.children)]
                own = js_own_text(self.masked, 0, len(self.masked), top)
                depth, pos = js_max_nesting(own)
                if depth > max_depth and pos >= 0:
                    self._finding("RS-QUAL-002", RULES["RS-QUAL-002"].severity, "medium", pos,
                                  "Nesting depth %d exceeds %d in module scope (approximate JS/TS estimate)" % (depth, max_depth))
        if "RS-QUAL-004" in self.enabled:
            for m in _JS_EMPTY_CATCH_RE.finditer(self.masked):
                self._finding("RS-QUAL-004", RULES["RS-QUAL-004"].severity, "medium", m.start(),
                              "Empty catch block silently swallows errors (approximate JS/TS check)")

    def collect_imports(self) -> List["JsImport"]:
        """Import specifiers found on the masked text (so comments and strings
        cannot contribute), read back from the original text. `import type`,
        `export type`, dynamic `import()` and imports inside a function body
        are soft."""
        masked, text = self.masked, self.sf.text
        found: Dict[int, JsImport] = {}

        def inside_function(pos: int) -> bool:
            return any(f.body_start < pos < f.body_end for f in self.funcs)

        def add(qpos: int, soft: bool) -> None:
            if qpos in found or qpos >= len(text):
                return
            quote = text[qpos]
            end = text.find(quote, qpos + 1)
            if end == -1:
                return
            spec = text[qpos + 1:end]
            if not spec or "\n" in spec:
                return
            line, col = js_line_col(self.starts, qpos)
            found[qpos] = JsImport(spec, line, col, soft or inside_function(qpos), self.sf.snippet(line))

        for m in _JS_IMPORT_FROM_RE.finditer(masked):
            add(m.start(3), bool(_JS_TYPE_ONLY_RE.match(m.group(2))))
        for m in _JS_IMPORT_SIDE_RE.finditer(masked):
            add(m.start(1), False)
        for m in _JS_IMPORT_DYN_RE.finditer(masked):
            add(m.start(1), True)
        for m in _JS_REQUIRE_RE.finditer(masked):
            add(m.start(1), False)
        return [found[k] for k in sorted(found)]

    # -- RS-SEC-006: insecure configuration -------------------------------
    def _sec(self, severity: str, confidence: str, offset: int, message: str) -> None:
        if self.test_file:
            severity = _downgrade(severity)
        self._finding("RS-SEC-006", severity, confidence, offset, message + " (JS/TS, approximate)")

    def _enclosing_object(self, offset: int) -> Tuple[int, int]:
        """Span of the innermost `{ ... }` object literal around `offset` on
        masked text, or (0, len) when none is found."""
        masked = self.masked
        depth = 0
        k = offset
        while k >= 0:
            ch = masked[k]
            if ch == "}":
                depth += 1
            elif ch == "{":
                if depth == 0:
                    return k, _js_match_forward(masked, k, "{", "}")
                depth -= 1
            k -= 1
        return 0, len(masked)

    def _call_arg(self, paren: int, limit: int = 400) -> str:
        return _extract_first_arg(self.masked[paren:paren + limit], 0)

    def run_security(self) -> None:
        masked, text = self.masked, self.sf.text
        for m in _JS_SEC_TLS_RE.finditer(masked):
            self._sec("high", "medium", m.start(), "TLS certificate verification disabled with rejectUnauthorized: false")
        for m in _JS_SEC_TLS_ENV_RE.finditer(text):
            if masked[m.start()] == "p":  # not inside a comment or string
                self._sec("high", "medium", m.start(), "TLS certificate verification disabled via NODE_TLS_REJECT_UNAUTHORIZED='0'")
        for m in _JS_SEC_HASH_RE.finditer(masked):
            q = m.start(1)
            end = text.find(text[q], q + 1)
            algo = text[q + 1:end].strip().lower() if end != -1 else ""
            if algo in ("md5", "sha1", "sha-1"):
                self._sec("medium", "medium", m.start(),
                          "Weak hash createHash('%s'); unsuitable for passwords or signatures (fine for non-security checksums)" % algo)
        if _JS_SEC_RANDOM_RE.search(masked):
            lines = masked.splitlines()
            for m in _JS_SEC_RANDOM_RE.finditer(masked):
                line, _ = js_line_col(self.starts, m.start())
                window = "\n".join(lines[max(0, line - 4):line + 3])
                ident = _JS_SEC_SECRET_IDENT_RE.search(window)
                if ident:
                    self._sec("medium", "medium", m.start(),
                              "Math.random() used near '%s'; not cryptographically secure" % ident.group(0))
        for m in _JS_SEC_JWT_ALG_RE.finditer(masked):
            close = text.find("]", m.end())
            if close != -1 and _JS_SEC_JWT_NONE_RE.search(text[m.end():close]):
                self._sec("high", "medium", m.start(), "JWT verification accepts the 'none' algorithm")
        for m in _JS_SEC_CORS_ORIGIN_RE.finditer(masked):
            q = m.start(1)
            if text[q + 1:q + 3] != "*" + text[q]:
                continue
            start, end = self._enclosing_object(m.start())
            if _JS_SEC_CORS_CRED_RE.search(masked, start, end):
                self._sec("medium", "medium", m.start(), "CORS wildcard origin '*' combined with credentials: true")
        for m in _JS_SEC_DSIH_RE.finditer(masked):
            k = m.end()
            depth = 0
            n = len(masked)
            while k < n and k - m.end() < 400:
                ch = masked[k]
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    if depth == 0:
                        break
                    depth -= 1
                elif ch == "," and depth == 0:
                    break
                k += 1
            value = masked[m.end():k].strip()
            if _is_literal_arg(value):
                self._sec("low", "medium", m.start(), "dangerouslySetInnerHTML with a constant string")
            else:
                self._sec("high", "medium", m.start(), "dangerouslySetInnerHTML with non-constant __html (XSS sink)")
        if _JS_SEC_FS_IMPORT_RE.search(text):
            for m in _JS_SEC_FS_CALL_RE.finditer(masked):
                arg = self._call_arg(m.end() - 1)
                if _JS_SEC_REQ_DATA_RE.search(arg):
                    self._sec("medium", "low", m.start(1),
                              "fs.%s() path built from request data (possible path traversal)" % m.group(1))
        for m in _JS_SEC_REGEXP_RE.finditer(masked):
            arg = self._call_arg(m.end() - 1)
            if _JS_SEC_REQ_DATA_RE.search(arg):
                self._sec("low", "low", m.start(), "new RegExp() built from request data (ReDoS / pattern injection)")


# --------------------------------------------------------------------------
# JavaScript / TypeScript: import graph (relative specifiers + tsconfig paths)
# --------------------------------------------------------------------------
_JS_IMPORT_FROM_RE = re.compile(r"(?<![\w$.])(import|export)\b([^;'\"`=]*?)\bfrom\s*(['\"])")
_JS_TYPE_ONLY_RE = re.compile(r"\s*type\b(?!\s*,)")
_JS_IMPORT_SIDE_RE = re.compile(r"(?<![\w$.])import\s*(['\"])")
_JS_IMPORT_DYN_RE = re.compile(r"(?<![\w$.])import\s*\(\s*(['\"])")
_JS_REQUIRE_RE = re.compile(r"(?<![\w$.])require\s*\(\s*(['\"])")
JS_RESOLVE_EXTS: Tuple[str, ...] = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".json")
_JS_TS_ALTERNATIVES: Dict[str, Tuple[str, ...]] = {
    ".js": (".ts", ".tsx", ".d.ts"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",),
}
_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")


@dataclasses.dataclass
class JsImport:
    specifier: str
    lineno: int
    col: int
    soft: bool
    snippet: str


@dataclasses.dataclass
class JsModule:
    rel: str
    imports: List[JsImport]


@dataclasses.dataclass
class JsPathAliases:
    base_dir: str                           # directory of the tsconfig/jsconfig, relative to the scan root
    base_url: Optional[str]                 # compilerOptions.baseUrl, relative to base_dir (None when absent)
    paths: List[Tuple[str, List[str]]]      # compilerOptions.paths entries in declaration order


def parse_jsonc(text: str) -> object:
    """json.loads for tsconfig-style JSON: comments and trailing commas removed."""
    stripped = strip_comments(text, "js")
    stripped = _TRAILING_COMMA_RE.sub(r"\1", stripped)
    return json.loads(stripped)


def load_js_path_aliases(rel: str, text: str, warnings: List[str]) -> Optional[JsPathAliases]:
    try:
        data = parse_jsonc(text)
    except ValueError as exc:
        warnings.append("%s: cannot parse (%s); path aliases ignored" % (rel, exc))
        return None
    if not isinstance(data, dict):
        warnings.append("%s: expected a JSON object; path aliases ignored" % rel)
        return None
    options = data.get("compilerOptions")
    if not isinstance(options, dict):
        return None
    base_url = options.get("baseUrl")
    if not isinstance(base_url, str) or not base_url.strip():
        base_url = None
    raw_paths = options.get("paths")
    paths: List[Tuple[str, List[str]]] = []
    if isinstance(raw_paths, dict):
        for pattern, targets in raw_paths.items():
            if isinstance(pattern, str) and isinstance(targets, list):
                paths.append((pattern, [t for t in targets if isinstance(t, str)]))
    if base_url is None and not paths:
        return None
    return JsPathAliases(posixpath.dirname(rel), base_url, paths)


def _alias_capture(pattern: str, spec: str) -> Optional[str]:
    if "*" in pattern:
        prefix, suffix = pattern.split("*", 1)
        if spec.startswith(prefix) and spec.endswith(suffix) and len(spec) >= len(prefix) + len(suffix):
            return spec[len(prefix):len(spec) - len(suffix)]
        return None
    return "" if spec == pattern else None


def js_module_name(rel: str) -> str:
    """POSIX relative path without extension (`src/a/index` for src/a/index.ts)."""
    return posixpath.splitext(rel)[0]


def js_layer_name(name: str, package_roots: Sequence[str]) -> str:
    """Dotted path under the first matching package root, so layer names map
    to the first path segment under that root."""
    for root in package_roots:
        r = root.strip().strip("/").replace("\\", "/")
        if r in ("", "."):
            return name.replace("/", ".")
        if name.startswith(r + "/"):
            return name[len(r) + 1:].replace("/", ".")
    return name.replace("/", ".")


class JsModuleResolver:
    def __init__(self, known_rels: Iterable[str], aliases: Sequence[JsPathAliases]) -> None:
        self.known: Set[str] = set(known_rels)
        self.aliases = list(aliases)

    def _try(self, base: str) -> Optional[str]:
        if base.startswith("../") or base in ("..", ".", ""):
            return None
        if base in self.known:
            return base
        for ext in JS_RESOLVE_EXTS:
            if base + ext in self.known:
                return base + ext
        stem, ext = posixpath.splitext(base)
        for alt in _JS_TS_ALTERNATIVES.get(ext, ()):
            if stem + alt in self.known:
                return stem + alt
        for ext in JS_RESOLVE_EXTS:
            cand = base + "/index" + ext
            if cand in self.known:
                return cand
        return None

    def resolve(self, from_rel: str, spec: str) -> Optional[str]:
        """Resolve a specifier to a known file's relative path, or None for
        bare package specifiers, absolute paths and unknown files."""
        if spec.startswith(("./", "../")) or spec in (".", ".."):
            return self._try(posixpath.normpath(posixpath.join(posixpath.dirname(from_rel), spec)))
        if spec.startswith("/") or spec.startswith("node:"):
            return None
        for al in self.aliases:
            root = posixpath.normpath(posixpath.join(al.base_dir, al.base_url or ".")) if (al.base_dir or al.base_url) else "."
            for pattern, targets in al.paths:
                captured = _alias_capture(pattern, spec)
                if captured is None:
                    continue
                for target in targets:
                    cand = target.replace("*", captured, 1) if "*" in target else target
                    hit = self._try(posixpath.normpath(posixpath.join(root, cand)))
                    if hit:
                        return hit
            if al.base_url is not None:
                hit = self._try(posixpath.normpath(posixpath.join(root, spec)))
                if hit:
                    return hit
        return None


# --------------------------------------------------------------------------
# Python AST analysis
# --------------------------------------------------------------------------
BLOCKING_CALLS: Set[str] = {
    "time.sleep", "input", "open", "io.open", "urllib.request.urlopen",
    "subprocess.run", "subprocess.call", "subprocess.check_output", "subprocess.check_call",
    "subprocess.getoutput", "subprocess.getstatusoutput", "os.system", "os.popen", "os.wait",
    "socket.create_connection", "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
    "requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete",
    "requests.head", "requests.options", "requests.request", "requests.Session",
    "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete", "httpx.head", "httpx.request",
    "urllib3.PoolManager", "pathlib.Path.read_text", "pathlib.Path.read_bytes",
    "pathlib.Path.write_text", "pathlib.Path.write_bytes",
}
BLOCKING_REMEDIATION: Dict[str, str] = {
    "time.sleep": "Use `await asyncio.sleep(...)`.",
    "input": "Read input in a thread: `await asyncio.to_thread(input, ...)`.",
    "open": "Use aiofiles or `await asyncio.to_thread(...)` for file I/O.",
    "io.open": "Use aiofiles or `await asyncio.to_thread(...)` for file I/O.",
    "urllib.request.urlopen": "Use aiohttp or httpx.AsyncClient.",
}
PATH_IO_METHODS = {"read_text", "read_bytes", "write_text", "write_bytes"}
SOCKET_CTORS = {"socket.socket", "socket.create_connection", "socket.create_server", "subprocess.Popen"}
SOCKET_BLOCKING_METHODS = {"recv", "recvfrom", "recv_into", "send", "sendall", "sendto", "accept",
                           "connect", "wait", "communicate", "makefile", "sendfile"}
EXECUTOR_WRAPPERS = {"asyncio.to_thread", "anyio.to_thread.run_sync", "trio.to_thread.run_sync",
                     "asyncio.get_running_loop().run_in_executor"}
TASK_SPAWNERS = {"asyncio.create_task", "asyncio.ensure_future"}
RESOURCE_CALLS: Set[str] = {
    "open", "io.open", "codecs.open", "socket.socket", "socket.create_connection", "socket.create_server",
    "urllib.request.urlopen", "sqlite3.connect", "tempfile.NamedTemporaryFile", "tempfile.TemporaryFile",
    "tempfile.SpooledTemporaryFile", "subprocess.Popen", "zipfile.ZipFile", "tarfile.open",
    "gzip.open", "bz2.open", "lzma.open",
}
CONTAINER_STORE_METHODS = {"append", "add", "insert", "extend", "put", "put_nowait", "setdefault",
                           "update", "push", "appendleft", "register", "callback", "enter_context",
                           "closing", "add_resource", "track"}
MANAGED_METHODS = {"enter_context", "closing", "callback", "push"}
SHELL_SINKS: Set[str] = {"os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput",
                         "subprocess.getoutput", "subprocess.getstatusoutput", "os.popen2", "os.popen3"}
SUBPROCESS_FUNCS: Set[str] = {"subprocess.run", "subprocess.call", "subprocess.check_output",
                              "subprocess.check_call", "subprocess.Popen"}
PICKLE_SINKS: Set[str] = set()
for _mod in ("pickle", "cPickle", "_pickle", "dill", "cloudpickle", "shelve"):
    for _fn in ("loads", "load", "Unpickler"):
        PICKLE_SINKS.add(_mod + "." + _fn)
PICKLE_SINKS.discard("shelve.loads")
PICKLE_SINKS.discard("shelve.load")
PICKLE_SINKS.discard("shelve.Unpickler")
PICKLE_SINKS.add("shelve.open")
MARSHAL_SINKS = {"marshal.loads", "marshal.load"}
YAML_SINKS = {"yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.unsafe_load_all"}
SAFE_YAML_LOADERS = re.compile(r"^(?:yaml\.)?(?:C)?(?:Safe|Base)Loader$")
BUILTIN_SINK_NAMES = {"open", "eval", "exec", "compile", "input", "__import__", "list", "dict", "set"}
MUTATOR_METHODS = {"append", "extend", "insert", "pop", "remove", "clear", "update", "setdefault",
                   "popitem", "add", "discard", "sort", "reverse", "appendleft", "popleft"}
LOCK_CTORS = {"asyncio.Lock", "threading.Lock", "threading.RLock", "asyncio.Semaphore",
              "threading.Semaphore", "asyncio.Condition", "threading.Condition", "multiprocessing.Lock",
              "asyncio.BoundedSemaphore", "threading.BoundedSemaphore"}


def walk_scope(node: ast.AST) -> Iterator[ast.AST]:
    """Iterate the descendants of `node` without descending into nested
    function definitions (which are scored as their own scope)."""
    stack = list(reversed(list(ast.iter_child_nodes(node))))
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, _FUNC_TYPES):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(n))))


def is_constant_expr(node: Optional[ast.AST]) -> bool:
    """True when the expression is a literal (string/number/tuple of literals,
    f-string without placeholders, concatenation of literals)."""
    if node is None:
        return False
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, ast.Constant):
            continue
        if isinstance(n, (ast.Tuple, ast.List, ast.Set)):
            stack.extend(n.elts)
        elif isinstance(n, ast.JoinedStr):
            if any(not isinstance(v, ast.Constant) for v in n.values):
                return False
        elif isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mult)):
            stack.append(n.left)
            stack.append(n.right)
        else:
            return False
    return True


_BRANCH_TYPES: Tuple[type, ...] = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert)


def scope_metrics(scope: ast.AST) -> Tuple[int, int, Optional[ast.AST]]:
    """One pass over a scope (nested functions excluded) returning
    (cyclomatic complexity, max nesting depth, deepest block node).

    McCabe = 1 + if/elif + loops + except handlers + boolean operands beyond
    the first + ternaries + comprehension for/if + match cases + asserts.
    Nesting counts if/for/while/try/with/match; an `elif` adds no level."""
    score = 1
    best_depth, best_node = 0, None
    stack: List[Tuple[ast.AST, int]] = [(c, 0) for c in reversed(list(ast.iter_child_nodes(scope)))]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, _FUNC_TYPES):
            continue
        if isinstance(node, _BRANCH_TYPES):
            score += 1
        elif isinstance(node, ast.BoolOp):
            score += max(0, len(node.values) - 1)
        elif isinstance(node, ast.comprehension):
            score += 1 + len(node.ifs)
        elif _AST_MATCH_CASE is not None and isinstance(node, _AST_MATCH_CASE):
            score += 1
        if isinstance(node, _BLOCK_TYPES):
            d = depth + 1
            if d > best_depth:
                best_depth, best_node = d, node
            if isinstance(node, ast.If):
                if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                    stack.append((node.orelse[0], depth))
                else:
                    for c in reversed(node.orelse):
                        stack.append((c, d))
                for c in reversed(node.body):
                    stack.append((c, d))
                stack.append((node.test, d))
            else:
                for c in reversed(list(ast.iter_child_nodes(node))):
                    stack.append((c, d))
        else:
            for c in reversed(list(ast.iter_child_nodes(node))):
                stack.append((c, depth))
    return score, best_depth, best_node


def cyclomatic_complexity(func: ast.AST) -> int:
    return scope_metrics(func)[0]


def max_nesting(scope: ast.AST) -> Tuple[int, Optional[ast.AST]]:
    _, depth, node = scope_metrics(scope)
    return depth, node


def _direct_names(expr: Optional[ast.AST]) -> Set[str]:
    """Names that are passed along 'as is' (possibly inside a literal container
    or await), i.e. the resource itself escapes rather than a derived value."""
    names: Set[str] = set()
    if expr is None:
        return names
    stack = [expr]
    while stack:
        n = stack.pop()
        if isinstance(n, ast.Name):
            names.add(n.id)
        elif isinstance(n, (ast.Tuple, ast.List, ast.Set)):
            stack.extend(n.elts)
        elif isinstance(n, ast.Dict):
            stack.extend(v for v in n.values if v is not None)
        elif isinstance(n, (ast.Await, ast.Starred)):
            stack.append(n.value)
    return names


@dataclasses.dataclass
class ImportRecord:
    module: Optional[str]   # dotted module for `from X import ...`, or the name for `import X`
    names: List[str]        # imported names (for from-imports), [] for `import X`
    level: int
    lineno: int
    col: int
    soft: bool
    snippet: str


@dataclasses.dataclass
class ModuleRecord:
    name: str
    rel: str
    is_package: bool
    imports: List[ImportRecord] = dataclasses.field(default_factory=list)
    layer_name: str = ""  # dotted name used for layer / forbidden-import matching (defaults to name)


class ScopeUsage:
    __slots__ = ("loads", "closed_finally", "closed_any", "managed", "escaped")

    def __init__(self) -> None:
        self.loads: Set[str] = set()
        self.closed_finally: Set[str] = set()
        self.closed_any: Set[str] = set()
        self.managed: Set[str] = set()
        self.escaped: Set[str] = set()


class PythonAnalyzer:
    """Single-pass analysis of one parsed module. Emits findings through the
    `emit` callback and returns a ModuleRecord for the import graph."""

    def __init__(self, sf: SourceFile, tree: ast.Module, config: Config, emit, module_name: Optional[str],
                 is_package: bool) -> None:
        self.sf = sf
        self.tree = tree
        self.config = config
        self.emit = emit
        self.module = ModuleRecord(module_name or "", sf.rel, is_package)
        self.parents, self._nodes = self._index_tree(tree)
        self.aliases: Dict[str, str] = {}
        self.shadowed: Set[str] = set()
        self.blocking = set(BLOCKING_CALLS) | set(config.extra_blocking_calls)
        self.shell_sinks = set(SHELL_SINKS) | set(config.extra_dangerous_sinks)
        self._scope_cache: Dict[ast.AST, ScopeUsage] = {}
        self._socket_vars: Dict[ast.AST, Set[str]] = {}
        self._taskgroup_vars: Dict[ast.AST, Set[str]] = {}
        self._locals_cache: Dict[ast.AST, Set[str]] = {}
        self.module_mutables: Set[str] = set()
        self._async3_seen: Set[Tuple[int, str]] = set()
        self.th = config.thresholds

    _INTERESTING: Tuple[type, ...] = (ast.Call, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                      ast.ExceptHandler, ast.Import, ast.ImportFrom, ast.Assign,
                                      ast.AugAssign, ast.AnnAssign, ast.Delete)

    @classmethod
    def _index_tree(cls, tree: ast.AST) -> Tuple[Dict[ast.AST, ast.AST], List[ast.AST]]:
        """One iterative pre-order traversal: parent map plus the nodes the
        rules care about, in source order."""
        parents: Dict[ast.AST, ast.AST] = {}
        nodes: List[ast.AST] = []
        interesting = cls._INTERESTING
        stack = [tree]
        while stack:
            node = stack.pop()
            if isinstance(node, interesting):
                nodes.append(node)
            children = list(ast.iter_child_nodes(node))
            for child in children:
                parents[child] = node
            stack.extend(reversed(children))
        return parents, nodes

    # -- helpers -----------------------------------------------------------
    def _finding(self, rule_id: str, severity: str, confidence: str, node: ast.AST, message: str,
                 remediation: Optional[str] = None) -> None:
        lineno = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1
        self.emit(Finding(rule_id, severity, confidence, self.sf.rel, lineno, col, message,
                          self.sf.snippet(lineno), remediation or RULES[rule_id].remediation))

    def enclosing_function(self, node: ast.AST) -> Optional[ast.AST]:
        p = self.parents.get(node)
        while p is not None:
            if isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return p
            p = self.parents.get(p)
        return None

    def enclosing_scope(self, node: ast.AST) -> ast.AST:
        func = self.enclosing_function(node)
        return func if func is not None else self.tree

    def dotted_parts(self, node: ast.AST) -> Optional[List[str]]:
        parts: List[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            parts.reverse()
            return parts
        return None

    def resolve(self, node: ast.AST) -> Optional[str]:
        """Resolve a Name/Attribute chain to a fully-qualified dotted name,
        following import aliases."""
        parts = self.dotted_parts(node)
        if not parts:
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Call):
                inner = self.resolve(node.value.func)
                if inner == "asyncio.get_event_loop" or inner == "asyncio.get_running_loop":
                    return "asyncio.get_running_loop()." + node.attr
                if inner in ("pathlib.Path", "pathlib.PurePath"):
                    return "pathlib.Path." + node.attr
            return None
        head = parts[0]
        full = self.aliases.get(head)
        if full is None:
            if head in self.shadowed and head in BUILTIN_SINK_NAMES:
                return None
            full = head
        return ".".join([full] + parts[1:])

    def last_attr(self, node: ast.AST) -> Optional[str]:
        return node.attr if isinstance(node, ast.Attribute) else None

    def is_awaited(self, node: ast.AST) -> bool:
        return isinstance(self.parents.get(node), ast.Await)

    def scope_usage(self, scope: ast.AST) -> ScopeUsage:
        usage = self._scope_cache.get(scope)
        if usage is not None:
            return usage
        usage = ScopeUsage()
        for n in ast.walk(scope):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                usage.loads.add(n.id)
            elif isinstance(n, ast.Attribute) and n.attr == "close" and isinstance(n.value, ast.Name):
                usage.closed_any.add(n.value.id)
            elif isinstance(n, _TRY_TYPES):
                for stmt in n.finalbody:
                    for m in ast.walk(stmt):
                        if isinstance(m, ast.Attribute) and m.attr == "close" and isinstance(m.value, ast.Name):
                            usage.closed_finally.add(m.value.id)
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                for item in n.items:
                    ce = item.context_expr
                    if isinstance(ce, ast.Name):
                        usage.managed.add(ce.id)
                    elif isinstance(ce, ast.Call):
                        for a in ce.args:
                            usage.managed |= _direct_names(a)
            elif isinstance(n, (ast.Return, ast.Yield, ast.YieldFrom)):
                usage.escaped |= _direct_names(n.value)
            elif isinstance(n, ast.Assign):
                if any(isinstance(t, (ast.Attribute, ast.Subscript)) for t in n.targets):
                    usage.escaped |= _direct_names(n.value)
            elif isinstance(n, ast.AnnAssign):
                if isinstance(n.target, (ast.Attribute, ast.Subscript)):
                    usage.escaped |= _direct_names(n.value)
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                if n.func.attr in MANAGED_METHODS:
                    for a in n.args:
                        usage.managed |= _direct_names(a)
                elif n.func.attr in CONTAINER_STORE_METHODS:
                    for a in n.args:
                        usage.escaped |= _direct_names(a)
                    for kw in n.keywords:
                        usage.escaped |= _direct_names(kw.value)
            elif isinstance(n, ast.Call) and self.resolve(n.func) == "contextlib.closing":
                for a in n.args:
                    usage.managed |= _direct_names(a)
        self._scope_cache[scope] = usage
        return usage

    def function_locals(self, func: ast.AST) -> Set[str]:
        names = self._locals_cache.get(func)
        if names is not None:
            return names
        names = set()
        args = getattr(func, "args", None)
        if args is not None:
            for a in list(args.args) + list(args.kwonlyargs) + list(getattr(args, "posonlyargs", [])):
                names.add(a.arg)
            if args.vararg:
                names.add(args.vararg.arg)
            if args.kwarg:
                names.add(args.kwarg.arg)
        declared_global: Set[str] = set()
        for n in walk_scope(func):
            if isinstance(n, ast.Global):
                declared_global.update(n.names)
            elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                names.add(n.id)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                for alias in n.names:
                    names.add((alias.asname or alias.name).split(".")[0])
        names -= declared_global
        self._locals_cache[func] = names
        return names

    def socket_vars(self, func: ast.AST) -> Set[str]:
        names = self._socket_vars.get(func)
        if names is None:
            names = set()
            for n in walk_scope(func):
                if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) and len(n.targets) == 1 \
                        and isinstance(n.targets[0], ast.Name) and self.resolve(n.value.func) in SOCKET_CTORS:
                    names.add(n.targets[0].id)
            self._socket_vars[func] = names
        return names

    def taskgroup_vars(self, func: ast.AST) -> Set[str]:
        names = self._taskgroup_vars.get(func)
        if names is None:
            names = set()
            for n in walk_scope(func):
                if isinstance(n, (ast.With, ast.AsyncWith)):
                    for item in n.items:
                        ce = item.context_expr
                        if isinstance(ce, ast.Call) and isinstance(item.optional_vars, ast.Name):
                            r = self.resolve(ce.func) or ""
                            if r.endswith("TaskGroup") or r.endswith("open_nursery") or r.endswith("create_task_group"):
                                names.add(item.optional_vars.id)
            self._taskgroup_vars[func] = names
        return names

    def _in_executor_wrapper(self, call: ast.Call) -> bool:
        node: ast.AST = call
        p = self.parents.get(node)
        while p is not None and not isinstance(p, ast.stmt):
            if isinstance(p, ast.Call) and node is not p.func:
                r = self.resolve(p.func) or ""
                attr = self.last_attr(p.func)
                if r in EXECUTOR_WRAPPERS or attr in ("run_in_executor", "to_thread", "run_sync"):
                    return True
            node, p = p, self.parents.get(p)
        return False

    def _under_type_checking(self, node: ast.AST) -> bool:
        p = self.parents.get(node)
        while p is not None:
            if isinstance(p, ast.If):
                t = p.test
                if (isinstance(t, ast.Name) and t.id == "TYPE_CHECKING") or \
                        (isinstance(t, ast.Attribute) and t.attr == "TYPE_CHECKING"):
                    return True
            p = self.parents.get(p)
        return False

    def _lock_held(self, node: ast.AST) -> bool:
        p = self.parents.get(node)
        while p is not None and not isinstance(p, _FUNC_TYPES):
            if isinstance(p, (ast.With, ast.AsyncWith)):
                for item in p.items:
                    ce = item.context_expr
                    text = ".".join(self.dotted_parts(ce) or []) if not isinstance(ce, ast.Call) \
                        else (self.resolve(ce.func) or ".".join(self.dotted_parts(ce.func) or []))
                    low = text.lower()
                    if text in LOCK_CTORS or "lock" in low or "mutex" in low or "sem" in low or "condition" in low:
                        return True
            p = self.parents.get(p)
        return False

    # -- pass 0: aliases, shadowing, module mutables -----------------------
    def _collect_module_info(self) -> None:
        for n in self._nodes:
            if isinstance(n, ast.Import):
                for alias in n.names:
                    if alias.asname:
                        self.aliases[alias.asname] = alias.name
                    else:
                        top = alias.name.split(".")[0]
                        self.aliases[top] = top
            elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                for alias in n.names:
                    if alias.name == "*":
                        continue
                    self.aliases[alias.asname or alias.name] = n.module + "." + alias.name
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if self.parents.get(n) is self.tree:
                    self.shadowed.add(n.name)
        for stmt in self.tree.body:
            targets: List[ast.AST] = []
            value: Optional[ast.AST] = None
            if isinstance(stmt, ast.Assign):
                targets, value = list(stmt.targets), stmt.value
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                targets, value = [stmt.target], stmt.value
            for t in targets:
                if isinstance(t, ast.Name):
                    self.shadowed.add(t.id)
                    if self._is_mutable_literal(value):
                        self.module_mutables.add(t.id)

    def _is_mutable_literal(self, value: Optional[ast.AST]) -> bool:
        if isinstance(value, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)):
            return True
        if isinstance(value, ast.Call):
            r = self.resolve(value.func)
            return r in ("list", "dict", "set", "collections.defaultdict", "collections.OrderedDict",
                         "collections.deque", "collections.Counter", "collections.ChainMap")
        return False

    # -- main pass ---------------------------------------------------------
    def run(self) -> ModuleRecord:
        self._collect_module_info()
        self._check_scope_quality(self.tree, "<module>")
        for node in self._nodes:
            if isinstance(node, ast.Call):
                self._visit_call(node)
            elif isinstance(node, _FUNC_TYPES):
                self._visit_function(node)
            elif isinstance(node, ast.ExceptHandler):
                self._visit_handler(node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                self._visit_import(node)
            elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete)):
                self._visit_store(node)
        return self.module

    def _visit_import(self, node: ast.AST) -> None:
        soft = self.enclosing_function(node) is not None or self._under_type_checking(node)
        snippet = self.sf.snippet(node.lineno)
        if isinstance(node, ast.Import):
            for alias in node.names:
                self.module.imports.append(ImportRecord(alias.name, [], 0, node.lineno, node.col_offset + 1, soft, snippet))
        else:
            names = [a.name for a in node.names]
            self.module.imports.append(ImportRecord(node.module, names, node.level, node.lineno,
                                                    node.col_offset + 1, soft, snippet))

    def _visit_function(self, func: ast.AST) -> None:
        self._check_scope_quality(func, func.name)

    def _check_scope_quality(self, scope: ast.AST, name: str) -> None:
        max_cc = self.th.get("max_cyclomatic_complexity", 10)
        max_depth = self.th.get("max_nesting_depth", 4)
        cc, depth, node = scope_metrics(scope)
        if isinstance(scope, _FUNC_TYPES) and cc > max_cc:
            severity = "high" if cc > 2 * max_cc else "medium"
            self._finding("RS-QUAL-001", severity, "high", scope,
                          "Function '%s' has cyclomatic complexity %d (threshold %d)" % (name, cc, max_cc))
        if depth > max_depth and node is not None:
            self._finding("RS-QUAL-002", RULES["RS-QUAL-002"].severity, "high", node,
                          "Nesting depth %d exceeds %d in %s" % (depth, max_depth,
                                                                 "function '%s'" % name if name != "<module>" else "module scope"))

    def _visit_handler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self._finding("RS-QUAL-003", RULES["RS-QUAL-003"].severity, "high", node, "Bare `except:` catches everything")
            return
        types = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
        broad = any(isinstance(t, ast.Name) and t.id in ("Exception", "BaseException") or
                    isinstance(t, ast.Attribute) and t.attr in ("Exception", "BaseException") for t in types)
        if not broad:
            return
        for stmt in node.body:
            if isinstance(stmt, (ast.Pass, ast.Continue)):
                continue
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis:
                continue
            return
        self._finding("RS-QUAL-004", RULES["RS-QUAL-004"].severity, "high", node,
                      "Broad exception handler silently swallows errors")

    def _visit_store(self, node: ast.AST) -> None:
        if not self.module_mutables:
            return
        func = self.enclosing_function(node)
        if not isinstance(func, ast.AsyncFunctionDef):
            return
        targets: List[ast.AST]
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.Delete):
            targets = list(node.targets)
        else:
            targets = [node.target]
        for t in targets:
            if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id in self.module_mutables:
                self._report_shared_mutation(func, node, t.value.id, "item assignment")

    def _report_shared_mutation(self, func: ast.AST, node: ast.AST, var: str, how: str) -> None:
        if var in self.function_locals(func):
            return
        key = (func.lineno, var)
        if key in self._async3_seen:
            return
        if self._lock_held(node):
            return
        self._async3_seen.add(key)
        self._finding("RS-ASYNC-003", RULES["RS-ASYNC-003"].severity, "low", node,
                      "Module-level mutable '%s' mutated (%s) in async function '%s' without a lock" % (var, how, func.name))

    def _visit_call(self, call: ast.Call) -> None:
        resolved = self.resolve(call.func)
        attr = self.last_attr(call.func)
        self._check_async_blocking(call, resolved, attr)
        self._check_fire_and_forget(call, resolved, attr)
        self._check_resource(call, resolved)
        self._check_sinks(call, resolved)
        if attr in MUTATOR_METHODS and isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) \
                and call.func.value.id in self.module_mutables:
            func = self.enclosing_function(call)
            if isinstance(func, ast.AsyncFunctionDef):
                self._report_shared_mutation(func, call, call.func.value.id, ".%s()" % attr)

    # -- RS-ASYNC-001 ------------------------------------------------------
    def _check_async_blocking(self, call: ast.Call, resolved: Optional[str], attr: Optional[str]) -> None:
        func = self.enclosing_function(call)
        if not isinstance(func, ast.AsyncFunctionDef):
            return
        if self.is_awaited(call) or self._in_executor_wrapper(call):
            return
        label: Optional[str] = None
        confidence = "high"
        if resolved in self.blocking:
            label = resolved
        elif resolved and resolved.startswith(("requests.", "httpx.")) and attr in (
                "get", "post", "put", "patch", "delete", "head", "options", "request"):
            label = resolved
        elif attr in PATH_IO_METHODS:
            label = "%s()" % attr
            confidence = "medium" if resolved is None or not resolved.startswith("pathlib.Path") else "high"
        elif attr in SOCKET_BLOCKING_METHODS and isinstance(call.func, ast.Attribute) \
                and isinstance(call.func.value, ast.Name) and call.func.value.id in self.socket_vars(func):
            label = "%s.%s()" % (call.func.value.id, attr)
            confidence = "medium"
        if label is None:
            return
        rem = BLOCKING_REMEDIATION.get(label, RULES["RS-ASYNC-001"].remediation)
        self._finding("RS-ASYNC-001", RULES["RS-ASYNC-001"].severity, confidence, call,
                      "Blocking call %s inside async function '%s'" % (label if label.endswith(")") else label + "()", func.name), rem)

    # -- RS-ASYNC-002 ------------------------------------------------------
    def _check_fire_and_forget(self, call: ast.Call, resolved: Optional[str], attr: Optional[str]) -> None:
        if resolved in TASK_SPAWNERS:
            pass
        elif attr in ("create_task", "ensure_future") and isinstance(call.func, ast.Attribute):
            base = call.func.value
            if isinstance(base, ast.Name):
                func = self.enclosing_function(call)
                if base.id in ("self", "cls") or (func is not None and base.id in self.taskgroup_vars(func)):
                    return
            elif not (isinstance(base, ast.Call) and (self.resolve(base.func) or "").startswith("asyncio.get_")):
                return
        else:
            return
        parent = self.parents.get(call)
        scope = self.enclosing_scope(call)
        if isinstance(parent, ast.Expr):
            self._finding("RS-ASYNC-002", RULES["RS-ASYNC-002"].severity, "high", call,
                          "Task created with %s but its handle is discarded" % (resolved or attr))
            return
        target: Optional[ast.AST] = None
        if isinstance(parent, ast.Assign) and len(parent.targets) == 1 and parent.value is call:
            target = parent.targets[0]
        elif isinstance(parent, ast.AnnAssign) and parent.value is call:
            target = parent.target
        if isinstance(target, ast.Name) and target.id not in self.scope_usage(scope).loads:
            self._finding("RS-ASYNC-002", RULES["RS-ASYNC-002"].severity, "medium", call,
                          "Task stored in '%s' is never awaited, gathered, returned or given a callback" % target.id)

    # -- RS-RES-001 --------------------------------------------------------
    def _check_resource(self, call: ast.Call, resolved: Optional[str]) -> None:
        if resolved not in RESOURCE_CALLS:
            return
        label = resolved + "()"
        node: ast.AST = call
        p = self.parents.get(node)
        confidence = "high"
        while p is not None and not isinstance(p, ast.stmt):
            if isinstance(p, (ast.withitem, ast.Yield, ast.YieldFrom, ast.Await, ast.Lambda)):
                return
            if isinstance(p, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
                return
            if isinstance(p, ast.Call) and node is not p.func:
                r = self.resolve(p.func) or ""
                a = self.last_attr(p.func)
                if r == "contextlib.closing" or a in CONTAINER_STORE_METHODS or a in MANAGED_METHODS:
                    return
                confidence = "medium"
            elif isinstance(p, ast.Attribute):
                confidence = "medium"
            node, p = p, self.parents.get(p)
        stmt = p
        if stmt is None or isinstance(stmt, (ast.Return, ast.With, ast.AsyncWith)):
            return
        severity = RULES["RS-RES-001"].severity
        extra = ""
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and node is stmt.value:
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                return
            var = targets[0].id
            usage = self.scope_usage(self.enclosing_scope(call))
            if var in usage.closed_finally or var in usage.managed or var in usage.escaped:
                return
            if var in usage.closed_any:
                severity, confidence = "low", "low"
                extra = " (closed, but not in a `finally` block)"
            label = "%s() assigned to '%s'" % (resolved, var)
        self._finding("RS-RES-001", severity, confidence, call,
                      "Resource from %s is not managed by `with`, closing() or try/finally%s" % (label, extra))

    # -- RS-SEC-003 / RS-SEC-004 -------------------------------------------
    def _first_arg(self, call: ast.Call, kw_names: Sequence[str] = ()) -> Optional[ast.AST]:
        if call.args:
            a = call.args[0]
            return a
        for kw in call.keywords:
            if kw.arg in kw_names:
                return kw.value
        return None

    def _keyword(self, call: ast.Call, name: str) -> Optional[ast.AST]:
        for kw in call.keywords:
            if kw.arg == name:
                return kw.value
        return None

    def _check_sinks(self, call: ast.Call, resolved: Optional[str]) -> None:
        if resolved is None:
            return
        rem3 = RULES["RS-SEC-003"].remediation
        rem4 = RULES["RS-SEC-004"].remediation
        if resolved in self.shell_sinks:
            arg = self._first_arg(call, ("cmd", "command", "args"))
            if arg is None:
                return
            const = is_constant_expr(arg)
            self._finding("RS-SEC-003", _sev_for_arg(const), "high", call,
                          "Shell command execution via %s() with %s argument"
                          % (resolved, "constant" if const else "non-constant"), rem3)
            return
        if resolved in SUBPROCESS_FUNCS:
            shell = self._keyword(call, "shell")
            if isinstance(shell, ast.Constant) and shell.value is True:
                arg = self._first_arg(call, ("args", "cmd"))
                const = is_constant_expr(arg) if arg is not None else True
                self._finding("RS-SEC-003", _sev_for_arg(const), "high", call,
                              "%s() with shell=True and %s command" % (resolved, "constant" if const else "non-constant"), rem3)
            return
        if resolved in ("eval", "exec", "builtins.eval", "builtins.exec"):
            arg = self._first_arg(call, ("source", "expression"))
            if arg is None:
                return
            const = is_constant_expr(arg)
            self._finding("RS-SEC-004", _sev_for_arg(const), "high", call,
                          "%s() of a %s expression" % (resolved.split(".")[-1], "constant" if const else "non-constant"), rem4)
            return
        if resolved in ("compile", "builtins.compile"):
            arg = self._first_arg(call, ("source",))
            if arg is not None and not is_constant_expr(arg):
                self._finding("RS-SEC-004", "critical", "medium", call, "compile() of a non-constant source", rem4)
            return
        if resolved in ("__import__", "builtins.__import__", "importlib.import_module", "importlib.__import__"):
            arg = self._first_arg(call, ("name",))
            if arg is not None and not is_constant_expr(arg):
                confidence = "high" if resolved.endswith("__import__") else "medium"
                self._finding("RS-SEC-004", "critical", confidence, call,
                              "%s() with a non-constant module name" % resolved, rem4)
            return
        if resolved in PICKLE_SINKS:
            self._finding("RS-SEC-004", "high", "high", call,
                          "%s() deserializes untrusted data into arbitrary objects" % resolved, rem4)
            return
        if resolved in MARSHAL_SINKS:
            self._finding("RS-SEC-004", "high", "high", call, "%s() loads code objects from data" % resolved, rem4)
            return
        if resolved in YAML_SINKS:
            loader = self._keyword(call, "Loader")
            if loader is None and len(call.args) >= 2:
                loader = call.args[1]
            if loader is not None:
                name = ".".join(self.dotted_parts(loader) or [])
                if SAFE_YAML_LOADERS.match(name) or SAFE_YAML_LOADERS.match(name.split(".")[-1]):
                    return
            self._finding("RS-SEC-004", "high", "high", call,
                          "%s() without SafeLoader can instantiate arbitrary Python objects" % resolved,
                          "Use yaml.safe_load() or pass Loader=yaml.SafeLoader.")


# --------------------------------------------------------------------------
# Module import graph: cycles (iterative Tarjan) and layer rules
# --------------------------------------------------------------------------
def tarjan_scc(nodes: Iterable[str], edges: Dict[str, Set[str]]) -> List[List[str]]:
    """Strongly connected components, computed iteratively (no recursion),
    returned as sorted lists in a deterministic order."""
    index: Dict[str, int] = {}
    lowlink: Dict[str, int] = {}
    on_stack: Set[str] = set()
    stack: List[str] = []
    result: List[List[str]] = []
    counter = 0
    for root in sorted(nodes):
        if root in index:
            continue
        work: List[Tuple[str, Iterator[str]]] = [(root, iter(sorted(edges.get(root, ()))))]
        index[root] = lowlink[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            v, it = work[-1]
            advanced = False
            for w in it:
                if w not in index:
                    index[w] = lowlink[w] = counter
                    counter += 1
                    stack.append(w)
                    on_stack.add(w)
                    work.append((w, iter(sorted(edges.get(w, ())))))
                    advanced = True
                    break
                if w in on_stack:
                    lowlink[v] = min(lowlink[v], index[w])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[v])
            if lowlink[v] == index[v]:
                comp: List[str] = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                result.append(sorted(comp))
    result.sort(key=lambda c: c[0])
    return result


def find_cycle_path(component: Sequence[str], edges: Dict[str, Set[str]]) -> List[str]:
    """A concrete cycle through the component, found with an iterative BFS
    from its smallest node and back."""
    members = set(component)
    start = min(component)
    if len(component) == 1:
        return [start, start]
    parent: Dict[str, Optional[str]] = {start: None}
    queue = collections.deque([start])
    while queue:
        u = queue.popleft()
        for w in sorted(edges.get(u, ())):
            if w not in members:
                continue
            if w == start:
                path = [u]
                while parent[path[-1]] is not None:
                    path.append(parent[path[-1]])  # type: ignore[arg-type]
                path.reverse()
                return path + [start]
            if w not in parent:
                parent[w] = u
                queue.append(w)
    return [start, start]


def module_name_for(rel: str, package_roots: Sequence[str]) -> Optional[Tuple[str, bool]]:
    """Map a relative .py path to a dotted module name using the first matching
    package root. Returns (name, is_package) or None."""
    if not rel.endswith((".py", ".pyw", ".pyi")):
        return None
    stem = rel.rsplit(".", 1)[0]
    for root in package_roots:
        r = root.strip().strip("/").replace("\\", "/")
        if r in ("", "."):
            inner = stem
        elif stem.startswith(r + "/"):
            inner = stem[len(r) + 1:]
        else:
            continue
        parts = inner.split("/")
        is_package = parts[-1] == "__init__"
        if is_package:
            parts = parts[:-1]
        if not parts:
            return None
        return ".".join(parts), is_package
    return None


def _layer_of(module: str, layers: Sequence[str]) -> Optional[int]:
    parts = module.split(".")
    for idx, layer in enumerate(layers):
        if _module_matches(module, parts, layer):
            return idx
    return None


def _module_matches(module: str, parts: Sequence[str], pattern: str) -> bool:
    if module == pattern or module.startswith(pattern + ".") or pattern in parts:
        return True
    if any(ch in pattern for ch in "*?[") and fnmatch.fnmatch(module, pattern):
        return True
    return False


class ModuleGraph:
    def __init__(self, records: Sequence[ModuleRecord], config: Config, emit) -> None:
        self.records = {r.name: r for r in sorted(records, key=lambda r: r.rel) if r.name}
        self.config = config
        self.emit = emit
        self.known: Set[str] = set(self.records)
        self.layer_names: Dict[str, str] = {n: (r.layer_name or n) for n, r in self.records.items()}
        self.hard: Dict[str, Set[str]] = collections.defaultdict(set)
        self.all: Dict[str, Set[str]] = collections.defaultdict(set)
        self.edge_info: Dict[Tuple[str, str], ImportRecord] = {}

    def _resolve_candidates(self, rec: ModuleRecord, imp: ImportRecord) -> List[str]:
        targets: List[str] = []
        if imp.level < 0:  # pre-resolved edge (JS/TS graph)
            return [imp.module] if imp.module in self.known else []
        if imp.level == 0 and not imp.names:
            # import a.b.c -> longest known prefix
            parts = (imp.module or "").split(".")
            for i in range(len(parts), 0, -1):
                cand = ".".join(parts[:i])
                if cand in self.known:
                    targets.append(cand)
                    break
            return targets
        if imp.level > 0:
            pkg_parts = rec.name.split(".") if rec.is_package else rec.name.split(".")[:-1]
            up = imp.level - 1
            if up > len(pkg_parts):
                return targets
            base_parts = pkg_parts[:len(pkg_parts) - up] if up else pkg_parts
            base = ".".join(base_parts)
            if imp.module:
                base = (base + "." + imp.module) if base else imp.module
        else:
            base = imp.module or ""
        for name in imp.names:
            if name == "*":
                if base in self.known:
                    targets.append(base)
                continue
            cand = (base + "." + name) if base else name
            if cand in self.known:
                targets.append(cand)
            elif base in self.known:
                targets.append(base)
            else:
                # from a.b.c import x where only a.b is local: longest prefix
                parts = base.split(".")
                for i in range(len(parts) - 1, 0, -1):
                    pre = ".".join(parts[:i])
                    if pre in self.known:
                        targets.append(pre)
                        break
        return targets

    def build(self) -> None:
        for name, rec in self.records.items():
            for imp in rec.imports:
                for target in self._resolve_candidates(rec, imp):
                    self.all[name].add(target)
                    if not imp.soft:
                        self.hard[name].add(target)
                    key = (name, target)
                    if key not in self.edge_info or (self.edge_info[key].soft and not imp.soft):
                        self.edge_info[key] = imp

    def _report_cycle(self, comp: List[str], edges: Dict[str, Set[str]], severity: str, soft_only: bool) -> None:
        path = find_cycle_path(comp, edges)
        first = path[0]
        imp = self.edge_info.get((first, path[1]))
        rec = self.records[first]
        line = imp.lineno if imp else 1
        col = imp.col if imp else 1
        snippet = imp.snippet if imp else ""
        kind = "Circular import (only via soft imports)" if soft_only else "Circular import"
        if len(comp) == 1:
            kind = "Self-import"
        message = "%s: %s" % (kind, " -> ".join(path))
        if len(comp) > len(path) - 1:
            message += " (component of %d modules)" % len(comp)
        self.emit(Finding("RS-ARCH-001", severity, "high", rec.rel, line, col, message, snippet,
                          RULES["RS-ARCH-001"].remediation))

    def report(self) -> None:
        self.build()
        hard_cyclic: Set[str] = set()
        hard_comps = tarjan_scc(self.known, self.hard)
        for comp in hard_comps:
            if len(comp) > 1 or comp[0] in self.hard.get(comp[0], ()):
                hard_cyclic.update(comp)
                self._report_cycle(comp, self.hard, RULES["RS-ARCH-001"].severity, False)
        if any(self.all[k] - self.hard.get(k, set()) for k in list(self.all)):
            for comp in tarjan_scc(self.known, self.all):
                if len(comp) > 1 or comp[0] in self.all.get(comp[0], ()):
                    if any(m in hard_cyclic for m in comp):
                        continue
                    self._report_cycle(comp, self.all, "low", True)
        self._report_layers()

    def _report_layers(self) -> None:
        layers = self.config.layers
        forbidden = self.config.forbidden_imports
        if not layers and not forbidden:
            return
        for src in sorted(self.all):
            lsrc = self.layer_names[src]
            src_parts = lsrc.split(".")
            src_layer = _layer_of(lsrc, layers) if layers else None
            for dst in sorted(self.all[src]):
                if dst == src:
                    continue
                imp = self.edge_info[(src, dst)]
                rec = self.records[src]
                ldst = self.layer_names[dst]
                dst_parts = ldst.split(".")
                if src_layer is not None:
                    dst_layer = _layer_of(ldst, layers)
                    if dst_layer is not None and dst_layer < src_layer:
                        self.emit(Finding("RS-ARCH-002", RULES["RS-ARCH-002"].severity, "high", rec.rel, imp.lineno,
                                          imp.col, "Layer '%s' must not import layer '%s' (%s -> %s)"
                                          % (layers[src_layer], layers[dst_layer], src, dst), imp.snippet,
                                          RULES["RS-ARCH-002"].remediation))
                for rule in forbidden:
                    if _module_matches(lsrc, src_parts, rule["from"]) and _module_matches(ldst, dst_parts, rule["to"]):
                        self.emit(Finding("RS-ARCH-002", RULES["RS-ARCH-002"].severity, "high", rec.rel, imp.lineno,
                                          imp.col, "Forbidden import: '%s' must not import '%s' (%s -> %s)"
                                          % (rule["from"], rule["to"], src, dst), imp.snippet,
                                          RULES["RS-ARCH-002"].remediation))


# --------------------------------------------------------------------------
# Scanner orchestration
# --------------------------------------------------------------------------
@dataclasses.dataclass
class ScanResult:
    findings: List[Finding]
    scanned_files: int
    warnings: List[str]
    suppressed: int = 0
    # leading-whitespace width of each finding's source line, for the terminal caret
    indents: Dict[Tuple[str, int], int] = dataclasses.field(default_factory=dict)


def expand_rule_selection(spec: Optional[str]) -> Optional[Set[str]]:
    """Expand a comma-separated list of rule IDs / globs. Raises ConfigError
    for an ID or glob that matches nothing."""
    if spec is None:
        return None
    selected: Set[str] = set()
    for raw in spec.split(","):
        item = raw.strip().upper()
        if not item:
            continue
        matched = {rid for rid in RULES if fnmatch.fnmatchcase(rid, item)}
        if not matched:
            raise ConfigError("unknown rule id or pattern: %s" % raw.strip())
        selected |= matched
    return selected


class Scanner:
    def __init__(self, root: str, config: Config, rules: Optional[Set[str]] = None,
                 ignore_rules: Optional[Set[str]] = None) -> None:
        self.root = root
        self.config = config
        self.enabled: Set[str] = set(rules) if rules is not None else set(RULES)
        if ignore_rules:
            self.enabled -= set(ignore_rules)
        self.findings: List[Finding] = []
        self.warnings: List[str] = []
        self.suppressed = 0
        self.scanned = 0
        self.modules: List[ModuleRecord] = []
        self.js_modules: List[JsModule] = []
        self.js_aliases: List[JsPathAliases] = []
        self.js_known: Set[str] = set()
        self._directives: Dict[str, Dict[int, Set[str]]] = {}
        self._seen: Set[Tuple[str, str, int, int]] = set()
        self._current: Optional[SourceFile] = None
        self.indents: Dict[Tuple[str, int], int] = {}

    def _emit(self, finding: Finding) -> None:
        if finding.rule_id not in self.enabled:
            return
        key_loc = (finding.file, finding.line)
        if key_loc not in self.indents:
            if self._current is not None and self._current.rel == finding.file:
                raw = self._current.raw_line(finding.line)
                self.indents[key_loc] = len(raw) - len(raw.lstrip())
            else:
                self.indents[key_loc] = max(0, finding.col - 1)
        override = self.config.severity_overrides.get(finding.rule_id)
        if override:
            finding.severity = override
        directives = self._directives.get(finding.file)
        if directives:
            for ln in (finding.line, finding.line - 1):
                ids = directives.get(ln)
                if ids and ("*" in ids or finding.rule_id in ids):
                    self.suppressed += 1
                    return
        key = (finding.rule_id, finding.file, finding.line, finding.col)
        if key in self._seen:  # never report the same (rule, file, line, col) twice
            return
        self._seen.add(key)
        self.findings.append(finding)

    def _sys_finding(self, rel: str, line: int, message: str) -> None:
        self._emit(Finding("RS-SYS-001", RULES["RS-SYS-001"].severity, "high", rel, line, 1, message, "",
                           RULES["RS-SYS-001"].remediation))

    def run(self) -> ScanResult:
        entries = discover_files(self.root, self.config, self.warnings)
        for entry in entries:
            try:
                self._scan_entry(entry)
            except Exception as exc:  # never crash: record and continue
                self._sys_finding(entry.rel, 1, "Internal error while scanning: %s: %s" % (type(exc).__name__, exc))
        self._current = None
        if self.modules and ("RS-ARCH-001" in self.enabled or "RS-ARCH-002" in self.enabled):
            ModuleGraph(self.modules, self.config, self._emit).report()
        if self.js_modules and ("RS-ARCH-001" in self.enabled or "RS-ARCH-002" in self.enabled):
            self._report_js_graph()
        self.findings.sort(key=Finding.sort_key)
        return ScanResult(self.findings, self.scanned, self.warnings, self.suppressed, self.indents)

    def _scan_entry(self, entry: FileEntry) -> None:
        ext = os.path.splitext(entry.rel)[1].lower()
        if ext in BINARY_EXTS:
            return
        try:
            with open(entry.path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            self._sys_finding(entry.rel, 1, "File could not be read: %s" % (exc.strerror or exc))
            return
        if b"\x00" in data[:8192]:
            return
        decode_error = None
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            decode_error = exc
            text = data.decode("utf-8", errors="replace")
        first_line = text.split("\n", 1)[0] if text else ""
        lang = detect_language(entry.rel, first_line)
        sf = SourceFile(entry.rel, entry.path, text, lang)
        self._directives[entry.rel] = sf.directives
        self._current = sf
        self.scanned += 1
        if decode_error is not None:
            self._sys_finding(entry.rel, 1, "File is not valid UTF-8 (%s); scanned with replacement characters"
                              % decode_error.reason)
        base_name = os.path.basename(entry.rel).lower()
        if base_name in ("tsconfig.json", "jsconfig.json"):
            aliases = load_js_path_aliases(entry.rel, text, self.warnings)
            if aliases is not None:
                self.js_aliases.append(aliases)
        if lang == "js":
            self.js_known.add(entry.rel)
        entropy_enabled = ("RS-SEC-002" in self.enabled and not is_lockfile(entry.rel)
                           and not is_minified(entry.rel, sf.lines))
        if "RS-SEC-001" in self.enabled or entropy_enabled:
            scan_secrets(sf, self.config, self._emit, entropy_enabled)
        if lang == "python":
            try:
                tree = ast.parse(text, filename=entry.rel)
            except SyntaxError as exc:
                self._sys_finding(entry.rel, exc.lineno or 1, "Python syntax error: %s" % (exc.msg or "invalid syntax"))
                return
            except (ValueError, RecursionError, MemoryError) as exc:
                self._sys_finding(entry.rel, 1, "Python file could not be parsed: %s" % exc)
                return
            named = module_name_for(entry.rel, self.config.package_roots)
            module_name, is_package = named if named else (None, False)
            analyzer = PythonAnalyzer(sf, tree, self.config, self._emit, module_name, is_package)
            record = analyzer.run()
            if record.name:
                self.modules.append(record)
        elif lang == "js":
            self._scan_js(sf)
        elif lang in ("c", "shell"):
            if "RS-SEC-003" in self.enabled or "RS-SEC-004" in self.enabled:
                scan_pattern_sinks(sf, self._emit)

    def _scan_js(self, sf: SourceFile) -> None:
        """JS/TS: masked-text structural rules, sinks and (later) imports.
        Declaration files and minified/bundled files only get secret scanning."""
        if js_is_declaration_file(sf.rel) or is_minified(sf.rel, sf.lines):
            return
        try:
            analyzer = JsAnalyzer(sf, self.config, self._emit, self.enabled)
        except (RecursionError, MemoryError, ValueError, IndexError) as exc:
            self._sys_finding(sf.rel, 1, "JS/TS file could not be tokenized: %s: %s" % (type(exc).__name__, exc))
            return
        analyzer.run_quality()
        if "RS-SEC-003" in self.enabled or "RS-SEC-004" in self.enabled:
            sink_emit = self._emit
            if analyzer.test_file:  # sinks in tests are usually fixtures: one level lower, like RS-SEC-006
                def sink_emit(f: Finding) -> None:
                    f.severity = _downgrade(f.severity)
                    self._emit(f)
            scan_pattern_sinks(sf, sink_emit, analyzer.masked)
        if "RS-SEC-006" in self.enabled:
            analyzer.run_security()
        if "RS-ARCH-001" in self.enabled or "RS-ARCH-002" in self.enabled:
            self.js_modules.append(JsModule(sf.rel, analyzer.collect_imports()))

    def _report_js_graph(self) -> None:
        """Build the JS/TS module graph from pre-resolved edges and reuse the
        Python cycle / layer reporting."""
        resolver = JsModuleResolver(self.js_known, self.js_aliases)
        roots = self.config.package_roots
        name_of = {rel: js_module_name(rel) for rel in self.js_known}
        records: List[ModuleRecord] = []
        with_record: Set[str] = set()
        for jm in self.js_modules:
            name = name_of[jm.rel]
            rec = ModuleRecord(name, jm.rel, False, [], js_layer_name(name, roots))
            for imp in jm.imports:
                target = resolver.resolve(jm.rel, imp.specifier)
                if target is None or target not in name_of:
                    continue
                rec.imports.append(ImportRecord(name_of[target], [], -1, imp.lineno, imp.col, imp.soft, imp.snippet))
            records.append(rec)
            with_record.add(jm.rel)
        for rel in sorted(self.js_known - with_record):
            records.append(ModuleRecord(name_of[rel], rel, False, [], js_layer_name(name_of[rel], roots)))
        ModuleGraph(records, self.config, self._emit).report()


def scan(root: str, config: Optional[Config] = None, rules: Optional[Set[str]] = None,
         ignore_rules: Optional[Set[str]] = None) -> ScanResult:
    return Scanner(root, config or Config(), rules, ignore_rules).run()


# --------------------------------------------------------------------------
# Git history scan (RS-SEC-005)
# --------------------------------------------------------------------------
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def scan_history(scanner: "Scanner", max_commits: int = 500) -> int:
    """Scan lines ADDED by past commits for known secret patterns. Reports only secrets that no longer appear in
    the working tree (those still present are already RS-SEC-001). Returns the number of commits examined.
    Requires the `git` executable; failures are reported as warnings, never crashes."""
    root = scanner.root if os.path.isdir(scanner.root) else (os.path.dirname(scanner.root) or ".")
    try:
        probe = subprocess.run(["git", "-C", root, "rev-parse", "--is-inside-work-tree"], capture_output=True,
                               text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        scanner.warnings.append("--history: git is not available (%s)" % exc)
        return 0
    if probe.returncode != 0:
        scanner.warnings.append("--history: %s is not inside a git work tree" % root)
        return 0
    top = subprocess.run(["git", "-C", root, "rev-parse", "--show-toplevel"], capture_output=True, text=True).stdout.strip()
    prefix = subprocess.run(["git", "-C", root, "rev-parse", "--show-prefix"], capture_output=True, text=True).stdout.strip()
    if os.path.isfile(os.path.join(top, ".git", "shallow")):
        scanner.warnings.append("--history: this is a shallow clone, so only the available commits are scanned")
    cmd = ["git", "-C", root, "log", "--all", "--no-color", "--no-ext-diff", "--unified=0", "-p", "-n", str(max_commits),
           "--format=@@COMMIT\x1f%H\x1f%an\x1f%aI"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding="utf-8", errors="replace")
    except OSError as exc:
        scanner.warnings.append("--history: cannot run git (%s)" % exc)
        return 0
    cfg = scanner.config
    seen: Set[Tuple[str, str]] = set()
    current_cache: Dict[str, Set[str]] = {}
    commits = 0
    commit: Tuple[str, str, str] = ("", "", "")
    path: Optional[str] = None
    added: List[Tuple[int, str]] = []

    def current_lines(rel: str) -> Set[str]:
        if rel not in current_cache:
            try:
                with open(os.path.join(top, rel), "r", encoding="utf-8", errors="replace") as fh:
                    current_cache[rel] = {ln.strip() for ln in fh}
            except OSError:
                current_cache[rel] = set()
        return current_cache[rel]

    def ignored(rel: str) -> bool:
        parts = rel.split("/")
        if any(part in cfg.ignore_dirs for part in parts[:-1]):
            return True
        return any(fnmatch.fnmatchcase(parts[-1], g) or fnmatch.fnmatchcase(rel, g) for g in cfg.ignore_globs)

    def flush() -> None:
        nonlocal added
        if path is None or not added or not commit[0]:
            added = []
            return
        rel = path[len(prefix):] if prefix and path.startswith(prefix) else path
        if prefix and not path.startswith(prefix) or ignored(path) or is_lockfile(rel):
            added = []
            return
        sf = SourceFile(path, "", "\n".join(text for _, text in added), detect_language(path, added[0][1]))
        numbers = [n for n, _ in added]
        now = current_lines(path)

        def emit(f: Finding) -> None:
            if f.rule_id != "RS-SEC-001" or not (1 <= f.line <= len(numbers)):
                return
            if sf.raw_line(f.line).strip() in now:
                return  # still in the working tree: reported by the normal scan
            key = (path, f.snippet)
            if key in seen:
                return
            seen.add(key)
            sha, author, date = commit
            msg = "%s -- added in commit %s (%s, %s) and since removed" % (f.message, sha[:8], date[:10], author)
            scanner._emit(Finding("RS-SEC-005", "critical" if f.severity == "critical" else "high", f.confidence,
                                  path, numbers[f.line - 1], f.col, msg, f.snippet, RULES["RS-SEC-005"].remediation))

        scan_secrets(sf, cfg, emit, False)
        added = []

    assert proc.stdout is not None
    try:
        lineno = 0
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            if line.startswith("@@COMMIT\x1f"):
                flush()
                path = None
                parts = line.split("\x1f")
                commit = (parts[1], parts[2], parts[3]) if len(parts) >= 4 else ("", "", "")
                commits += 1
            elif line.startswith("+++ "):
                flush()
                path = line[6:] if line.startswith("+++ b/") else None
            elif line.startswith("--- "):
                continue
            elif line.startswith("@@"):
                flush()
                m = _HUNK_RE.match(line)
                lineno = int(m.group(1)) if m else 0
            elif line.startswith("+") and path is not None:
                if len(line) < 2000:
                    added.append((lineno, line[1:]))
                lineno += 1
        flush()
    finally:
        proc.stdout.close()
        proc.wait()
    return commits


# --------------------------------------------------------------------------
# Baseline
# --------------------------------------------------------------------------
def load_baseline(path: str) -> Set[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise ConfigError("cannot read baseline %s: %s" % (path, exc))
    except ValueError as exc:
        raise ConfigError("invalid JSON in baseline %s: %s" % (path, exc))
    fps = data.get("fingerprints") if isinstance(data, dict) else None
    if not isinstance(fps, list) or not all(isinstance(f, str) for f in fps):
        raise ConfigError("baseline %s must contain a 'fingerprints' list of strings" % path)
    return set(fps)


def write_baseline(path: str, findings: Sequence[Finding]) -> int:
    fps = sorted({f.fingerprint() for f in findings})
    payload = collections.OrderedDict((("tool", TOOL_NAME), ("version", __version__), ("fingerprints", fps)))
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
    except OSError as exc:
        raise ConfigError("cannot write baseline %s: %s" % (path, exc))
    return len(fps)


# --------------------------------------------------------------------------
# Output rendering
# --------------------------------------------------------------------------
SEVERITY_BADGE = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MED]", "low": "[LOW]"}
SEVERITY_COLOR = {"critical": "1;35", "high": "1;31", "medium": "33", "low": "36"}


def _enable_windows_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes  # noqa: WPS433 (stdlib)
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return bool(os.environ.get("WT_SESSION") or os.environ.get("ANSICON") or os.environ.get("TERM"))


def color_enabled(no_color_flag: bool, stream) -> bool:
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        if not stream.isatty():
            return False
    except Exception:
        return False
    return _enable_windows_ansi()


def summarize(findings: Sequence[Finding], scanned_files: int, threshold: str) -> "collections.OrderedDict[str, object]":
    by_sev = collections.OrderedDict((s, 0) for s in reversed(SEVERITIES))
    by_rule: Dict[str, int] = collections.OrderedDict()
    for f in findings:
        by_sev[f.severity] += 1
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    by_rule_sorted = collections.OrderedDict(sorted(by_rule.items()))
    failed = any(SEVERITY_RANK[f.severity] >= SEVERITY_RANK[threshold] for f in findings)
    return collections.OrderedDict((
        ("scanned_files", scanned_files),
        ("total", len(findings)),
        ("by_severity", by_sev),
        ("by_rule", by_rule_sorted),
        ("fail_on_severity", threshold),
        ("failed", failed),
    ))


def render_json(findings: Sequence[Finding], scanned_files: int, threshold: str) -> str:
    summary = summarize(findings, scanned_files, threshold)
    payload = collections.OrderedDict((
        ("tool", TOOL_NAME),
        ("version", __version__),
        ("scanned_files", scanned_files),
        ("summary", summary),
        ("findings", [f.to_dict() for f in findings]),
    ))
    return json.dumps(payload, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


def render_markdown(findings: Sequence[Finding], scanned_files: int, threshold: str) -> str:
    summary = summarize(findings, scanned_files, threshold)
    out: List[str] = ["## repo_sentry report", ""]
    out.append("**Scanned files:** %d · **Findings:** %d · **Threshold:** %s · **Result:** %s" % (
        scanned_files, len(findings), threshold, "FAIL" if summary["failed"] else "PASS"))
    out.append("")
    out.append("| Severity | Count |")
    out.append("|---|---:|")
    for sev, count in summary["by_severity"].items():  # type: ignore[union-attr]
        out.append("| %s | %d |" % (sev.capitalize(), count))
    if summary["by_rule"]:
        out.append("")
        out.append("| Rule | Title | Count |")
        out.append("|---|---|---:|")
        for rid, count in summary["by_rule"].items():  # type: ignore[union-attr]
            out.append("| %s | %s | %d |" % (rid, RULES[rid].title if rid in RULES else "", count))
    for sev in reversed(SEVERITIES):
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        out.append("")
        out.append("### %s (%d)" % (sev.capitalize(), len(group)))
        out.append("")
        for f in group:
            snippet = f.snippet.replace("`", "ˋ")
            out.append("- **%s** `%s:%d:%d` — %s _(confidence: %s)_" % (f.rule_id, f.file, f.line, f.col, f.message, f.confidence))
            if snippet:
                out.append("  `%s`" % snippet)
            out.append("  _Fix:_ %s" % f.remediation)
    if not findings:
        out.append("")
        out.append("No findings.")
    out.append("")
    return "\n".join(out)


def render_terminal(findings: Sequence[Finding], scanned_files: int, threshold: str, color: bool,
                    indents: Optional[Dict[Tuple[str, int], int]] = None) -> str:
    def paint(text: str, code: str) -> str:
        return "\x1b[%sm%s\x1b[0m" % (code, text) if color else text

    summary = summarize(findings, scanned_files, threshold)
    out: List[str] = []
    out.append(paint("%s %s" % (TOOL_NAME, __version__), "1") + "  scanned %d file(s)" % scanned_files)
    out.append("")
    for f in findings:
        badge = paint(SEVERITY_BADGE[f.severity], SEVERITY_COLOR[f.severity])
        loc = paint("%s:%d:%d" % (f.file, f.line, f.col), "4")
        out.append("%s %s  %s  (confidence: %s)" % (badge, paint(f.rule_id, "1"), loc, f.confidence))
        out.append("    %s" % f.message)
        if f.snippet:
            lead = indents.get((f.file, f.line), 0) if indents else 0
            caret = max(0, f.col - 1 - lead)
            caret = min(caret, max(0, len(f.snippet) - 1))
            out.append("      %s" % paint(f.snippet, "2"))
            out.append("      %s%s" % (" " * caret, paint("^", SEVERITY_COLOR[f.severity])))
        out.append("    %s %s" % (paint("fix:", "32"), f.remediation))
        out.append("")
    out.append(paint("Summary", "1"))
    out.append("  %-10s %5s" % ("severity", "count"))
    for sev, count in summary["by_severity"].items():  # type: ignore[union-attr]
        out.append("  %-10s %5d" % (sev, count))
    if summary["by_rule"]:
        out.append("")
        out.append("  %-13s %5s  %s" % ("rule", "count", "title"))
        for rid, count in summary["by_rule"].items():  # type: ignore[union-attr]
            out.append("  %-13s %5d  %s" % (rid, count, RULES[rid].title if rid in RULES else ""))
    out.append("")
    verdict = "FAIL" if summary["failed"] else "PASS"
    out.append("  total: %d finding(s); threshold: %s; result: %s" % (
        len(findings), threshold, paint(verdict, "1;31" if summary["failed"] else "1;32")))
    return "\n".join(out) + "\n"


def render_rule_catalog() -> str:
    out = ["%s %s - rule catalog" % (TOOL_NAME, __version__), ""]
    out.append("%-13s %-9s %-13s %s" % ("ID", "SEVERITY", "CATEGORY", "TITLE"))
    for rule in RULES.values():
        out.append("%-13s %-9s %-13s %s" % (rule.id, rule.severity, rule.category, rule.title))
        out.append("    languages: %s" % rule.languages)
        out.append("    %s" % rule.description)
    out.append("")
    out.append("Python files are analysed with the `ast` module. JavaScript/TypeScript files are lexically")
    out.append("masked (comments, strings, template text, regex literals and JSX text blanked) and analysed")
    out.append("approximately: brace-matched function discovery feeds RS-QUAL-001/002/004, a relative-import")
    out.append("graph with tsconfig/jsconfig path aliases feeds RS-ARCH-001/002, and RS-SEC-003/004/006 are")
    out.append("pattern-based on the masked code. JS/TS findings carry confidence low or medium. C/C++ and")
    out.append("shell files are scanned with regular-expression patterns only (RS-SEC-003, RS-SEC-004 and")
    out.append("the secret rules); those findings also carry confidence low or medium.")
    out.append("Suppress a finding with a comment `reposentry: ignore RS-XXX-NNN` on the same or the")
    out.append("preceding line, or record known findings with --write-baseline / --baseline.")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise ConfigError("usage error: %s" % message)


def build_arg_parser() -> argparse.ArgumentParser:
    p = _ArgumentParser(prog="repo_sentry", description="Static analysis and architecture audit for repositories "
                        "(standard library only).")
    p.add_argument("path", nargs="?", default=None, help="directory or file to scan (default: .)")
    p.add_argument("--path", dest="path_opt", default=None, help="alias for the positional path")
    p.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal")
    p.add_argument("--fail-on-severity", choices=SEVERITIES, default="high",
                   help="exit 1 when a finding at or above this severity exists (default: high)")
    p.add_argument("--rules", default=None, help="comma-separated rule IDs or globs to enable (e.g. RS-SEC-*)")
    p.add_argument("--ignore-rules", default=None, help="comma-separated rule IDs or globs to disable")
    p.add_argument("--list-rules", action="store_true", help="print the rule catalog and exit")
    p.add_argument("--config", default=None, help="config file (default: <path>/.reposentry.json if present)")
    p.add_argument("--baseline", default=None, help="suppress findings whose fingerprints are in this baseline")
    p.add_argument("--write-baseline", default=None, metavar="PATH", help="write a baseline of the current findings")
    p.add_argument("--self-test", action="store_true", help="run the embedded test suite and exit")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    p.add_argument("--max-file-kb", type=int, default=1024, help="skip files larger than this (default 1024)")
    p.add_argument("--history", action="store_true",
                   help="also scan lines added by past commits for secrets that were later removed (RS-SEC-005; needs git)")
    p.add_argument("--history-max", type=int, default=500, metavar="N", help="max commits for --history (default 500)")
    p.add_argument("--version", action="store_true", help="print the version and exit")
    return p


def run_self_tests(verbosity: int = 1) -> int:
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(stream=sys.stdout, verbosity=verbosity)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point. Returns the exit code instead of exiting."""
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_arg_parser()
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:  # --help
            return int(exc.code or 0)
        if args.version:
            print("%s %s" % (TOOL_NAME, __version__))
            return 0
        if args.list_rules:
            sys.stdout.write(render_rule_catalog())
            return 0
        if args.self_test:
            return run_self_tests(verbosity=2 if os.environ.get("REPO_SENTRY_VERBOSE") else 1)
        if args.path is not None and args.path_opt is not None and args.path != args.path_opt:
            raise ConfigError("usage error: conflicting positional path and --path")
        path = args.path if args.path is not None else (args.path_opt if args.path_opt is not None else ".")
        if not os.path.exists(path):
            raise ConfigError("path does not exist: %s" % path)
        if args.max_file_kb < 0:
            raise ConfigError("--max-file-kb must be >= 0")
        warnings: List[str] = []
        config_path = args.config
        if config_path is None:
            candidate = os.path.join(path if os.path.isdir(path) else os.path.dirname(path) or ".", ".reposentry.json")
            if os.path.isfile(candidate):
                config_path = candidate
        if config_path is not None:
            config, warnings = load_config(config_path)
        else:
            config = Config()
        config.max_file_bytes = args.max_file_kb * 1024
        rules = expand_rule_selection(args.rules)
        ignore_rules = expand_rule_selection(args.ignore_rules)
        baseline = load_baseline(args.baseline) if args.baseline else set()
        for w in warnings:
            sys.stderr.write("warning: %s\n" % w)
        scanner = Scanner(path, config, rules, ignore_rules)
        result = scanner.run()
        if args.history:
            if args.history_max < 1:
                raise ConfigError("--history-max must be >= 1")
            scan_history(scanner, args.history_max)
            scanner.findings.sort(key=lambda f: f.sort_key())
        for w in result.warnings:
            sys.stderr.write("warning: %s\n" % w)
        all_findings = result.findings
        if args.write_baseline:
            count = write_baseline(args.write_baseline, all_findings)
            sys.stderr.write("baseline written to %s (%d fingerprint(s))\n" % (args.write_baseline, count))
        findings = [f for f in all_findings if f.fingerprint() not in baseline] if baseline else all_findings
        threshold = args.fail_on_severity
        if args.format == "json":
            sys.stdout.write(render_json(findings, result.scanned_files, threshold))
        elif args.format == "markdown":
            sys.stdout.write(render_markdown(findings, result.scanned_files, threshold))
        else:
            color = color_enabled(args.no_color, sys.stdout)
            sys.stdout.write(render_terminal(findings, result.scanned_files, threshold, color, result.indents))
        failed = any(SEVERITY_RANK[f.severity] >= SEVERITY_RANK[threshold] for f in findings)
        return 1 if failed else 0
    except ConfigError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("error: interrupted\n")
        return 2
    except Exception as exc:  # defensive: never leak a traceback as a crash
        sys.stderr.write("error: %s: %s\n" % (type(exc).__name__, exc))
        return 2


# --------------------------------------------------------------------------
# Embedded test suite (python repo_sentry.py --self-test)
# --------------------------------------------------------------------------
class _ProjectMixin:
    def make_project(self, files: Dict[str, str]) -> str:
        tmp = tempfile.TemporaryDirectory(prefix="repo_sentry_test_")
        self.addCleanup(tmp.cleanup)  # type: ignore[attr-defined]
        for rel, content in files.items():
            full = os.path.join(tmp.name, *rel.split("/"))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            mode = "wb" if isinstance(content, bytes) else "w"
            with open(full, mode, **({} if mode == "wb" else {"encoding": "utf-8"})) as fh:
                fh.write(content)
        return tmp.name

    def scan_files(self, files: Dict[str, str], config: Optional[Dict[str, object]] = None) -> List[Finding]:
        root = self.make_project(files)
        cfg, _ = config_from_dict(config or {})
        return scan(root, cfg).findings

    @staticmethod
    def by_rule(findings: Sequence[Finding], rule_id: str) -> List[Finding]:
        return [f for f in findings if f.rule_id == rule_id]

    @staticmethod
    def run_cli(argv: Sequence[str]) -> Tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()


class TestCycleDetector(_ProjectMixin, unittest.TestCase):
    def test_three_module_cycle_reported_once(self):
        findings = self.scan_files({"a.py": "import b\n", "b.py": "import c\n", "c.py": "import a\n"})
        cycles = self.by_rule(findings, "RS-ARCH-001")
        self.assertEqual(len(cycles), 1)
        self.assertEqual(cycles[0].severity, "high")
        self.assertIn("a -> b -> c -> a", cycles[0].message)

    def test_acyclic_diamond_reports_nothing(self):
        findings = self.scan_files({"top.py": "import left\nimport right\n", "left.py": "import bottom\n",
                                    "right.py": "import bottom\n", "bottom.py": "x = 1\n"})
        self.assertEqual(self.by_rule(findings, "RS-ARCH-001"), [])

    def test_self_import_reported(self):
        findings = self.scan_files({"solo.py": "import solo\n"})
        cycles = self.by_rule(findings, "RS-ARCH-001")
        self.assertEqual(len(cycles), 1)
        self.assertIn("Self-import", cycles[0].message)

    def test_relative_imports_resolve(self):
        findings = self.scan_files({"pkg/__init__.py": "", "pkg/a.py": "from . import b\n",
                                    "pkg/b.py": "from .a import thing\n"})
        cycles = self.by_rule(findings, "RS-ARCH-001")
        self.assertEqual(len(cycles), 1)
        self.assertIn("pkg.a -> pkg.b -> pkg.a", cycles[0].message)

    def test_src_layout_and_parent_relative_import(self):
        findings = self.scan_files({"src/app/__init__.py": "", "src/app/core/__init__.py": "",
                                    "src/app/core/x.py": "from ..util import y\n",
                                    "src/app/util.py": "from app.core.x import z\n"})
        cycles = self.by_rule(findings, "RS-ARCH-001")
        self.assertEqual(len(cycles), 1)
        self.assertIn("app.core.x", cycles[0].message)
        self.assertIn("app.util", cycles[0].message)

    def test_type_checking_only_cycle_is_low(self):
        findings = self.scan_files({
            "a.py": "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from b import B\n",
            "b.py": "from a import A\n"})
        cycles = self.by_rule(findings, "RS-ARCH-001")
        self.assertEqual(len(cycles), 1)
        self.assertEqual(cycles[0].severity, "low")
        self.assertIn("soft", cycles[0].message)

    def test_function_level_import_cycle_is_low(self):
        findings = self.scan_files({"a.py": "def f():\n    import b\n", "b.py": "import a\n"})
        cycles = self.by_rule(findings, "RS-ARCH-001")
        self.assertEqual(len(cycles), 1)
        self.assertEqual(cycles[0].severity, "low")

    def test_stdlib_and_third_party_imports_dropped(self):
        findings = self.scan_files({"a.py": "import os, json\nimport requests\nfrom typing import List\n"})
        self.assertEqual(self.by_rule(findings, "RS-ARCH-001"), [])

    def test_long_chain_graph_does_not_recurse(self):
        n = 5000
        edges: Dict[str, Set[str]] = {"m%d" % i: {"m%d" % (i + 1)} for i in range(n - 1)}
        edges["m%d" % (n - 1)] = {"m0"}
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(100)
        try:
            comps = tarjan_scc(edges.keys(), edges)
            big = [c for c in comps if len(c) > 1]
            self.assertEqual(len(big), 1)
            self.assertEqual(len(big[0]), n)
            path = find_cycle_path(big[0], edges)
            self.assertEqual(path[0], path[-1])
            self.assertEqual(len(path), n + 1)
            chain = {"m%d" % i: {"m%d" % (i + 1)} for i in range(n - 1)}
            self.assertTrue(all(len(c) == 1 for c in tarjan_scc(chain.keys(), chain)))
        finally:
            sys.setrecursionlimit(old)

    def test_long_chain_on_disk(self):
        n = 5000
        files = {"m%d.py" % i: "import m%d\n" % (i + 1) for i in range(n - 1)}
        files["m%d.py" % (n - 1)] = "x = 1\n"
        findings = self.scan_files(files)
        self.assertEqual(self.by_rule(findings, "RS-ARCH-001"), [])


class TestLayerRules(_ProjectMixin, unittest.TestCase):
    FILES = {"api/__init__.py": "", "api/routes.py": "from domain import models\n",
             "domain/__init__.py": "", "domain/models.py": "from api import routes\n"}

    def test_domain_importing_api_flagged(self):
        findings = self.scan_files(self.FILES, {"layers": ["api", "service", "domain"]})
        layer = self.by_rule(findings, "RS-ARCH-002")
        self.assertEqual(len(layer), 1)
        self.assertEqual(layer[0].file, "domain/models.py")
        self.assertIn("'domain' must not import layer 'api'", layer[0].message)

    def test_api_importing_domain_not_flagged(self):
        files = {"api/__init__.py": "", "api/routes.py": "from domain import models\n",
                 "domain/__init__.py": "", "domain/models.py": "x = 1\n"}
        findings = self.scan_files(files, {"layers": ["api", "service", "domain"]})
        self.assertEqual(self.by_rule(findings, "RS-ARCH-002"), [])

    def test_forbidden_imports_rule(self):
        findings = self.scan_files(self.FILES, {"forbidden_imports": [{"from": "domain", "to": "api"}]})
        layer = self.by_rule(findings, "RS-ARCH-002")
        self.assertEqual(len(layer), 1)
        self.assertIn("Forbidden import", layer[0].message)
        self.assertEqual(layer[0].file, "domain/models.py")


class TestAsyncRules(_ProjectMixin, unittest.TestCase):
    def test_time_sleep_flagged(self):
        findings = self.scan_files({"a.py": "import time\nasync def f():\n    time.sleep(1)\n"})
        hits = self.by_rule(findings, "RS-ASYNC-001")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].line, 3)
        self.assertIn("time.sleep", hits[0].message)

    def test_aliased_import_resolved(self):
        findings = self.scan_files({"a.py": "import time as t\nasync def f():\n    t.sleep(1)\n",
                                    "b.py": "from time import sleep\nasync def g():\n    sleep(2)\n",
                                    "c.py": "import requests as r\nasync def h():\n    r.get('http://x')\n"})
        hits = self.by_rule(findings, "RS-ASYNC-001")
        self.assertEqual(sorted(f.file for f in hits), ["a.py", "b.py", "c.py"])

    def test_to_thread_and_run_in_executor_not_flagged(self):
        src = ("import asyncio, time\nasync def f():\n    await asyncio.to_thread(time.sleep, 1)\n"
               "    loop = asyncio.get_running_loop()\n    await loop.run_in_executor(None, time.sleep, 1)\n"
               "    await asyncio.to_thread(lambda: time.sleep(1))\n")
        findings = self.scan_files({"a.py": src})
        self.assertEqual(self.by_rule(findings, "RS-ASYNC-001"), [])

    def test_sync_nested_def_not_flagged(self):
        src = "import time\nasync def f():\n    def inner():\n        time.sleep(1)\n    return inner\n"
        findings = self.scan_files({"a.py": src})
        self.assertEqual(self.by_rule(findings, "RS-ASYNC-001"), [])

    def test_sync_function_not_flagged(self):
        findings = self.scan_files({"a.py": "import time\ndef f():\n    time.sleep(1)\n"})
        self.assertEqual(self.by_rule(findings, "RS-ASYNC-001"), [])

    def test_open_subprocess_input_flagged(self):
        src = ("import subprocess\nasync def f(p):\n    data = open(p).read()\n"
               "    subprocess.run(['ls'])\n    input()\n    return data\n")
        findings = self.scan_files({"a.py": src})
        hits = self.by_rule(findings, "RS-ASYNC-001")
        self.assertEqual(len(hits), 3)

    def test_extra_blocking_calls_config(self):
        findings = self.scan_files({"a.py": "import mylib\nasync def f():\n    mylib.slow()\n"},
                                   {"extra_blocking_calls": ["mylib.slow"]})
        self.assertEqual(len(self.by_rule(findings, "RS-ASYNC-001")), 1)

    def test_discarded_create_task_flagged(self):
        src = "import asyncio\nasync def work(): pass\nasync def f():\n    asyncio.create_task(work())\n"
        findings = self.scan_files({"a.py": src})
        hits = self.by_rule(findings, "RS-ASYNC-002")
        self.assertEqual(len(hits), 1)
        self.assertIn("discarded", hits[0].message)

    def test_unused_task_variable_flagged_but_awaited_not(self):
        src = ("import asyncio\nasync def work(): pass\n"
               "async def f():\n    t = asyncio.create_task(work())\n"
               "async def g():\n    t = asyncio.create_task(work())\n    await t\n"
               "async def h():\n    t = asyncio.ensure_future(work())\n    t.add_done_callback(print)\n"
               "async def i():\n    tasks = [asyncio.create_task(work()) for _ in range(3)]\n    await asyncio.gather(*tasks)\n"
               "async def j():\n    return asyncio.create_task(work())\n"
               "async def k():\n    async with asyncio.TaskGroup() as tg:\n        tg.create_task(work())\n")
        findings = self.scan_files({"a.py": src})
        hits = self.by_rule(findings, "RS-ASYNC-002")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].line, 4)

    def test_shared_state_mutation_without_lock(self):
        src = ("import asyncio\nCACHE = {}\nITEMS = []\nLOCK = asyncio.Lock()\n"
               "async def a(k, v):\n    CACHE[k] = v\n"
               "async def b(v):\n    ITEMS.append(v)\n"
               "async def c(k, v):\n    async with LOCK:\n        CACHE[k] = v\n"
               "async def d(v):\n    ITEMS = []\n    ITEMS.append(v)\n")
        findings = self.scan_files({"a.py": src})
        hits = self.by_rule(findings, "RS-ASYNC-003")
        self.assertEqual(sorted(f.line for f in hits), [6, 8])
        self.assertTrue(all(f.confidence == "low" for f in hits))


class TestResourceRule(_ProjectMixin, unittest.TestCase):
    def test_bare_open_flagged(self):
        findings = self.scan_files({"a.py": "def f(p):\n    f = open(p)\n    return f.read()\n"})
        hits = self.by_rule(findings, "RS-RES-001")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].line, 2)
        self.assertEqual(hits[0].severity, "medium")

    def test_with_open_not_flagged(self):
        findings = self.scan_files({"a.py": "def f(p):\n    with open(p) as fh:\n        return fh.read()\n"})
        self.assertEqual(self.by_rule(findings, "RS-RES-001"), [])

    def test_try_finally_close_not_flagged(self):
        src = "def f(p):\n    fh = open(p)\n    try:\n        return fh.read()\n    finally:\n        fh.close()\n"
        findings = self.scan_files({"a.py": src})
        self.assertEqual(self.by_rule(findings, "RS-RES-001"), [])

    def test_returned_yielded_stored_not_flagged(self):
        src = ("import socket, sqlite3\nclass C:\n    def __init__(self, p):\n        self.fh = open(p)\n"
               "def f(p):\n    return open(p)\n"
               "def g(p):\n    yield open(p)\n"
               "def h(p, bag):\n    bag.append(open(p))\n"
               "def i():\n    import contextlib\n    with contextlib.closing(socket.socket()) as s:\n        return s\n"
               "def j(p):\n    conn = sqlite3.connect(p)\n    with conn:\n        pass\n"
               "def k(p, stack):\n    fh = stack.enter_context(open(p))\n    return fh.read()\n"
               "def m(p):\n    fh = open(p)\n    return fh\n")
        findings = self.scan_files({"a.py": src})
        self.assertEqual(self.by_rule(findings, "RS-RES-001"), [])

    def test_other_resource_constructors(self):
        src = ("import socket, subprocess, zipfile, tempfile\ndef f(p):\n    s = socket.socket()\n"
               "    proc = subprocess.Popen(['ls'])\n    z = zipfile.ZipFile(p)\n    t = tempfile.NamedTemporaryFile()\n"
               "    return 1\n")
        findings = self.scan_files({"a.py": src})
        self.assertEqual(len(self.by_rule(findings, "RS-RES-001")), 4)

    def test_close_outside_finally_is_low(self):
        src = "def f(p):\n    fh = open(p)\n    data = fh.read()\n    fh.close()\n    return data\n"
        findings = self.scan_files({"a.py": src})
        hits = self.by_rule(findings, "RS-RES-001")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "low")


class TestQualityRules(_ProjectMixin, unittest.TestCase):
    @staticmethod
    def complexity_of(src: str) -> int:
        tree = ast.parse(src)
        func = next(n for n in tree.body if isinstance(n, ast.FunctionDef))
        return cyclomatic_complexity(func)

    def test_exact_complexity_samples(self):
        self.assertEqual(self.complexity_of("def f(a):\n    return a\n"), 1)
        self.assertEqual(self.complexity_of(
            "def f(a, b):\n    if a:\n        return 1\n    elif b:\n        return 2\n    return 3\n"), 3)
        sample = ("def f(xs):\n    for x in xs:\n        if x and x > 1 or x < 0:\n            pass\n"
                  "        try:\n            pass\n        except ValueError:\n            pass\n"
                  "    return [y for y in xs if y]\n")
        # 1 + for + if + (and, or) + except + comprehension for + comprehension if = 8
        self.assertEqual(self.complexity_of(sample), 8)

    def test_nested_functions_scored_separately(self):
        src = ("def outer(a):\n    def inner(b):\n        if b:\n            return 1\n        return 2\n"
               "    while a:\n        a -= 1\n    return inner\n")
        self.assertEqual(self.complexity_of(src), 2)

    def test_complexity_threshold_and_high_severity(self):
        branches = "".join("    if x == %d:\n        return %d\n" % (i, i) for i in range(12))
        src = "def f(x):\n%s    return -1\n" % branches
        findings = self.scan_files({"a.py": src}, {"thresholds": {"max_cyclomatic_complexity": 10}})
        hits = self.by_rule(findings, "RS-QUAL-001")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "medium")
        findings = self.scan_files({"a.py": src}, {"thresholds": {"max_cyclomatic_complexity": 5}})
        self.assertEqual(self.by_rule(findings, "RS-QUAL-001")[0].severity, "high")

    def test_deep_nesting_flagged(self):
        src = ("def f(a):\n    if a:\n        for x in a:\n            while x:\n                try:\n"
               "                    if x:\n                        pass\n                except ValueError:\n"
               "                    pass\n")
        findings = self.scan_files({"a.py": src})
        hits = self.by_rule(findings, "RS-QUAL-002")
        self.assertEqual(len(hits), 1)
        self.assertIn("depth 5", hits[0].message)
        shallow = "def f(a):\n    if a:\n        if a:\n            if a:\n                if a:\n                    pass\n"
        self.assertEqual(self.by_rule(self.scan_files({"a.py": shallow}), "RS-QUAL-002"), [])

    def test_elif_does_not_add_nesting(self):
        src = "def f(a):\n    if a == 1:\n        pass\n    elif a == 2:\n        pass\n    elif a == 3:\n        pass\n    elif a == 4:\n        pass\n    elif a == 5:\n        pass\n"
        self.assertEqual(self.by_rule(self.scan_files({"a.py": src}), "RS-QUAL-002"), [])

    def test_bare_except_and_swallowed_exception(self):
        src = ("def f():\n    try:\n        pass\n    except:\n        pass\n"
               "def g():\n    try:\n        pass\n    except Exception:\n        pass\n"
               "def h():\n    try:\n        pass\n    except Exception:\n        ...\n"
               "def i():\n    try:\n        pass\n    except Exception as exc:\n        raise RuntimeError() from exc\n"
               "def j():\n    try:\n        pass\n    except ValueError:\n        pass\n")
        findings = self.scan_files({"a.py": src})
        self.assertEqual(len(self.by_rule(findings, "RS-QUAL-003")), 1)
        self.assertEqual(sorted(f.line for f in self.by_rule(findings, "RS-QUAL-004")), [9, 14])


class TestExampleFilesAndHistory(_ProjectMixin, unittest.TestCase):
    AWS = "AKIA" + "J7Q2M9X4L1P8R6T3"

    def test_known_default_in_example_file_is_skipped(self):
        files = {".env.example": "LAVALINK_PASSWORD=youshallnotpass\n",
                 "lavalink/application.example.yml": "lavalink:\n  server:\n    password: \"youshallnotpass\"\n"}
        self.assertEqual(self.by_rule(self.scan_files(files), "RS-SEC-001"), [])

    def test_known_default_in_real_file_is_flagged_and_labelled(self):
        hits = self.by_rule(self.scan_files({".env": "LAVALINK_PASSWORD=youshallnotpass\n"}), "RS-SEC-001")
        self.assertEqual(len(hits), 1)
        self.assertIn("well-known default", hits[0].message)
        self.assertEqual(hits[0].severity, "high")

    def test_unknown_value_in_example_file_is_low_and_real_token_stays_critical(self):
        files = {".env.example": "API_TOKEN=Zk39dLmQ82xPwv7R\n", "settings.sample.py": "KEY = '%s'\n" % self.AWS}
        hits = {f.file: f for f in self.by_rule(self.scan_files(files), "RS-SEC-001")}
        self.assertEqual(hits[".env.example"].severity, "low")
        self.assertEqual(hits["settings.sample.py"].severity, "critical")

    def test_is_example_file(self):
        for name in (".env.example", "a/b/application.example.yml", "config.sample.json", "x.env.template", "settings.dist"):
            self.assertTrue(is_example_file(name), name)
        for name in (".env", "examples.py", "app.yml", "sampler.py"):
            self.assertFalse(is_example_file(name), name)

    def _git(self, cwd, *args):
        subprocess.run(["git", "-C", cwd, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"] + list(args),
                       check=True, capture_output=True)

    def test_history_finds_removed_secret_only(self):
        try:
            subprocess.run(["git", "--version"], check=True, capture_output=True)
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("git not available")
        root = self.make_project({"app.py": "KEY = '%s'\nprint(1)\n" % self.AWS})
        self._git(root, "init", "-q")
        self._git(root, "add", "-A")
        self._git(root, "commit", "-qm", "add key")
        with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as fh:
            fh.write("import os\nKEY = os.environ['K']\n")
        self._git(root, "commit", "-qam", "remove key")
        sc = Scanner(root, Config())
        res = sc.run()
        self.assertEqual(self.by_rule(res.findings, "RS-SEC-001"), [])
        self.assertEqual(scan_history(sc), 2)
        hist = self.by_rule(sc.findings, "RS-SEC-005")
        self.assertEqual(len(hist), 1)
        self.assertEqual((hist[0].file, hist[0].line, hist[0].severity), ("app.py", 1, "critical"))
        self.assertNotIn(self.AWS, json.dumps([f.to_dict() for f in sc.findings]))
        self.assertIn("commit", hist[0].message)

    def test_history_skips_secret_still_in_tree(self):
        try:
            subprocess.run(["git", "--version"], check=True, capture_output=True)
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("git not available")
        root = self.make_project({"app.py": "KEY = '%s'\n" % self.AWS})
        self._git(root, "init", "-q")
        self._git(root, "add", "-A")
        self._git(root, "commit", "-qm", "add key")
        sc = Scanner(root, Config())
        sc.run()
        scan_history(sc)
        self.assertEqual(self.by_rule(sc.findings, "RS-SEC-005"), [])
        self.assertEqual(len(self.by_rule(sc.findings, "RS-SEC-001")), 1)

    def test_history_outside_git_is_a_warning_not_a_crash(self):
        root = self.make_project({"a.py": "x = 1\n"})
        sc = Scanner(root, Config())
        sc.run()
        self.assertEqual(scan_history(sc), 0)
        self.assertTrue(any("--history" in w for w in sc.warnings))


class TestSecrets(_ProjectMixin, unittest.TestCase):
    AWS = "AKIA" + "J7Q2M9X4L1P8R6T3"
    GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # reposentry: ignore RS-SEC-002
    JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
           "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
           "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")  # reposentry: ignore RS-SEC-002
    # synthetic test fixture, not a real key -- reposentry: ignore RS-SEC-002
    PEM_BODY = "MIIEowIBAAKCAQEAu7Qx9v2K1pL8nR4sT6uV0wXyZaBcDeFgHiJkLmNoPqRsTuVw"
    PEM = ("-----BEGIN RSA PRIVATE KEY-----\n" + PEM_BODY + "\n" + PEM_BODY[::-1]  # reposentry: ignore RS-SEC-001
           + "\n-----END RSA PRIVATE KEY-----\n")

    def test_known_patterns_detected(self):
        files = {"aws.py": "KEY = '%s'\n" % self.AWS, "gh.txt": "token %s\n" % self.GH,
                 "jwt.js": "const t = '%s';\n" % self.JWT, "key.pem": self.PEM}
        findings = self.scan_files(files)
        hits = self.by_rule(findings, "RS-SEC-001")
        self.assertEqual(sorted(f.file for f in hits), ["aws.py", "gh.txt", "jwt.js", "key.pem"])
        self.assertEqual({f.severity for f in hits if f.file in ("aws.py", "gh.txt", "key.pem")}, {"critical"})

    def test_hardcoded_assignment_and_placeholders(self):
        files = {"a.py": "password = 'changeme'\napi_key = \"hunter2-correct-horse\"\nsecret = os.environ['X']\n",
                 "b.py": "uuid = '123e4567-e89b-12d3-a456-426614174000'\n",
                 "package-lock.json": "\"integrity\": \"sha256-%s\"\n" % ("ab12cd34" * 8),
                 "c.py": "digest = '%s'\n" % ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")}
        findings = self.scan_files(files)
        sec1 = self.by_rule(findings, "RS-SEC-001")
        self.assertEqual([(f.file, f.line) for f in sec1], [("a.py", 2)])
        self.assertEqual(self.by_rule(findings, "RS-SEC-002"), [])

    def test_high_entropy_hex_detected(self):
        # synthetic fixture -- reposentry: ignore RS-SEC-002
        files = {"a.py": "KEY = '4f9a2c7e1b8d3f6a0c5e9b2d7f1a4c8e3b6d9f2a'\n"}
        findings = self.scan_files(files)
        hits = self.by_rule(findings, "RS-SEC-002")
        self.assertEqual(len(hits), 1)
        self.assertIn("hex", hits[0].message)

    def test_output_is_redacted_in_every_format(self):
        files = {"aws.py": "KEY = '%s'\n" % self.AWS, "gh.txt": "token %s\n" % self.GH,
                 "jwt.js": "const t = '%s';\n" % self.JWT, "key.pem": self.PEM,
                 # synthetic fixture -- reposentry: ignore RS-SEC-001
                 "pw.py": "password = 'hunter2-correct-horse'\n"}
        root = self.make_project(files)
        findings = scan(root).findings
        secrets = [self.AWS, self.GH, self.JWT, self.PEM_BODY, self.PEM_BODY[::-1], "hunter2-correct-horse"]
        for rendered in (render_terminal(findings, 5, "high", True), render_terminal(findings, 5, "high", False),
                         render_json(findings, 5, "high"), render_markdown(findings, 5, "high")):
            for secret in secrets:
                self.assertNotIn(secret, rendered)
            self.assertIn("****", rendered)
        self.assertIn("AKIA****[len=20]", render_json(findings, 5, "high"))
        for rendered in (self.run_cli([root, "--format", "json"])[1], self.run_cli([root, "--format", "markdown"])[1],
                         self.run_cli([root])[1]):
            for secret in secrets:
                self.assertNotIn(secret, rendered)

    def test_secret_in_lockfile_still_pattern_scanned_but_no_entropy(self):
        files = {"yarn.lock": "resolved \"https://x/%s\"\n  integrity sha512-%s\n" % ("deadbeef" * 6, "Zm9vYmFy" * 8)}
        findings = self.scan_files(files)
        self.assertEqual(self.by_rule(findings, "RS-SEC-002"), [])


class TestInjectionSinks(_ProjectMixin, unittest.TestCase):
    def test_python_sinks(self):
        src = ("import os, subprocess\nimport subprocess as sp\nfrom os import system\n"
               "def f(user_input, cmd, x):\n    os.system(user_input)\n    os.system('ls')\n"
               "    subprocess.run(cmd, shell=True)\n    subprocess.run(cmd)\n    sp.check_output('ls', shell=True)\n"
               "    system(f'ls {x}')\n    eval('1+1')\n    eval(x)\n    exec(x)\n")
        findings = self.scan_files({"a.py": src})
        sev = {(f.line, f.rule_id): f.severity for f in findings if f.rule_id.startswith("RS-SEC-00")}
        self.assertEqual(sev[(5, "RS-SEC-003")], "critical")
        self.assertEqual(sev[(6, "RS-SEC-003")], "medium")
        self.assertEqual(sev[(7, "RS-SEC-003")], "critical")
        self.assertNotIn((8, "RS-SEC-003"), sev)
        self.assertEqual(sev[(9, "RS-SEC-003")], "medium")
        self.assertEqual(sev[(10, "RS-SEC-003")], "critical")
        self.assertEqual(sev[(11, "RS-SEC-004")], "medium")
        self.assertEqual(sev[(12, "RS-SEC-004")], "critical")
        self.assertTrue(SEVERITY_RANK[sev[(11, "RS-SEC-004")]] < SEVERITY_RANK[sev[(12, "RS-SEC-004")]])
        self.assertEqual(sev[(13, "RS-SEC-004")], "critical")

    def test_deserialization_sinks(self):
        src = ("import pickle, yaml, marshal\ndef f(d):\n    pickle.loads(d)\n    yaml.load(d)\n"
               "    yaml.load(d, Loader=yaml.SafeLoader)\n    yaml.safe_load(d)\n    marshal.loads(d)\n"
               "    __import__(d)\n    __import__('os')\n    compile(d, 'x', 'exec')\n")
        findings = self.scan_files({"a.py": src})
        lines = sorted(f.line for f in self.by_rule(findings, "RS-SEC-004"))
        self.assertEqual(lines, [3, 4, 7, 8, 10])

    def test_shadowed_builtin_not_flagged(self):
        src = "def eval(x):\n    return x\ndef f(y):\n    return eval(y)\n"
        findings = self.scan_files({"a.py": src})
        self.assertEqual(self.by_rule(findings, "RS-SEC-004"), [])

    def test_javascript_sinks(self):
        src = ("const { exec } = require('child_process');\n// exec(userInput) in a comment\n"
               "exec(userInput);\nexec('ls -la');\neval(code);\nconst f = new Function(body);\n"
               "setTimeout('doIt()', 10);\nel.innerHTML = userHtml;\nif (a == b) {}\n")
        findings = self.scan_files({"a.js": src})
        sinks = {(f.line, f.rule_id): f.severity for f in findings if f.rule_id in ("RS-SEC-003", "RS-SEC-004")}
        self.assertNotIn((2, "RS-SEC-003"), sinks)
        self.assertEqual(sinks[(3, "RS-SEC-003")], "critical")
        self.assertEqual(sinks[(4, "RS-SEC-003")], "medium")
        self.assertEqual(sinks[(5, "RS-SEC-004")], "critical")
        self.assertEqual(sinks[(6, "RS-SEC-004")], "critical")
        self.assertEqual(sinks[(7, "RS-SEC-004")], "medium")
        self.assertEqual(sinks[(8, "RS-SEC-004")], "high")
        self.assertTrue(all(f.confidence in ("low", "medium") for f in findings if f.file == "a.js"))

    def test_c_and_shell_sinks(self):
        c_src = ("#include <stdlib.h>\n/* system(evil) */\nint main(int argc, char **argv) {\n"
                 "    system(argv[1]);\n    system(\"ls\");\n    char buf[8]; strcpy(buf, argv[1]);\n    gets(buf);\n    return 0;\n}\n")
        sh_src = ("#!/bin/bash\n# eval \"$x\" in a comment\neval \"$CMD\"\neval 'echo hi'\n"
                  "curl -fsSL https://example.com/install.sh | sudo bash\nwget -qO- https://x | sh\n")
        findings = self.scan_files({"m.c": c_src, "s.sh": sh_src})
        c = {(f.line, f.rule_id): f.severity for f in findings if f.file == "m.c"}
        self.assertEqual(c[(4, "RS-SEC-003")], "critical")
        self.assertEqual(c[(5, "RS-SEC-003")], "medium")
        self.assertEqual(c[(6, "RS-SEC-004")], "high")
        self.assertEqual(c[(7, "RS-SEC-004")], "high")
        self.assertNotIn((2, "RS-SEC-003"), c)
        sh = {f.line: f.severity for f in findings if f.file == "s.sh" and f.rule_id == "RS-SEC-003"}
        self.assertEqual(sh, {3: "critical", 4: "medium", 5: "critical", 6: "critical"})


class TestConfig(_ProjectMixin, unittest.TestCase):
    def test_invalid_json_exit_2(self):
        root = self.make_project({".reposentry.json": "{not json", "a.py": "x = 1\n"})
        code, _, err = self.run_cli([root])
        self.assertEqual(code, 2)
        self.assertIn("invalid JSON", err)

    def test_invalid_value_exit_2_and_unknown_key_warning(self):
        root = self.make_project({".reposentry.json": json.dumps({"thresholds": {"max_nesting_depth": "deep"}}), "a.py": ""})
        self.assertEqual(self.run_cli([root])[0], 2)
        root2 = self.make_project({".reposentry.json": json.dumps({"bogus": 1}), "a.py": "x = 1\n"})
        code, _, err = self.run_cli([root2])
        self.assertEqual(code, 0)
        self.assertIn("unknown config key 'bogus'", err)

    def test_severity_override_applied(self):
        src = "def f():\n    try:\n        pass\n    except:\n        pass\n"
        findings = self.scan_files({"a.py": src}, {"severity_overrides": {"RS-QUAL-003": "low"}})
        self.assertEqual(self.by_rule(findings, "RS-QUAL-003")[0].severity, "low")

    def test_ignore_dirs_globs_and_gitignore(self):
        files = {"a.py": "import os\nos.system(x)\n", "vendor/b.py": "import os\nos.system(x)\n",
                 "gen/c.py": "import os\nos.system(x)\n", "skip.generated.py": "import os\nos.system(x)\n",
                 ".gitignore": "gen/\n"}
        findings = self.scan_files(files, {"ignore_dirs": ["vendor"], "ignore_globs": ["*.generated.py"]})
        self.assertEqual(sorted({f.file for f in findings}), ["a.py"])
        findings = self.scan_files(files, {"ignore_dirs": ["vendor"], "ignore_globs": ["*.generated.py"],
                                           "respect_gitignore": False})
        self.assertEqual(sorted({f.file for f in findings}), ["a.py", "gen/c.py"])

    def test_suppression_comment(self):
        src = ("import os\nos.system(x)  # reposentry: ignore RS-SEC-003\n"
               "# reposentry: ignore RS-SEC-003\nos.system(y)\nos.system(z)\n"
               "os.system(w)  # reposentry: ignore RS-QUAL-003\n")
        findings = self.scan_files({"a.py": src})
        self.assertEqual(sorted(f.line for f in self.by_rule(findings, "RS-SEC-003")), [5, 6])

    def test_baseline_roundtrip(self):
        root = self.make_project({"a.py": "import os\nos.system(x)\n"})
        baseline = os.path.join(root, "base.json")
        code, _, err = self.run_cli([root, "--write-baseline", baseline, "--ignore-rules", "RS-SEC-002"])
        self.assertEqual(code, 1)
        self.assertIn("baseline written", err)
        code, out, _ = self.run_cli([root, "--baseline", baseline, "--format", "json", "--ignore-rules", "RS-SEC-002"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["summary"]["total"], 0)
        with open(os.path.join(root, "a.py"), "a", encoding="utf-8") as fh:
            fh.write("os.system(new_thing)\n")
        code, out, _ = self.run_cli([root, "--baseline", baseline, "--format", "json", "--ignore-rules", "RS-SEC-002"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["summary"]["total"], 1)

    def test_rule_selection(self):
        root = self.make_project({"a.py": "import os\nos.system(x)\ntry:\n    pass\nexcept:\n    pass\n"})
        code, out, _ = self.run_cli([root, "--rules", "RS-QUAL-*", "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual({f["rule_id"] for f in json.loads(out)["findings"]}, {"RS-QUAL-003"})
        self.assertEqual(self.run_cli([root, "--rules", "RS-NOPE-999"])[0], 2)


class TestCLI(_ProjectMixin, unittest.TestCase):
    def test_exit_codes_by_threshold(self):
        root = self.make_project({"a.py": "def f():\n    try:\n        pass\n    except:\n        pass\n"})
        self.assertEqual(self.run_cli([root])[0], 0)
        self.assertEqual(self.run_cli([root, "--fail-on-severity", "medium"])[0], 1)
        self.assertEqual(self.run_cli([root, "--fail-on-severity", "low"])[0], 1)
        self.assertEqual(self.run_cli(["--path", root, "--fail-on-severity", "critical"])[0], 0)

    def test_bad_path_and_bad_config_exit_2(self):
        self.assertEqual(self.run_cli([os.path.join(tempfile.gettempdir(), "repo_sentry_definitely_missing")])[0], 2)
        root = self.make_project({"a.py": "x = 1\n"})
        self.assertEqual(self.run_cli([root, "--config", os.path.join(root, "missing.json")])[0], 2)
        self.assertEqual(self.run_cli([root, "--baseline", os.path.join(root, "missing.json")])[0], 2)
        self.assertEqual(self.run_cli([root, "--format", "xml"])[0], 2)

    def test_json_output_parses_and_is_deterministic(self):
        root = self.make_project({"a.py": "import os\nos.system(x)\n", "b.py": "import a\n",
                                  "c.js": "eval(x)\n"})
        code1, out1, _ = self.run_cli([root, "--format", "json"])
        code2, out2, _ = self.run_cli([root, "--format", "json"])
        self.assertEqual((code1, code2), (1, 1))
        self.assertEqual(out1, out2)
        data = json.loads(out1)
        self.assertEqual(list(data.keys()), ["tool", "version", "scanned_files", "summary", "findings"])
        self.assertEqual(data["tool"], TOOL_NAME)
        self.assertEqual(data["scanned_files"], 3)
        self.assertEqual(list(data["findings"][0].keys()),
                         ["rule_id", "severity", "confidence", "file", "line", "col", "message", "snippet", "remediation"])
        sevs = [SEVERITY_RANK[f["severity"]] for f in data["findings"]]
        self.assertEqual(sevs, sorted(sevs, reverse=True))

    def test_markdown_and_terminal_render(self):
        root = self.make_project({"a.py": "import os\nos.system(x)\n"})
        code, out, _ = self.run_cli([root, "--format", "markdown"])
        self.assertEqual(code, 1)
        self.assertIn("| Severity | Count |", out)
        self.assertIn("### Critical (1)", out)
        code, out, _ = self.run_cli([root, "--no-color"])
        self.assertIn("[CRITICAL] RS-SEC-003", out)
        self.assertIn("^", out)
        self.assertNotIn("\x1b[", out)
        self.assertIn("result: FAIL", out)

    def test_list_rules_and_version(self):
        code, out, _ = self.run_cli(["--list-rules"])
        self.assertEqual(code, 0)
        for rid in RULES:
            self.assertIn(rid, out)
        self.assertIn("pattern", out)
        code, out, _ = self.run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn(__version__, out)

    def test_single_file_scan(self):
        root = self.make_project({"a.py": "import os\nos.system(x)\n"})
        code, out, _ = self.run_cli([os.path.join(root, "a.py"), "--format", "json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["findings"][0]["file"], "a.py")


class TestRobustness(_ProjectMixin, unittest.TestCase):
    def test_syntax_error_recorded_and_scan_continues(self):
        files = {"bad.py": "def broken(:\n    pass\n", "good.py": "import os\nos.system(x)\n"}
        findings = self.scan_files(files)
        sys_findings = self.by_rule(findings, "RS-SYS-001")
        self.assertEqual([f.file for f in sys_findings], ["bad.py"])
        self.assertEqual(sys_findings[0].severity, "low")
        self.assertEqual([f.file for f in self.by_rule(findings, "RS-SEC-003")], ["good.py"])

    def test_binary_file_skipped_and_size_cap(self):
        files = {"blob.py": b"\x00\x01\x02 os.system(x)", "big.py": "import os\nos.system(x)\n" + "#" * 3000}
        root = self.make_project(files)
        cfg = Config()
        cfg.max_file_bytes = 1024
        result = scan(root, cfg)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.scanned_files, 0)

    def test_non_utf8_file_scanned_with_replacement(self):
        files = {"latin.py": "x = '\xe9'\nimport os\nos.system(y)\n".encode("latin-1")}
        findings = self.scan_files(files)
        self.assertEqual(len(self.by_rule(findings, "RS-SYS-001")), 1)
        self.assertEqual(len(self.by_rule(findings, "RS-SEC-003")), 1)

    def test_deterministic_ordering(self):
        files = {"z.py": "import os\nos.system(x)\n", "a.py": "import os\nos.system(x)\ntry:\n    pass\nexcept:\n    pass\n"}
        f1 = [f.to_dict() for f in self.scan_files(files)]
        f2 = [f.to_dict() for f in self.scan_files(files)]
        self.assertEqual(f1, f2)
        self.assertEqual([f["file"] for f in f1 if f["severity"] == "critical"], ["a.py", "z.py"])

    def test_comment_stripper_preserves_layout(self):
        src = "a(); // c\nb('x//y'); /* z\nq */ c();\n"
        stripped = strip_comments(src, "js")
        self.assertEqual(len(stripped), len(src))
        self.assertEqual(stripped.count("\n"), src.count("\n"))
        self.assertIn("b('x//y')", stripped)
        self.assertNotIn("z", stripped)
        sh = "echo '#notacomment' # real\n"
        self.assertIn("#notacomment", strip_comments(sh, "shell"))
        self.assertNotIn("real", strip_comments(sh, "shell"))

    def test_gitignore_matcher(self):
        gi = GitIgnore()
        gi.load("", "build/\n*.log\n!keep.log\n/root_only.txt\ndocs/**/*.md\n")
        self.assertTrue(gi.is_ignored("build", True))
        self.assertTrue(gi.is_ignored("build/x.py", False))
        self.assertFalse(gi.is_ignored("build", False))
        self.assertTrue(gi.is_ignored("a/b.log", False))
        self.assertFalse(gi.is_ignored("a/keep.log", False))
        self.assertTrue(gi.is_ignored("root_only.txt", False))
        self.assertFalse(gi.is_ignored("sub/root_only.txt", False))
        self.assertTrue(gi.is_ignored("docs/a/b/c.md", False))


class TestJsMasking(_ProjectMixin, unittest.TestCase):
    TRICKY = [
        "const r = /[/]x\\/y/g; const d = (a + b) / 2 / c; var s = a / b / c;\n",
        "const x = (a) / 2;\nconst re = x.replace(/\\/+/g, '/');\n",
        "const t = `a ${b ? `c ${d ? `e ${f}` : 'g'}` : 'h'} i`;\nnext();\n",
        "function App() {\n  return <p className='x'>don't {name} won't</p>;\n}\nconst y = exec(cmd);\n",
        "const s = 'unterminated\nconst after = eval(z);\n",
        "const a: Array<string> = []; if (a < b > c) {} const m = new Map<string, number>();\nrun(x);\n",
    ]

    def test_comments_strings_and_templates_are_masked(self):
        src = "// eval(x)\nconst s = \"exec(cmd)\";\nconst t = `eval(x)`;\nconst u = `pre ${eval(y)} post`;\n"
        masked = js_mask(src)
        self.assertEqual(len(masked), len(src))
        self.assertNotIn("eval(x)", masked)
        self.assertNotIn("exec(cmd)", masked)
        self.assertIn("eval(y)", masked)
        self.assertIn('"', masked)
        self.assertIn("`", masked)
        self.assertEqual([i for i, ch in enumerate(masked) if ch == "\n"], [i for i, ch in enumerate(src) if ch == "\n"])

    def test_length_and_newlines_preserved_on_tricky_inputs(self):
        for src in self.TRICKY:
            masked = js_mask(src)
            self.assertEqual(len(masked), len(src), src)
            self.assertEqual([i for i, ch in enumerate(masked) if ch == "\n"],
                             [i for i, ch in enumerate(src) if ch == "\n"], src)
            crlf = src.replace("\n", "\r\n")
            masked_crlf = js_mask(crlf)
            self.assertEqual(len(masked_crlf), len(crlf))
            self.assertEqual(masked_crlf.count("\r\n"), crlf.count("\r\n"))

    def test_regex_versus_division(self):
        masked = js_mask(self.TRICKY[0])
        self.assertNotIn("[/]x", masked)
        self.assertIn("(a + b) / 2 / c", masked)
        self.assertIn("a / b / c", masked)
        masked = js_mask(self.TRICKY[1])
        self.assertIn("(a) / 2", masked)
        self.assertIn("x.replace(/", masked)
        self.assertNotIn("\\/+", masked)
        masked = js_mask("const n = total / count;\nreturn /ab+c/i.test(s) ? 1 : 2;\n")
        self.assertIn("total / count", masked)
        self.assertNotIn("ab+c", masked)
        self.assertIn(".test(s)", masked)

    def test_nested_templates_three_deep(self):
        masked = js_mask(self.TRICKY[2])
        self.assertEqual(masked, "const t = `  ${b ? `  ${d ? `  ${f}` : ' '}` : ' '}  `;\nnext();\n")

    def test_jsx_with_apostrophes_and_generics(self):
        masked = js_mask(self.TRICKY[3])
        self.assertNotIn("don't", masked)
        self.assertNotIn("won't", masked)
        self.assertIn("{name}", masked)
        self.assertIn("exec(cmd)", masked)
        tsx = ("const items: Array<string> = [];\nfunction List<T,>(props: { rows: T[] }) {\n"
               "  return (\n    <ul className=\"list\">\n      {props.rows.map((r) => <li key={String(r)}>it's {r} here</li>)}\n"
               "    </ul>\n  );\n}\nif (a < b && c > d) { exec(cmd); }\nconst m = new Map<string, number>();\n")
        masked = js_mask(tsx)
        self.assertEqual(len(masked), len(tsx))
        self.assertNotIn("it's", masked)
        self.assertIn("Array<string>", masked)
        self.assertIn("exec(cmd)", masked)
        self.assertIn("new Map<string, number>()", masked)
        self.assertIn("String(r)", masked)
        plain_ts = js_mask("const v = <any>obj;\nconst w = a < b;\nexec(cmd);\n", jsx=False)
        self.assertIn("exec(cmd)", plain_ts)

    def test_unterminated_constructs_do_not_derail(self):
        masked = js_mask(self.TRICKY[4])
        self.assertIn("eval(z)", masked)
        masked = js_mask("const t = `never closed\nexec(a);\n")
        self.assertNotIn("exec(a)", masked)
        self.assertEqual(len(masked), len("const t = `never closed\nexec(a);\n"))
        masked = js_mask("/* never closed\nexec(a);\n")
        self.assertNotIn("exec(a)", masked)
        masked = js_mask("const r = /never closed\nexec(a);\n")
        self.assertIn("exec(a)", masked)
        self.assertEqual(js_mask(""), "")

    def test_masking_is_fast_on_pathological_input(self):
        import time as _time
        big_parens = "f" + "(" * 200000 + ")" * 200000 + ";\n"
        one_line = "var x = 1;" + " a = a + 1;" * 100000 + "\n"
        tpl = "const t = `" + "${" * 20000 + "x" + "}" * 20000 + "`;\n"
        started = _time.time()
        for src in (big_parens, one_line, tpl, "a" * 1000000):
            masked = js_mask(src)
            self.assertEqual(len(masked), len(src))
        self.assertLess(_time.time() - started, 5.0)

    def test_masked_sinks_ignore_comments_and_strings(self):
        src = ("// eval(x)\nconst s = \"eval(x)\";\nconst t = `eval(x)`;\nconst u = `${eval(y)}`;\neval(x);\n")
        findings = self.scan_files({"a.js": src})
        lines = sorted(f.line for f in self.by_rule(findings, "RS-SEC-004"))
        self.assertEqual(lines, [4, 5])


class TestJsStructure(_ProjectMixin, unittest.TestCase):
    FIXTURE = (
        "function plain(a) { return [a].map(x => x + 1); }\n"                      # 1 declaration
        "async function fetchIt(url) { const r = await get(url); return r; }\n"   # 2 async declaration
        "function* gen() { yield 1; }\n"                                            # 3 generator
        "const arrow = (a, b) => { return a + b; };\n"                              # 4 arrow with block body
        "const asyncArrow = async x => { return x; };\n"                           # 5 async arrow, bare param
        "export default () => { run(); };\n"                                        # 6 export default arrow
        "class K extends Base {\n"
        "  constructor(v) { super(); this.v = v; }\n"                               # 7 constructor
        "  static async #load(id) { return id; }\n"                                 # 8 static async private method
        "}\n"
        "const obj = {\n"
        "  handler(e) {\n"                                                          # 9 object-literal method
        "    if (e) { while (e) { e--; } }\n"
        "    for (const k of e) { switch (k) { case 1: break; } }\n"
        "    try { x(); } catch (err) { log(err); }\n"
        "    with (e) { y(); }\n"
        "  },\n"
        "};\n"
    )

    def test_function_discovery_names_and_count(self):
        funcs = js_discover_functions(js_mask(self.FIXTURE))
        names = [f.name for f in funcs]
        self.assertEqual(len(funcs), 9)
        self.assertEqual(names, ["plain", "fetchIt", "gen", "arrow", "asyncArrow", "default", "constructor",
                                 "#load", "handler"])
        for bad in ("if", "while", "catch", "for", "switch", "with"):
            self.assertNotIn(bad, names)
        self.assertTrue(all(f.body_end > f.body_start for f in funcs))

    def test_typescript_signatures_and_return_types(self):
        src = ("export function parse<T>(input: string, opts?: Options): { ok: boolean; value: T } {\n"
               "  if (input) { return { ok: true, value: null as any }; }\n  return { ok: false, value: null as any };\n}\n"
               "interface Api { load(id: string): Promise<void>; }\n"
               "abstract class A { abstract run(): void; protected async step(n: number): Promise<number> { return n; } }\n")
        funcs = js_discover_functions(js_mask(src))
        self.assertEqual([f.name for f in funcs], ["parse", "step"])

    @staticmethod
    def metrics(src: str) -> Dict[str, Tuple[int, int]]:
        masked = js_mask(src)
        out: Dict[str, Tuple[int, int]] = {}
        for f in js_discover_functions(masked):
            own = js_own_text(masked, f.body_start + 1, f.body_end, f.children)
            out[f.name] = (js_complexity(own), js_max_nesting(own)[0])
        return out

    def test_exact_complexity_samples(self):
        # (a) 1 + three `if` = 4
        a = "function a(x) { if (x) {} if (x > 1) {} if (x > 2) {} return x; }\n"
        self.assertEqual(self.metrics(a)["a"][0], 4)
        # (b) 1 + if + else-if (2) + for (1) + && || ?? (3) + ternary (1) + 3 cases (3, default not counted)
        #     + catch (1) = 12
        b = ("function b(x, y, z, k) {\n"
             "  if (x) { } else if (y) { } else { }\n"
             "  for (const i of z) { }\n"
             "  const v = x && y || z ?? k;\n"
             "  const w = x ? 1 : 2;\n"
             "  switch (k) { case 1: break; case 2: break; case 3: break; default: break; }\n"
             "  try { run(); } catch (e) { log(e); }\n"
             "  return v + w;\n}\n")
        self.assertEqual(self.metrics(b)["b"][0], 12)
        # (c) optional chaining is not counted, `??` is: 1 + 1 = 2
        c = "function c(a) { return a?.b ?? c; }\n"
        self.assertEqual(self.metrics(c)["c"][0], 2)
        # (d) the nested arrow's `if` belongs to `inner` (1 + 1 = 2), the parent keeps its own `if` (1 + 1 = 2)
        d = ("function d(a) {\n  const inner = (q) => { if (q) { return 1; } return 2; };\n"
             "  if (a) { return inner(a); }\n  return 0;\n}\n")
        m = self.metrics(d)
        self.assertEqual(m["d"][0], 2)
        self.assertEqual(m["inner"][0], 2)
        # TS optional parameters and properties are not ternaries
        e = "function e(a?: number, b?: string) { const o: { p?: number } = {}; return a ? o : b; }\n"
        self.assertEqual(self.metrics(e)["e"][0], 2)

    def test_complexity_threshold_via_scan(self):
        branches = "".join("  if (x === %d) { return %d; }\n" % (i, i) for i in range(12))
        src = "function big(x) {\n%s  return -1;\n}\n" % branches
        findings = self.scan_files({"a.js": src})
        hits = self.by_rule(findings, "RS-QUAL-001")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "medium")
        self.assertEqual(hits[0].confidence, "medium")
        self.assertIn("approximate", hits[0].message)
        self.assertEqual(hits[0].line, 1)
        findings = self.scan_files({"a.js": src}, {"thresholds": {"max_cyclomatic_complexity": 5}})
        self.assertEqual(self.by_rule(findings, "RS-QUAL-001")[0].severity, "high")

    def test_nesting_depth(self):
        deep = ("function f(a) {\n  if (a) {\n    if (a) {\n      if (a) {\n        if (a) {\n"
                "          if (a) { run(); }\n        }\n      }\n    }\n  }\n}\n")
        findings = self.scan_files({"a.ts": deep})
        hits = self.by_rule(findings, "RS-QUAL-002")
        self.assertEqual(len(hits), 1)
        self.assertIn("depth 5", hits[0].message)
        self.assertEqual(hits[0].line, 6)
        chain = ("function g(a) {\n" + "  if (a === 0) { run(); }\n" +
                 "".join("  else if (a === %d) { run(); }\n" % i for i in range(1, 7)) + "  else { run(); }\n}\n")
        self.assertEqual(self.metrics(chain)["g"][1], 1)
        self.assertEqual(self.by_rule(self.scan_files({"a.ts": chain}), "RS-QUAL-002"), [])
        four = "function h(a) {\n  for (;;) {\n    while (a) {\n      try {\n        if (a) { run(); }\n      } catch (e) { log(e); }\n    }\n  }\n}\n"
        self.assertEqual(self.by_rule(self.scan_files({"a.js": four}), "RS-QUAL-002"), [])

    def test_empty_catch(self):
        src = ("try { a(); } catch (e) {}\n"
               "try { b(); } catch {\n  // ignore\n}\n"
               "try { c(); } catch (e) { console.error(e); }\n"
               "try { d(); } catch (e) { /* nothing */ }\n")
        findings = self.scan_files({"a.js": src})
        hits = self.by_rule(findings, "RS-QUAL-004")
        self.assertEqual(sorted(f.line for f in hits), [1, 2, 6])
        self.assertTrue(all(f.severity == "medium" and f.confidence == "medium" for f in hits))

    def test_test_files_skip_quality_rules(self):
        branches = "".join("  if (x === %d) { return %d; }\n" % (i, i) for i in range(12))
        src = "function big(x) {\n%s  return -1;\n}\n" % branches
        findings = self.scan_files({"big.test.js": src, "__tests__/other.js": src, "src/big.js": src})
        self.assertEqual([f.file for f in self.by_rule(findings, "RS-QUAL-001")], ["src/big.js"])


class TestJsImportGraph(_ProjectMixin, unittest.TestCase):
    def test_three_module_cycle_reported_once_with_path(self):
        files = {"a.ts": "import { b } from './b';\nexport const a = 1;\n",
                 "b.ts": "import { c } from './c';\nexport const b = 2;\n",
                 "c.ts": "import { a } from './a';\nexport const c = 3;\n"}
        cycles = self.by_rule(self.scan_files(files), "RS-ARCH-001")
        self.assertEqual(len(cycles), 1)
        self.assertEqual(cycles[0].severity, "high")
        self.assertEqual(cycles[0].file, "a.ts")
        self.assertEqual(cycles[0].line, 1)
        self.assertIn("a -> b -> c -> a", cycles[0].message)

    def test_js_extension_resolves_to_ts_and_index_import(self):
        files = {"main.ts": "import { x } from './x.js';\n", "x.ts": "import './main';\n",
                 "app.ts": "import u from './utils';\n", "utils/index.ts": "import '../app';\n"}
        cycles = self.by_rule(self.scan_files(files), "RS-ARCH-001")
        messages = sorted(c.message for c in cycles)
        self.assertEqual(len(messages), 2)
        self.assertIn("app -> utils/index -> app", messages[0])
        self.assertIn("main -> x -> main", messages[1])

    def test_tsconfig_paths_alias_and_malformed_config(self):
        tsconfig = ('{\n  // comment\n  "compilerOptions": {\n    "baseUrl": ".",\n'
                    '    "paths": { "@/*": ["src/*"], },\n  },\n}\n')
        files = {"tsconfig.json": tsconfig, "src/a.ts": "import b from '@/b';\n", "src/b.ts": "import a from '@/a';\n"}
        cycles = self.by_rule(self.scan_files(files), "RS-ARCH-001")
        self.assertEqual(len(cycles), 1)
        self.assertIn("src/a -> src/b -> src/a", cycles[0].message)
        root = self.make_project({"jsconfig.json": "{ not json at all", "a.js": "import './b';\n", "b.js": "import './a';\n"})
        result = scan(root)
        self.assertTrue(any("jsconfig.json" in w for w in result.warnings))
        self.assertEqual(len(self.by_rule(result.findings, "RS-ARCH-001")), 1)

    def test_type_only_dynamic_and_function_level_imports_are_soft(self):
        files = {"a.ts": "import type { B } from './b';\nexport class A {}\n", "b.ts": "import { A } from './a';\nexport class B {}\n"}
        cycles = self.by_rule(self.scan_files(files), "RS-ARCH-001")
        self.assertEqual([c.severity for c in cycles], ["low"])
        self.assertIn("soft", cycles[0].message)
        files = {"a.js": "const b = require('./b');\n", "b.js": "async function f() { const a = await import('./a'); return a; }\n"}
        cycles = self.by_rule(self.scan_files(files), "RS-ARCH-001")
        self.assertEqual([c.severity for c in cycles], ["low"])
        files = {"a.js": "const b = require('./b');\n", "b.js": "function f() { return require('./a'); }\n"}
        self.assertEqual([c.severity for c in self.by_rule(self.scan_files(files), "RS-ARCH-001")], ["low"])

    def test_self_import_bare_packages_and_comments(self):
        files = {"s.ts": "import './s';\n",
                 "ok.ts": "import React from 'react';\nimport fs from 'node:fs';\nconst _ = require('lodash');\n"
                          "// import x from './s'\nconst t = \"import y from './s'\";\n"}
        cycles = self.by_rule(self.scan_files(files), "RS-ARCH-001")
        self.assertEqual(len(cycles), 1)
        self.assertEqual(cycles[0].file, "s.ts")
        self.assertIn("Self-import", cycles[0].message)

    def test_long_chain_on_disk(self):
        n = 5000
        files = {"m%d.js" % i: "import './m%d';\n" % (i + 1) for i in range(n - 1)}
        files["m%d.js" % (n - 1)] = "export const x = 1;\n"
        self.assertEqual(self.by_rule(self.scan_files(files), "RS-ARCH-001"), [])

    def test_layers_and_forbidden_imports(self):
        files = {"src/api/routes.ts": "import { Model } from '../domain/models';\n",
                 "src/domain/models.ts": "import { routes } from '../api/routes';\n"}
        findings = self.scan_files(files, {"layers": ["api", "service", "domain"]})
        layer = self.by_rule(findings, "RS-ARCH-002")
        self.assertEqual([(f.file, f.line) for f in layer], [("src/domain/models.ts", 1)])
        self.assertIn("'domain' must not import layer 'api'", layer[0].message)
        findings = self.scan_files(files, {"forbidden_imports": [{"from": "domain", "to": "api"}]})
        self.assertEqual([f.file for f in self.by_rule(findings, "RS-ARCH-002")], ["src/domain/models.ts"])


class TestJsSecurity(_ProjectMixin, unittest.TestCase):
    def test_sinks_on_masked_code(self):
        src = ("const { exec } = require('child_process');\n"   # 1
               "exec(userInput);\n"                              # 2 critical
               "exec(\"ls\");\n"                                 # 3 medium
               "eval(x);\n"                                      # 4 critical
               "// eval(x)\n"                                    # 5 not flagged
               "const s = \"eval(x)\";\n"                        # 6 not flagged
               "el.innerHTML = x;\n"                             # 7 high
               "el.innerHTML = \"<b>\";\n"                       # 8 medium
               "exec(`rm -rf ${dir}`);\n"                        # 9 critical
               "exec('ls' + dir);\n")                            # 10 critical
        findings = self.scan_files({"a.js": src})
        sev = {(f.line, f.rule_id): f.severity for f in findings if f.rule_id in ("RS-SEC-003", "RS-SEC-004")}
        self.assertEqual(sev, {(2, "RS-SEC-003"): "critical", (3, "RS-SEC-003"): "medium", (4, "RS-SEC-004"): "critical",
                               (7, "RS-SEC-004"): "high", (8, "RS-SEC-004"): "medium", (9, "RS-SEC-003"): "critical",
                               (10, "RS-SEC-003"): "critical"})
        self.assertTrue(SEVERITY_RANK[sev[(8, "RS-SEC-004")]] < SEVERITY_RANK[sev[(7, "RS-SEC-004")]])

    def test_execa_and_shelljs_count_as_shell(self):
        findings = self.scan_files({"a.js": "import { exec } from 'execa';\nexec(cmd);\n",
                                    "b.js": "const sh = require('shelljs');\nsh.exec(cmd);\n",
                                    "c.js": "const exec = (x) => x;\nexec(cmd);\n"})
        self.assertEqual(sorted(f.file for f in self.by_rule(findings, "RS-SEC-003")), ["a.js", "b.js"])

    def test_dangerously_set_inner_html(self):
        src = ("export function View({ html }) {\n"
               "  return (\n    <div>\n      <p dangerouslySetInnerHTML={{ __html: html }} />\n"
               "      <p dangerouslySetInnerHTML={{__html: \"<b>static</b>\"}} />\n    </div>\n  );\n}\n")
        findings = self.scan_files({"view.jsx": src})
        hits = sorted((f.line, f.severity) for f in self.by_rule(findings, "RS-SEC-006"))
        self.assertEqual(hits, [(4, "high"), (5, "low")])

    SEC006 = (
        "const https = require('https');\n"                                          # 1
        "const crypto = require('crypto');\n"                                        # 2
        "const fs = require('fs');\n"                                                # 3
        "const agent = new https.Agent({ rejectUnauthorized: false });\n"            # 4 high
        "const okAgent = new https.Agent({ rejectUnauthorized: true });\n"           # 5
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n"                          # 6 high
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';\n"                          # 7
        "// process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n"                       # 8
        "const h1 = crypto.createHash('md5').update(pw).digest('hex');\n"            # 9 medium
        "const h2 = crypto.createHash('sha256').update(pw).digest('hex');\n"         # 10
        "const sessionToken = Math.random().toString(36).slice(2);\n"                # 11 medium
        "const a1 = 1;\n"                                                            # 12
        "const a2 = 2;\n"                                                            # 13
        "const a3 = 3;\n"                                                            # 14
        "const a4 = 4;\n"                                                            # 15
        "const jitter = Math.random() * 100;\n"                                      # 16
        "const b1 = 1;\n"                                                            # 17
        "const b2 = 2;\n"                                                            # 18
        "const b3 = 3;\n"                                                            # 19
        "const b4 = 4;\n"                                                            # 20
        "jwt.verify(t, key, { algorithms: ['HS256', 'none'] });\n"                   # 21 high
        "jwt.verify(t, key, { algorithms: ['HS256'] });\n"                           # 22
        "app.use(cors({ origin: '*', credentials: true }));\n"                       # 23 medium
        "app.use(cors({ origin: '*' }));\n"                                          # 24
        "app.use(cors({ origin: 'https://x.example', credentials: true }));\n"       # 25
        "fs.readFile(`${base}/${req.query.name}`, cb);\n"                            # 26 medium
        "fs.readFile('/etc/hosts', cb);\n"                                           # 27
        "fs.unlinkSync(path.join(base, params.id));\n"                               # 28 medium
        "const re1 = new RegExp(req.query.q);\n"                                     # 29 low
        "const re2 = new RegExp('^abc$');\n"                                         # 30
    )

    def test_sec006_positives_and_negatives(self):
        findings = self.scan_files({"server.js": self.SEC006})
        hits = {f.line: f.severity for f in self.by_rule(findings, "RS-SEC-006")}
        self.assertEqual(hits, {4: "high", 6: "high", 9: "medium", 11: "medium", 21: "high", 23: "medium",
                                26: "medium", 28: "medium", 29: "low"})
        self.assertTrue(all(f.confidence in ("low", "medium") and "approximate" in f.message
                            for f in self.by_rule(findings, "RS-SEC-006")))

    def test_sec006_downgraded_in_test_files(self):
        findings = self.scan_files({"server.test.js": self.SEC006})
        hits = {f.line: f.severity for f in self.by_rule(findings, "RS-SEC-006")}
        self.assertEqual(hits, {4: "medium", 6: "medium", 9: "low", 11: "low", 21: "medium", 23: "low",
                                26: "low", 28: "low", 29: "low"})

    def test_function_expression_names(self):
        src = ("const o = { f: function (q) { if (q) {} }, g: async function () {}, h: (a) => { if (a) {} } };\n"
               "const k = function () { if (1) {} };\nexport default function () {}\n[1].map(function () {});\n")
        names = [f.name for f in js_discover_functions(js_mask(src))]
        self.assertEqual(names, ["f", "g", "h", "k", "default", "<anonymous>"])

    def test_sinks_downgraded_in_test_files(self):
        code = "import { exec } from 'child_process';\nexec(userInput);\neval(x);\nexec('ls');\n"
        real = {(f.rule_id, f.line): f.severity for f in self.scan_files({"a.js": code})}
        test = {(f.rule_id, f.line): f.severity for f in self.scan_files({"a.test.js": code})}
        self.assertEqual(real, {("RS-SEC-003", 2): "critical", ("RS-SEC-004", 3): "critical", ("RS-SEC-003", 4): "medium"})
        self.assertEqual(test, {("RS-SEC-003", 2): "high", ("RS-SEC-004", 3): "high", ("RS-SEC-003", 4): "low"})

    def test_list_rules_describes_sec006(self):
        code, out, _ = self.run_cli(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("RS-SEC-006", out)
        self.assertIn("JS/TS: pattern-based, approximate", out)


class TestJsRobustnessAndCli(_ProjectMixin, unittest.TestCase):
    AWS = "AKIA" + "J7Q2M9X4L1P8R6T3"

    def test_secret_in_js_comment_detected_and_redacted(self):
        root = self.make_project({"a.js": "// key: %s\nconst x = 1;\n" % self.AWS,
                                  "b.js": "const t = `%s`;\n" % self.AWS})
        result = scan(root)
        hits = self.by_rule(result.findings, "RS-SEC-001")
        self.assertEqual(sorted(f.file for f in hits), ["a.js", "b.js"])
        self.assertTrue(all(f.severity == "critical" for f in hits))
        for rendered in (render_terminal(result.findings, 2, "high", False), render_json(result.findings, 2, "high"),
                         render_markdown(result.findings, 2, "high"), self.run_cli([root])[1],
                         self.run_cli([root, "--format", "json"])[1], self.run_cli([root, "--format", "markdown"])[1]):
            self.assertNotIn(self.AWS, rendered)
            self.assertIn("AKIA****[len=20]", rendered)

    def test_rules_ignore_override_suppression_and_baseline(self):
        src = TestJsSecurity.SEC006
        root = self.make_project({"server.js": src})
        code, out, _ = self.run_cli([root, "--rules", "RS-SEC-006", "--format", "json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual({f["rule_id"] for f in data["findings"]}, {"RS-SEC-006"})
        self.assertEqual(len(data["findings"]), 9)
        code, out, _ = self.run_cli([root, "--ignore-rules", "RS-SEC-006", "--format", "json"])
        self.assertNotIn("RS-SEC-006", {f["rule_id"] for f in json.loads(out)["findings"]})
        findings = self.scan_files({"server.js": src}, {"severity_overrides": {"RS-SEC-006": "low"}})
        self.assertTrue(all(f.severity == "low" for f in self.by_rule(findings, "RS-SEC-006")))
        suppressed = src.replace("rejectUnauthorized: false });", "rejectUnauthorized: false }); // reposentry: ignore RS-SEC-006")
        findings = self.scan_files({"server.js": suppressed})
        self.assertNotIn(4, [f.line for f in self.by_rule(findings, "RS-SEC-006")])
        baseline = os.path.join(root, "baseline.json")
        self.assertEqual(self.run_cli([root, "--rules", "RS-SEC-006", "--write-baseline", baseline])[0], 1)
        code, out, _ = self.run_cli([root, "--rules", "RS-SEC-006", "--baseline", baseline, "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["summary"]["total"], 0)

    def test_json_identical_across_runs_and_crlf(self):
        files = {"a.ts": "import { b } from './b';\nfunction f(x) {\n  if (x) { eval(x); }\n  try { g(); } catch (e) {}\n}\n",
                 "b.ts": "import { a } from './a';\nexport const b = 1;\n"}
        root_lf = self.make_project(files)
        root_crlf = self.make_project({k: v.replace("\n", "\r\n") for k, v in files.items()})
        out1 = self.run_cli([root_lf, "--format", "json"])[1]
        out2 = self.run_cli([root_lf, "--format", "json"])[1]
        out3 = self.run_cli([root_crlf, "--format", "json"])[1]
        self.assertEqual(out1, out2)
        self.assertEqual(out1, out3)
        findings = json.loads(out1)["findings"]
        self.assertEqual(sorted((f["rule_id"], f["file"], f["line"]) for f in findings),
                         [("RS-ARCH-001", "a.ts", 1), ("RS-QUAL-004", "a.ts", 4), ("RS-SEC-004", "a.ts", 3)])

    def test_pathological_inputs_finish_quickly(self):
        import time as _time
        files = {"parens.js": "f" + "(" * 200000 + ")" * 200000 + ";\n",
                 "oneline.js": "var x = 1;" + " x = x + 1;" * 90000 + "\n",
                 "template.js": "const t = `never closed ${a + b\nfunction f() { if (x) { eval(x); } }\n",
                 "binary.js": b"\x00\x01\x02eval(x)\n",
                 "braces.js": "{" * 100000 + "}" * 100000 + "\n"}
        root = self.make_project(files)
        started = _time.time()
        result = scan(root)
        self.assertLess(_time.time() - started, 5.0)
        self.assertEqual(self.by_rule(result.findings, "RS-SYS-001"), [])
        self.assertEqual(result.scanned_files, 4)

    def test_untokenizable_file_yields_sys_finding_and_scan_continues(self):
        from unittest import mock
        root = self.make_project({"bad.js": "const a = 1;\n", "good.js": "eval(x);\n"})
        original = js_mask

        def boom(text, jsx=True):
            if "const a" in text:
                raise ValueError("synthetic tokenizer failure")
            return original(text, jsx)

        with mock.patch.dict(globals(), {"js_mask": boom}):
            findings = scan(root).findings
        self.assertEqual([f.file for f in self.by_rule(findings, "RS-SYS-001")], ["bad.js"])
        self.assertEqual(self.by_rule(findings, "RS-SYS-001")[0].severity, "low")
        self.assertEqual([f.file for f in self.by_rule(findings, "RS-SEC-004")], ["good.js"])

    def test_declaration_minified_and_ignored_dirs_skipped(self):
        branches = "".join("  if (x === %d) { return %d; }\n" % (i, i) for i in range(12))
        src = "function big(x) {\n%s  return eval(x);\n}\n" % branches
        files = {"types.d.ts": src, "bundle.min.js": src, "app.js.map": "{\"mappings\": \"%s\"}\n" % ("AAAA" * 30),
                 "coverage/lcov.js": src, ".next/x.js": src, "out/y.js": src, "src/real.js": src,
                 "packed.js": "var a=1;" + "a=a+1;" * 400 + "eval(x);\n"}
        root = self.make_project(files)
        result = scan(root)
        self.assertEqual({f.file for f in result.findings}, {"src/real.js"})
        self.assertEqual({f.rule_id for f in result.findings}, {"RS-QUAL-001", "RS-SEC-004"})

    def test_dogfood_express_project(self):
        branches = "".join("  if (kind === %d) { return %d; }\n" % (i, i) for i in range(25))
        files = {
            "package.json": '{"name": "demo", "dependencies": {"express": "^4.18.0"}}\n',
            "app.js": ("const express = require('express');\nconst routes = require('./routes');\n"
                       "const config = require('./config');\nconst app = express();\napp.use(routes);\n"
                       "app.listen(config.port);\n"),
            "config.js": "module.exports = { port: 3000, name: 'demo' };\n",
            "routes.js": ("const { exec } = require('child_process');\nconst { Router } = require('express');\n"
                          "const { helper } = require('./utils');\nconst router = Router();\n"
                          "router.get('/run', (req, res) => {\n  exec(req.query.cmd, (err, out) => res.send(helper(out)));\n});\n"
                          "module.exports = router;\n"),
            "utils.js": ("const routes = require('./routes');\nfunction classify(kind) {\n%s  return -1;\n}\n"
                         "function helper(out) { return String(out); }\nmodule.exports = { classify, helper, routes };\n" % branches),
            "db.js": ("const { connect } = require('./config');\nasync function init() {\n  try {\n    await connect();\n"
                      "  } catch (e) {}\n}\nmodule.exports = { init };\n"),
            "middleware/auth.js": ("module.exports = function auth(req, res, next) {\n  if (!req.headers.authorization) {\n"
                                   "    return res.status(401).end();\n  }\n  next();\n};\n"),
        }
        findings = self.scan_files(files)
        self.assertEqual(sorted({(f.rule_id, f.file) for f in findings}),
                         [("RS-ARCH-001", "routes.js"), ("RS-QUAL-001", "utils.js"), ("RS-QUAL-004", "db.js"),
                          ("RS-SEC-003", "routes.js")])
        self.assertEqual(len(findings), 4)
        sec = self.by_rule(findings, "RS-SEC-003")[0]
        self.assertEqual((sec.severity, sec.line), ("critical", 6))
        self.assertIn("routes -> utils -> routes", self.by_rule(findings, "RS-ARCH-001")[0].message)


if __name__ == "__main__":
    sys.exit(main())
