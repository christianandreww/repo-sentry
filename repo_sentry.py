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

__version__ = "1.4.1"
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
         "python, js"),
    Rule("RS-ASYNC-002", "Fire-and-forget task", "medium", "async",
         "asyncio.create_task / ensure_future / loop.create_task whose result is "
         "discarded or stored in a variable that is never awaited, gathered, returned "
         "or given add_done_callback. Such tasks can be garbage-collected mid-flight and "
         "their exceptions are silently lost.",
         "Keep a strong reference and await/gather the task, use asyncio.TaskGroup, or "
         "attach add_done_callback to surface exceptions.",
         "python, js"),
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
         "python, js"),
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
         "JS/TS: parser-based, with heuristic fallback (pattern-based, approximate, confidence low/medium) "
         "for files the parser cannot handle. TLS verification disabled (rejectUnauthorized: false, "
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
COMMENT_PREFIXES = ("#", "//", "/*", "*", "--", ";", "<!--", "{/*")
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
        # Lines whose directive is the whole line (a comment on its own). Only these also cover the NEXT
        # line; a trailing comment after code covers its own line only.
        self.standalone_directives: Set[int] = set()
        for idx, line in enumerate(self.lines, 1):
            if "reposentry" in line.lower():
                m = DIRECTIVE_RE.search(line)
                if m:
                    ids = set(RULE_ID_RE.findall(m.group(1) or ""))
                    self.directives[idx] = {i.upper() for i in ids} if ids else {"*"}
                    if line.lstrip().startswith(COMMENT_PREFIXES):
                        self.standalone_directives.add(idx)

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
            if ln != line and ln not in self.standalone_directives:
                continue
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
                         "PEM private key block detected (%d lines, redacted)" % n_lines,
                         "-----BEGIN PRIVATE KEY----- … %d line(s) redacted … -----END PRIVATE KEY-----" % n_lines,  # reposentry: ignore RS-SEC-001
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
# JavaScript / TypeScript: tokenizer and parser (ES2023 + TypeScript syntax)
# --------------------------------------------------------------------------
class JsToken:
    __slots__ = ("kind", "value", "start", "end", "line", "col", "nl")

    def __init__(self, kind: str, value: str, start: int, end: int, line: int, col: int, nl: bool) -> None:
        self.kind = kind      # name | num | str | tpl | regex | punct | priv | jsxtext | bad | eof
        self.value = value    # identifier text, operator text, raw literal (strings keep their quotes)
        self.start = start
        self.end = end
        self.line = line
        self.col = col
        self.nl = nl          # a line break precedes this token

    def __repr__(self) -> str:
        return "JsToken(%s %r @%d:%d)" % (self.kind, self.value, self.line, self.col)


_JS_TRIVIA = r"(?:[ \t\r\f\v ﻿  \n]+|//[^\n]*|/\*(?:.*?\*/|.*))*"
_JS_SKIP_RE = re.compile(_JS_TRIVIA, re.DOTALL)
_JS_COMMENT_RE = re.compile(r"//[^\n]*|/\*(?:.*?\*/|.*)", re.DOTALL)
# trivia and the next token in one match; the token start is m.start(m.lastgroup)
_JS_TOKEN_RE = re.compile(_JS_TRIVIA + r"""(?:
 (?P<name>[A-Za-z_$\u0080-￿][\w$\u0080-￿]*)
|(?P<num>0[xX][\da-fA-F_]+n?|0[oO][0-7_]+n?|0[bB][01_]+n?|(?:\d[\d_]*(?:\.[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?n?)
|(?P<str>"(?:[^"\\\n]|\\(?:\r\n|.))*"|'(?:[^'\\\n]|\\(?:\r\n|.))*')
|(?P<priv>\#[A-Za-z_$\u0080-￿][\w$\u0080-￿]*)
|(?P<punct>\.\.\.|\?\?=|\?\.(?!\d)|\?\?|=>|===|!==|==|!=|<=|\*\*=|\*\*|\+\+|--|&&=|\|\|=|&&|\|\||<<=|<<|[-+*/%&|^]=|[{}()\[\];,<>+\-*/%&|^!~?:=.@#\\])
|(?P<eof>$)
)""", re.VERBOSE | re.DOTALL)
_JS_TPL_PART_RE = re.compile(r"(?:[^`\\$]|\\.|\$(?!\{))*", re.DOTALL)
_JS_REGEX_BODY_RE = re.compile(r"/(?:[^/\\\[\n]|\\[^\n]|\[(?:[^\]\\\n]|\\[^\n])*\])+/[A-Za-z]*")
_JS_JSX_TEXT_RE = re.compile(r"[^{<]+")
_JS_JSX_TAG_TOKEN_RE = re.compile(r"(?P<name>[A-Za-z_$\u0080-￿][\w$\u0080-￿\-]*)|(?P<str>\"[^\"]*\"|'[^']*')|(?P<punct>[{}<>/=.:])")
_JS_UNTERMINATED_STR_RE = re.compile(r"[^\n]*")


class JsLexer:
    """Parser-driven tokenizer. `scan()` reads the next token in expression/
    statement context (a `/` is a division); the parser re-scans a `/` as a
    regex, a `}` as a template continuation and switches into JSX modes when
    its grammar says so. Comments are kept as trivia spans. Never raises."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.n = len(text)
        self.pos = 0
        self.line = 1
        self.line_start = 0
        self.comments: List[Tuple[int, int]] = []
        self.errors: List[Tuple[int, int, str]] = []
        if text.startswith("#!"):
            nl = text.find("\n")
            self.pos = self.n if nl == -1 else nl

    # -- state for speculative parsing ------------------------------------
    def snapshot(self) -> Tuple[int, int, int, int, int]:
        return (self.pos, self.line, self.line_start, len(self.comments), len(self.errors))

    def restore(self, state: Tuple[int, int, int, int, int]) -> None:
        self.pos, self.line, self.line_start = state[0], state[1], state[2]
        del self.comments[state[3]:]
        del self.errors[state[4]:]

    def _skip(self) -> bool:
        """Skip whitespace and comments; returns True when a newline was crossed."""
        text = self.text
        a = self.pos
        m = _JS_SKIP_RE.match(text, a)
        b = m.end()
        if b == a:
            return False
        nl = False
        k = text.count("\n", a, b)
        if k:
            self.line += k
            self.line_start = text.rfind("\n", a, b) + 1
            nl = True
        if text.find("/", a, b) != -1:
            for cm in _JS_COMMENT_RE.finditer(text, a, b):
                self.comments.append((cm.start(), cm.end()))
        self.pos = b
        return nl

    def scan(self) -> JsToken:
        text = self.text
        a = self.pos
        m = _JS_TOKEN_RE.match(text, a)
        nl = False
        if m is None:
            # trivia followed by a character no token starts with (unterminated string, backtick, stray byte)
            nl = self._skip()
            pos = self.pos
            line, col = self.line, pos - self.line_start + 1
            if pos >= self.n:
                return JsToken("eof", "", pos, pos, line, col, nl)
            c = text[pos]
            if c in "\"'":  # unterminated string: runs to the end of the line
                e = _JS_UNTERMINATED_STR_RE.match(text, pos).end()
                self.errors.append((line, col, "unterminated string literal"))
                self.pos = e
                return JsToken("str", text[pos:e] + c, pos, e, line, col, nl)
            if c == "`":
                return self._scan_template(pos, pos + 1, line, col, nl)
            self.pos = pos + 1
            return JsToken("bad", c, pos, pos + 1, line, col, nl)
        kind = m.lastgroup
        pos = m.start(kind)
        if pos > a:
            k = text.count("\n", a, pos)
            if k:
                self.line += k
                self.line_start = text.rfind("\n", a, pos) + 1
                nl = True
            if text.find("/", a, pos) != -1:
                for cm in _JS_COMMENT_RE.finditer(text, a, pos):
                    self.comments.append((cm.start(), cm.end()))
        e = m.end()
        self.pos = e
        line, col = self.line, pos - self.line_start + 1
        if kind == "str":
            value = m.group(kind)
            if "\\" in value and "\n" in value:  # line continuations
                self.line += value.count("\n")
                self.line_start = text.rfind("\n", pos, e) + 1
            return JsToken("str", value, pos, e, line, col, nl)
        return JsToken(kind, m.group(kind), pos, e, line, col, nl)

    def _scan_template(self, start: int, body_start: int, line: int, col: int, nl: bool) -> JsToken:
        """A template chunk starting after '`' or after the `}` of a substitution.
        The token value is the raw chunk; `kind` is "tpl" and the value's last
        character tells how it ended: appended "`" (tail) or "$" (head/middle)."""
        text = self.text
        m = _JS_TPL_PART_RE.match(text, body_start)
        e = m.end()
        chunk = text[body_start:e]
        k = chunk.count("\n")
        if k:
            self.line += k
            self.line_start = text.rfind("\n", body_start, e) + 1
        if e >= self.n:
            self.errors.append((line, col, "unterminated template literal"))
            self.pos = self.n
            return JsToken("tpl", chunk + "`", start, self.n, line, col, nl)
        if text[e] == "`":
            self.pos = e + 1
            return JsToken("tpl", chunk + "`", start, e + 1, line, col, nl)
        self.pos = e + 2  # `${`
        return JsToken("tpl", chunk + "$", start, e + 2, line, col, nl)

    def rescan_template_continuation(self, tok: JsToken) -> JsToken:
        """`tok` is the `}` closing a `${ ... }` substitution."""
        return self._scan_template(tok.start, tok.start + 1, tok.line, tok.col, tok.nl)

    def rescan_backtick(self, tok: JsToken) -> JsToken:
        return self._scan_template(tok.start, tok.start + 1, tok.line, tok.col, tok.nl)

    def rescan_regex(self, tok: JsToken) -> JsToken:
        """`tok` is a `/` or `/=` punct in operand position."""
        text = self.text
        m = _JS_REGEX_BODY_RE.match(text, tok.start)
        if m is None:
            e = _JS_UNTERMINATED_STR_RE.match(text, tok.start).end()
            self.errors.append((tok.line, tok.col, "unterminated regular expression"))
            self.pos = e
            return JsToken("regex", text[tok.start:e], tok.start, e, tok.line, tok.col, tok.nl)
        self.pos = m.end()
        return JsToken("regex", m.group(), tok.start, m.end(), tok.line, tok.col, tok.nl)

    def rescan_greater(self, tok: JsToken, op: str) -> None:
        """`tok` is a single `>`; the parser merged it into `op` (e.g. `>>=`)."""
        self.pos = tok.start + len(op)

    def scan_jsx_text(self) -> JsToken:
        """From the current position: JSX child text up to `{` or `<`, or that punct."""
        text = self.text
        pos = self.pos
        line, col = self.line, pos - self.line_start + 1
        if pos >= self.n:
            return JsToken("eof", "", pos, pos, line, col, False)
        m = _JS_JSX_TEXT_RE.match(text, pos)
        if m is None:
            self.pos = pos + 1
            return JsToken("punct", text[pos], pos, pos + 1, line, col, False)
        e = m.end()
        k = text.count("\n", pos, e)
        if k:
            self.line += k
            self.line_start = text.rfind("\n", pos, e) + 1
        self.pos = e
        return JsToken("jsxtext", m.group(), pos, e, line, col, False)

    def scan_jsx_tag(self) -> JsToken:
        """Token inside `<Tag ...>`: names may contain `-`, strings have no escapes."""
        nl = self._skip()
        text = self.text
        pos = self.pos
        line, col = self.line, pos - self.line_start + 1
        if pos >= self.n:
            return JsToken("eof", "", pos, pos, line, col, nl)
        m = _JS_JSX_TAG_TOKEN_RE.match(text, pos)
        if m is None:
            self.pos = pos + 1
            return JsToken("bad", text[pos], pos, pos + 1, line, col, nl)
        e = m.end()
        kind = m.lastgroup
        if kind == "str":
            k = text.count("\n", pos, e)
            if k:
                self.line += k
                self.line_start = text.rfind("\n", pos, e) + 1
        self.pos = e
        return JsToken(kind, m.group(), pos, e, line, col, nl)


class JsNode:
    """Lightweight ESTree-like node. Fields live in `fields` and are also
    readable as attributes (`node.callee`)."""
    __slots__ = ("type", "start", "end", "line", "col", "fields")

    def __init__(self, type_: str, start: int, line: int, col: int, fields: Optional[Dict[str, object]] = None) -> None:
        self.fields: Dict[str, object] = fields if fields is not None else {}
        self.type = type_
        self.start = start
        self.end = start
        self.line = line
        self.col = col

    def __getattr__(self, name: str) -> object:
        try:
            return self.fields[name]
        except KeyError:
            raise AttributeError(name) from None

    def get(self, name: str, default: object = None) -> object:
        return self.fields.get(name, default)

    def __repr__(self) -> str:
        return "JsNode(%s @%d:%d)" % (self.type, self.line, self.col)


def js_children(node: JsNode) -> List[JsNode]:
    """Direct child nodes in source order of the fields (deterministic)."""
    out: List[JsNode] = []
    for value in node.fields.values():
        if isinstance(value, JsNode):
            out.append(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, JsNode):
                    out.append(item)
    return out


def js_walk(root: JsNode) -> Iterator[JsNode]:
    """Iterative pre-order traversal (no recursion)."""
    stack = [root]
    pop = stack.pop
    push = stack.append
    while stack:
        node = pop()
        yield node
        kids = js_children(node)
        for i in range(len(kids) - 1, -1, -1):
            push(kids[i])


class _JsParseError(Exception):
    def __init__(self, line: int, col: int, message: str) -> None:
        Exception.__init__(self, message)
        self.line = line
        self.col = col


class _JsParseAbort(Exception):
    """Unrecoverable: nesting too deep or too many errors; the file falls back."""


JS_PARSER_MAX_DEPTH = 400
_JS_RESERVED = frozenset((
    "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else",
    "enum", "export", "extends", "false", "finally", "for", "function", "if", "import", "in", "instanceof",
    "new", "null", "return", "super", "switch", "this", "throw", "true", "try", "typeof", "var", "void",
    "while", "with",
))
_JS_STMT_KEYWORDS = frozenset((
    "function", "class", "const", "let", "var", "if", "for", "while", "do", "return", "import", "export", "try",
    "switch", "throw", "async", "interface", "type", "enum", "declare", "namespace", "abstract", "break",
    "continue",
))
_JS_BINARY_PREC: Dict[str, int] = {
    "??": 1, "||": 2, "&&": 3, "|": 4, "^": 5, "&": 6,
    "==": 7, "!=": 7, "===": 7, "!==": 7,
    "<": 8, ">": 8, "<=": 8, ">=": 8, "instanceof": 8, "in": 8, "as": 8, "satisfies": 8,
    "<<": 9, ">>": 9, ">>>": 9,
    "+": 10, "-": 10, "*": 11, "/": 11, "%": 11, "**": 12,
}
_JS_ASSIGN_OPS = frozenset(("=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=",
                            "&&=", "||=", "??="))
_JS_GREATER_RE = re.compile(r">>>=|>>>|>>=|>>|>=|>")
_JS_ARROW_AHEAD_RE = re.compile(r"(?:[ \t\r\f\v]|//[^\n]*|/\*.*?\*/)*=>", re.DOTALL)
_JS_TSX_GENERIC_ARROW_RE = re.compile(r"\s*(?:const\s+)?[A-Za-z_$][\w$]*\s*(?:,|extends\b|=[^=>])")
_JS_TS_TYPE_KEYWORDS = frozenset(("string", "number", "boolean", "any", "unknown", "never", "void", "null",
                                  "undefined", "object", "symbol", "bigint", "this", "true", "false"))
_JS_MODIFIERS = frozenset(("public", "private", "protected", "static", "readonly", "abstract", "override",
                           "declare", "async", "get", "set", "accessor"))


class JsParser:
    """Hand-written recursive-descent parser with precedence climbing. Errors
    are recorded and recovered at statement boundaries; nesting deeper than
    JS_PARSER_MAX_DEPTH or too many errors raise _JsParseAbort."""

    def __init__(self, text: str, ts: bool, jsx: bool, max_errors: int) -> None:
        self.text = text
        self.ts = ts
        self.jsx = jsx
        self.lexer = JsLexer(text)
        self.errors: List[Tuple[int, int, str]] = []
        self.max_errors = max_errors
        self.depth = 0
        self.brace_depth = 0
        self.speculating = 0
        self.failed_arrow: Set[int] = set()
        self.failed_typeargs: Set[int] = set()
        self.prev_end = 0
        self.tok: JsToken = self.lexer.scan()

    # -- token helpers ------------------------------------------------------
    def next(self) -> JsToken:
        tok = self.tok
        self.prev_end = tok.end
        if tok.kind == "punct":
            v = tok.value
            if v == "{":
                self.brace_depth += 1
            elif v == "}":
                self.brace_depth -= 1
        self.tok = self.lexer.scan()
        return tok

    def is_p(self, value: str) -> bool:
        t = self.tok
        return t.kind == "punct" and t.value == value

    def is_n(self, value: str) -> bool:
        t = self.tok
        return t.kind == "name" and t.value == value

    def eat(self, value: str) -> bool:
        t = self.tok
        if t.kind == "punct" and t.value == value:
            self.next()
            return True
        return False

    def eat_name(self, value: str) -> bool:
        t = self.tok
        if t.kind == "name" and t.value == value:
            self.next()
            return True
        return False

    def error(self, message: Optional[str] = None, tok: Optional[JsToken] = None) -> "_JsParseError":
        t = tok or self.tok
        if message is None:
            message = "unexpected end of input" if t.kind == "eof" else "unexpected token %r" % t.value[:20]
        return _JsParseError(t.line, t.col, message)

    def expect(self, value: str) -> JsToken:
        t = self.tok
        if t.kind == "punct" and t.value == value:
            return self.next()
        raise self.error("expected '%s'" % value)

    def expect_name(self, value: str) -> JsToken:
        t = self.tok
        if t.kind == "name" and t.value == value:
            return self.next()
        raise self.error("expected '%s'" % value)

    def semicolon(self) -> None:
        t = self.tok
        if t.kind == "punct":
            if t.value == ";":
                self.next()
                return
            if t.value == "}":
                return
        if t.nl or t.kind == "eof":
            return
        raise self.error("expected ';'")

    def node(self, type_: str, tok: Optional[JsToken] = None, **fields: object) -> JsNode:
        t = tok or self.tok
        return JsNode(type_, t.start, t.line, t.col, fields)

    def finish(self, node: JsNode) -> JsNode:
        node.end = self.prev_end
        return node

    def enter(self) -> None:
        self.depth += 1
        if self.depth > JS_PARSER_MAX_DEPTH:
            raise _JsParseAbort("nesting deeper than %d" % JS_PARSER_MAX_DEPTH)

    def leave(self) -> None:
        self.depth -= 1

    def peek(self) -> JsToken:
        """Look one token ahead (default mode) without consuming."""
        state = self.lexer.snapshot()
        t = self.lexer.scan()
        self.lexer.restore(state)
        return t

    def peek_is_name_like(self) -> bool:
        """The next token can be a property/binding name (name, string, number, [ or #private)."""
        t = self.peek()
        if t.kind in ("name", "str", "num", "priv"):
            return True
        return t.kind == "punct" and t.value == "["

    def is_identifier_tok(self, t: Optional[JsToken] = None) -> bool:
        t = t or self.tok
        return t.kind == "name" and t.value not in _JS_RESERVED

    def identifier(self) -> JsNode:
        t = self.tok
        if t.kind != "name" or t.value in _JS_RESERVED:
            raise self.error("expected identifier")
        self.next()
        return self.finish(JsNode("Identifier", t.start, t.line, t.col, {"name": t.value}))

    # -- speculation --------------------------------------------------------
    def _snapshot(self) -> tuple:
        return (self.lexer.snapshot(), self.tok, self.prev_end, self.brace_depth, len(self.errors), self.depth)

    def _restore(self, state: tuple) -> None:
        self.lexer.restore(state[0])
        self.tok, self.prev_end, self.brace_depth, self.depth = state[1], state[2], state[3], state[5]
        del self.errors[state[4]:]

    # -- program and statements --------------------------------------------
    def parse_program(self) -> JsNode:
        prog = self.node("Program", body=[])
        prog.fields["body"] = self.parse_statement_list(top=True)
        return self.finish(prog)

    def parse_statement_list(self, top: bool = False) -> List[JsNode]:
        body: List[JsNode] = []
        base = self.brace_depth
        depth = self.depth
        while True:
            t = self.tok
            if t.kind == "eof":
                break
            if t.kind == "punct" and t.value == "}" and not top:
                break
            start_tok = t
            try:
                if t.kind == "punct" and t.value == "}":
                    raise self.error("unexpected '}'")
                body.append(self.parse_statement())
            except _JsParseError as exc:
                self.depth = depth
                self.record_error(exc)
                self.recover(base)
                if self.tok is start_tok:
                    self.next()  # guarantee progress
        return body

    def record_error(self, exc: "_JsParseError") -> None:
        if self.speculating:
            raise exc
        self.errors.append((exc.line, exc.col, str(exc)))
        if len(self.errors) > self.max_errors:
            raise _JsParseAbort("too many syntax errors")

    def recover(self, base: int) -> None:
        """Skip to the next statement boundary: `;` at the statement's brace
        depth (consumed), `}` closing the enclosing block (left for the
        caller), or a line break followed by a statement keyword."""
        while True:
            t = self.tok
            if t.kind == "eof":
                return
            if self.brace_depth <= base:
                if t.kind == "punct":
                    if t.value == ";":
                        self.next()
                        return
                    if t.value == "}":
                        if self.brace_depth < base:
                            self.next()
                            continue
                        return
                elif t.kind == "name" and t.nl and t.value in _JS_STMT_KEYWORDS:
                    return
            self.next()

    def parse_statement(self) -> JsNode:
        self.depth += 1
        if self.depth > JS_PARSER_MAX_DEPTH:
            raise _JsParseAbort("nesting deeper than %d" % JS_PARSER_MAX_DEPTH)
        node = self._parse_statement()
        self.depth -= 1
        return node

    def _parse_statement(self) -> JsNode:
        t = self.tok
        kind = t.kind
        if kind == "punct":
            v = t.value
            if v == "{":
                return self.parse_block()
            if v == ";":
                self.next()
                return self.finish(self.node("EmptyStatement", t))
            if v == "@":
                self.parse_decorators()
                return self._parse_statement()
        elif kind == "name":
            v = t.value
            handler = _JS_STATEMENT_DISPATCH.get(v)
            if handler is not None:
                result = handler(self)
                if result is not None:
                    return result
            elif v not in _JS_RESERVED and _JS_LABEL_AHEAD_RE.match(self.text, t.end):
                p = self.peek()
                if p.kind == "punct" and p.value == ":":
                    self.next()
                    self.next()
                    node = self.node("LabeledStatement", t, label=t.value)
                    node.fields["body"] = self.parse_statement()
                    return self.finish(node)
        expr = self.parse_expression()
        node = JsNode("ExpressionStatement", t.start, t.line, t.col, {"expression": expr})
        self.semicolon()
        return self.finish(node)

    def parse_block(self) -> JsNode:
        node = self.node("BlockStatement", body=[])
        self.expect("{")
        node.fields["body"] = self.parse_statement_list()
        self.expect("}")
        return self.finish(node)

    def parse_decorators(self) -> List[JsNode]:
        out: List[JsNode] = []
        while self.is_p("@"):
            self.next()
            out.append(self.parse_lhs_expression(allow_call=True))
        return out

    # statement handlers (return None when the keyword is actually an identifier)
    def stmt_var(self) -> Optional[JsNode]:
        t = self.tok
        if t.value == "let" and not self._let_is_declaration():
            return None  # `let` used as an identifier
        node = self.parse_var_declaration(in_for=False)
        self.semicolon()
        return self.finish(node)

    def _let_is_declaration(self) -> bool:
        """`let` starts a declaration when a binding (name, `[` or `{`) follows."""
        p = self.peek()
        if p.kind == "name":
            return p.value not in ("in", "instanceof")
        return p.kind == "punct" and p.value in ("[", "{")

    def parse_var_declaration(self, in_for: bool) -> JsNode:
        t = self.next()
        node = self.node("VariableDeclaration", t, kind=t.value, declarations=[])
        decls: List[JsNode] = node.fields["declarations"]  # type: ignore[assignment]
        while True:
            d = self.node("VariableDeclarator")
            d.fields["id"] = self.parse_binding_target(allow_annotation=True)
            if self.eat("="):
                d.fields["init"] = self.parse_assignment(no_in=in_for)
            else:
                d.fields["init"] = None
            decls.append(self.finish(d))
            if not self.eat(","):
                break
        return self.finish(node)

    def stmt_function(self) -> JsNode:
        return self.parse_function(declaration=True, is_async=False)

    def stmt_async(self) -> Optional[JsNode]:
        p = self.peek()
        if p.kind == "name" and p.value == "function" and not p.nl:
            self.next()
            return self.parse_function(declaration=True, is_async=True)
        return None

    def stmt_class(self) -> JsNode:
        return self.parse_class(declaration=True)

    def stmt_if(self) -> JsNode:
        node = self.node("IfStatement")
        self.next()
        self.expect("(")
        node.fields["test"] = self.parse_expression()
        self.expect(")")
        node.fields["consequent"] = self.parse_statement()
        if self.eat_name("else"):
            node.fields["alternate"] = self.parse_statement()
        else:
            node.fields["alternate"] = None
        return self.finish(node)

    def stmt_for(self) -> JsNode:
        start = self.tok
        self.next()
        is_await = self.eat_name("await")
        self.expect("(")
        init: Optional[JsNode] = None
        t = self.tok
        if t.kind == "punct" and t.value == ";":
            pass
        elif t.kind == "name" and (t.value in ("var", "const") or (t.value == "let" and self._let_is_declaration())):
            init = self.parse_var_declaration(in_for=True)
        else:
            init = self.parse_expression(no_in=True)
        if init is not None and self.tok.kind == "name" and self.tok.value in ("of", "in"):
            kind = "ForOfStatement" if self.tok.value == "of" else "ForInStatement"
            self.next()
            node = self.node(kind, start, left=self.to_pattern(init) if init.type != "VariableDeclaration" else init)
            node.fields["right"] = self.parse_assignment() if kind == "ForOfStatement" else self.parse_expression()
            node.fields["await"] = is_await
            self.expect(")")
            node.fields["body"] = self.parse_statement()
            return self.finish(node)
        node = self.node("ForStatement", start, init=init)
        self.expect(";")
        node.fields["test"] = None if self.is_p(";") else self.parse_expression()
        self.expect(";")
        node.fields["update"] = None if self.is_p(")") else self.parse_expression()
        self.expect(")")
        node.fields["body"] = self.parse_statement()
        return self.finish(node)

    def stmt_while(self) -> JsNode:
        node = self.node("WhileStatement")
        self.next()
        self.expect("(")
        node.fields["test"] = self.parse_expression()
        self.expect(")")
        node.fields["body"] = self.parse_statement()
        return self.finish(node)

    def stmt_do(self) -> JsNode:
        node = self.node("DoWhileStatement")
        self.next()
        node.fields["body"] = self.parse_statement()
        self.expect_name("while")
        self.expect("(")
        node.fields["test"] = self.parse_expression()
        self.expect(")")
        self.eat(";")
        return self.finish(node)

    def stmt_return(self) -> JsNode:
        node = self.node("ReturnStatement")
        self.next()
        t = self.tok
        if t.nl or t.kind == "eof" or (t.kind == "punct" and t.value in (";", "}")):
            node.fields["argument"] = None
        else:
            node.fields["argument"] = self.parse_expression()
        self.semicolon()
        return self.finish(node)

    def stmt_jump(self) -> JsNode:
        t = self.next()
        node = self.node("BreakStatement" if t.value == "break" else "ContinueStatement", t)
        if self.tok.kind == "name" and not self.tok.nl and self.tok.value not in _JS_RESERVED:
            node.fields["label"] = self.next().value
        else:
            node.fields["label"] = None
        self.semicolon()
        return self.finish(node)

    def stmt_throw(self) -> JsNode:
        node = self.node("ThrowStatement")
        self.next()
        node.fields["argument"] = self.parse_expression()
        self.semicolon()
        return self.finish(node)

    def stmt_try(self) -> JsNode:
        node = self.node("TryStatement")
        self.next()
        node.fields["block"] = self.parse_block()
        node.fields["handler"] = None
        node.fields["finalizer"] = None
        if self.is_n("catch"):
            h = self.node("CatchClause")
            self.next()
            if self.eat("("):
                h.fields["param"] = self.parse_binding_target(allow_annotation=True)
                self.expect(")")
            else:
                h.fields["param"] = None
            h.fields["body"] = self.parse_block()
            node.fields["handler"] = self.finish(h)
        if self.eat_name("finally"):
            node.fields["finalizer"] = self.parse_block()
        if node.fields["handler"] is None and node.fields["finalizer"] is None:
            raise self.error("expected 'catch' or 'finally'")
        return self.finish(node)

    def stmt_switch(self) -> JsNode:
        node = self.node("SwitchStatement", cases=[])
        self.next()
        self.expect("(")
        node.fields["discriminant"] = self.parse_expression()
        self.expect(")")
        self.expect("{")
        cases: List[JsNode] = node.fields["cases"]  # type: ignore[assignment]
        base = self.brace_depth
        depth = self.depth
        while not self.is_p("}") and self.tok.kind != "eof":
            c = self.node("SwitchCase", consequent=[])
            try:
                if self.eat_name("case"):
                    c.fields["test"] = self.parse_expression()
                elif self.eat_name("default"):
                    c.fields["test"] = None
                else:
                    raise self.error("expected 'case' or 'default'")
                self.expect(":")
            except _JsParseError as exc:
                self.depth = depth
                self.record_error(exc)
                self.recover(base)
                if self.is_p("}") or self.tok.kind == "eof":
                    break
                continue
            cons: List[JsNode] = c.fields["consequent"]  # type: ignore[assignment]
            while not self.is_p("}") and self.tok.kind != "eof" and not (self.tok.kind == "name" and self.tok.value in ("case", "default")):
                start_tok = self.tok
                try:
                    cons.append(self.parse_statement())
                except _JsParseError as exc:
                    self.depth = depth
                    self.record_error(exc)
                    self.recover(base)
                    if self.tok is start_tok:
                        self.next()
            cases.append(self.finish(c))
        self.expect("}")
        return self.finish(node)

    def stmt_with(self) -> JsNode:
        node = self.node("WithStatement")
        self.next()
        self.expect("(")
        node.fields["object"] = self.parse_expression()
        self.expect(")")
        node.fields["body"] = self.parse_statement()
        return self.finish(node)

    def stmt_debugger(self) -> JsNode:
        node = self.node("DebuggerStatement")
        self.next()
        self.semicolon()
        return self.finish(node)

    # -- modules ------------------------------------------------------------
    def parse_string_literal(self) -> JsNode:
        t = self.tok
        if t.kind != "str":
            raise self.error("expected string literal")
        self.next()
        return self.finish(JsNode("Literal", t.start, t.line, t.col,
                                  {"value": _js_unquote(t.value), "raw": t.value, "kind": "string"}))

    def parse_module_specifier_name(self) -> str:
        t = self.tok
        if t.kind == "name":
            self.next()
            return t.value
        if t.kind == "str":
            self.next()
            return _js_unquote(t.value)
        raise self.error("expected module export name")

    def parse_import_attributes(self) -> None:
        if (self.is_n("with") or self.is_n("assert")) and not self.tok.nl:
            self.next()
            self.parse_object_expression()

    def stmt_import(self) -> Optional[JsNode]:
        p = self.peek()
        if p.kind == "punct" and p.value in ("(", "."):
            return None  # import(...) / import.meta expression statement
        node = self.node("ImportDeclaration", specifiers=[], typeOnly=False, source=None)
        self.next()
        specs: List[JsNode] = node.fields["specifiers"]  # type: ignore[assignment]
        if self.tok.kind == "str":
            node.fields["source"] = self.parse_string_literal()
            self.parse_import_attributes()
            self.semicolon()
            return self.finish(node)
        if self.is_n("type") and self.ts:
            p = self.peek()
            if (p.kind == "name" and p.value != "from") or (p.kind == "punct" and p.value in ("{", "*")):
                self.next()
                node.fields["typeOnly"] = True
            elif p.kind == "name" and p.value == "from":
                # `import type from './x'` imports a binding named `type`, unless followed by another `from`
                pass
        if self.is_identifier_tok() and not (self.is_n("from") and self.peek().kind == "str"):
            name_tok = self.next()
            if self.is_p("=") and self.ts:
                # import x = require('y') | import x = A.B.C
                self.next()
                node.type = "TSImportEqualsDeclaration"
                node.fields["id"] = name_tok.value
                if self.is_n("require") and self.peek().kind == "punct" and self.peek().value == "(":
                    self.next()
                    self.expect("(")
                    node.fields["source"] = self.parse_string_literal()
                    self.expect(")")
                else:
                    node.fields["reference"] = self.parse_entity_name()
                self.semicolon()
                return self.finish(node)
            specs.append(JsNode("ImportDefaultSpecifier", name_tok.start, name_tok.line, name_tok.col, {"local": name_tok.value}))
            if not self.eat(","):
                self.expect_name("from")
                node.fields["source"] = self.parse_string_literal()
                self.parse_import_attributes()
                self.semicolon()
                return self.finish(node)
        if self.eat("*"):
            self.expect_name("as")
            local = self.identifier()
            specs.append(JsNode("ImportNamespaceSpecifier", local.start, local.line, local.col, {"local": local.fields["name"]}))
        elif self.is_p("{"):
            self.next()
            while not self.is_p("}"):
                st = self.tok
                type_only = False
                if self.is_n("type") and self.ts:
                    p = self.peek()
                    if p.kind in ("name", "str") and not (p.kind == "name" and p.value == "as" and self.peek_is_as_binding()):
                        self.next()
                        type_only = True
                imported = self.parse_module_specifier_name()
                local = imported
                if self.eat_name("as"):
                    local = self.identifier().fields["name"]
                specs.append(JsNode("ImportSpecifier", st.start, st.line, st.col,
                                    {"imported": imported, "local": local, "typeOnly": type_only}))
                if not self.eat(","):
                    break
            self.expect("}")
        self.expect_name("from")
        node.fields["source"] = self.parse_string_literal()
        self.parse_import_attributes()
        self.semicolon()
        if specs and all(s.fields.get("typeOnly") for s in specs):
            node.fields["typeOnly"] = True
        return self.finish(node)

    def peek_is_as_binding(self) -> bool:
        """`import { type as as x }` / `{ type as }` edge cases: treat `type` as a name."""
        state = self.lexer.snapshot()
        self.lexer.scan()      # as
        t2 = self.lexer.scan()  # next
        self.lexer.restore(state)
        return not (t2.kind == "name" and t2.value not in ("as",))

    def parse_entity_name(self) -> str:
        parts = [self.identifier().fields["name"]]
        while self.eat("."):
            parts.append(self.next().value)
        return ".".join(str(p) for p in parts)

    def stmt_export(self) -> JsNode:
        start = self.tok
        self.next()
        t = self.tok
        if t.kind == "punct":
            if t.value == "*":
                node = self.node("ExportAllDeclaration", start, exported=None, typeOnly=False)
                self.next()
                if self.eat_name("as"):
                    node.fields["exported"] = self.parse_module_specifier_name()
                self.expect_name("from")
                node.fields["source"] = self.parse_string_literal()
                self.parse_import_attributes()
                self.semicolon()
                return self.finish(node)
            if t.value == "{":
                return self.parse_export_specifiers(start, type_only=False)
            if t.value == "=" and self.ts:
                self.next()
                node = self.node("TSExportAssignment", start)
                node.fields["expression"] = self.parse_expression()
                self.semicolon()
                return self.finish(node)
            if t.value == "@":
                self.parse_decorators()
                t = self.tok
        if t.kind == "name":
            v = t.value
            if v == "default":
                self.next()
                node = self.node("ExportDefaultDeclaration", start)
                d = self.tok
                if d.kind == "name" and d.value == "function":
                    node.fields["declaration"] = self.parse_function(declaration=True, is_async=False, allow_anonymous=True)
                elif d.kind == "name" and d.value == "async" and self.peek().kind == "name" and self.peek().value == "function":
                    self.next()
                    node.fields["declaration"] = self.parse_function(declaration=True, is_async=True, allow_anonymous=True)
                elif d.kind == "name" and d.value == "class":
                    node.fields["declaration"] = self.parse_class(declaration=True, allow_anonymous=True)
                elif d.kind == "name" and d.value == "abstract" and self.peek().kind == "name" and self.peek().value == "class":
                    self.next()
                    node.fields["declaration"] = self.parse_class(declaration=True, allow_anonymous=True)
                elif d.kind == "name" and d.value == "interface" and self.ts and self.peek().kind == "name":
                    node.fields["declaration"] = self.stmt_interface()
                elif d.kind == "punct" and d.value == "@":
                    self.parse_decorators()
                    node.fields["declaration"] = self.parse_class(declaration=True, allow_anonymous=True)
                else:
                    node.fields["declaration"] = self.parse_assignment()
                    self.semicolon()
                return self.finish(node)
            if v == "type" and self.ts and self.peek().kind == "punct" and self.peek().value in ("{", "*"):
                self.next()
                if self.is_p("*"):
                    node = self.node("ExportAllDeclaration", start, exported=None, typeOnly=True)
                    self.next()
                    if self.eat_name("as"):
                        node.fields["exported"] = self.parse_module_specifier_name()
                    self.expect_name("from")
                    node.fields["source"] = self.parse_string_literal()
                    self.semicolon()
                    return self.finish(node)
                return self.parse_export_specifiers(start, type_only=True)
            if v == "as" and self.ts:
                self.next()
                self.expect_name("namespace")
                node = self.node("TSNamespaceExportDeclaration", start, id=self.identifier().fields["name"])
                self.semicolon()
                return self.finish(node)
            if v == "import" and self.ts:
                decl = self.stmt_import()
                node = self.node("ExportNamedDeclaration", start, declaration=decl, specifiers=[], source=None, typeOnly=False)
                return self.finish(node)
        node = self.node("ExportNamedDeclaration", start, specifiers=[], source=None, typeOnly=False)
        node.fields["declaration"] = self.parse_statement()
        return self.finish(node)

    def parse_export_specifiers(self, start: JsToken, type_only: bool) -> JsNode:
        node = self.node("ExportNamedDeclaration", start, declaration=None, specifiers=[], source=None, typeOnly=type_only)
        specs: List[JsNode] = node.fields["specifiers"]  # type: ignore[assignment]
        self.expect("{")
        while not self.is_p("}"):
            st = self.tok
            spec_type_only = False
            if self.is_n("type") and self.ts and self.peek().kind in ("name", "str"):
                p = self.peek()
                if not (p.kind == "name" and p.value == "as"):
                    self.next()
                    spec_type_only = True
            local = self.parse_module_specifier_name()
            exported = local
            if self.eat_name("as"):
                exported = self.parse_module_specifier_name()
            specs.append(JsNode("ExportSpecifier", st.start, st.line, st.col,
                                {"local": local, "exported": exported, "typeOnly": spec_type_only}))
            if not self.eat(","):
                break
        self.expect("}")
        if self.eat_name("from"):
            node.fields["source"] = self.parse_string_literal()
            self.parse_import_attributes()
        self.semicolon()
        return self.finish(node)

    # -- TypeScript declarations -------------------------------------------
    def stmt_type(self) -> Optional[JsNode]:
        if not self.ts:
            return None
        p = self.peek()
        if p.kind != "name" or p.nl:
            return None
        node = self.node("TSTypeAliasDeclaration")
        self.next()
        node.fields["id"] = self.identifier().fields["name"]
        if self.is_p("<"):
            self.parse_type_parameters()
        self.expect("=")
        node.fields["typeAnnotation"] = self.parse_type()
        self.semicolon()
        return self.finish(node)

    def stmt_interface(self) -> Optional[JsNode]:
        if not self.ts:
            return None
        p = self.peek()
        if p.kind != "name" or p.nl:
            return None
        node = self.node("TSInterfaceDeclaration")
        self.next()
        node.fields["id"] = self.identifier().fields["name"]
        if self.is_p("<"):
            self.parse_type_parameters()
        if self.eat_name("extends"):
            while True:
                self.parse_type_reference_for_heritage()
                if not self.eat(","):
                    break
        node.fields["body"] = self.parse_object_type()
        return self.finish(node)

    def stmt_enum(self) -> Optional[JsNode]:
        if not self.ts:
            return None
        return self.parse_enum(self.tok)

    def parse_enum(self, start: JsToken) -> JsNode:
        node = self.node("TSEnumDeclaration", start, members=[])
        self.expect_name("enum")
        node.fields["id"] = self.identifier().fields["name"]
        self.expect("{")
        members: List[JsNode] = node.fields["members"]  # type: ignore[assignment]
        while not self.is_p("}"):
            m = self.node("TSEnumMember")
            key = self.parse_property_key()
            m.fields["id"] = key[0]
            m.fields["initializer"] = self.parse_assignment() if self.eat("=") else None
            members.append(self.finish(m))
            if not self.eat(","):
                break
        self.expect("}")
        return self.finish(node)

    def stmt_const(self) -> JsNode:
        if self.ts:
            p = self.peek()
            if p.kind == "name" and p.value == "enum":
                start = self.next()
                return self.parse_enum(start)
        return self.stmt_var()  # type: ignore[return-value]

    def stmt_declare(self) -> Optional[JsNode]:
        if not self.ts:
            return None
        p = self.peek()
        if p.nl or p.kind != "name" or p.value not in ("const", "let", "var", "function", "class", "enum", "namespace",
                                                        "module", "global", "type", "interface", "abstract", "async"):
            return None
        start = self.next()
        if self.is_n("global"):
            node = self.node("TSModuleDeclaration", start, id="global", declare=True)
            self.next()
            node.fields["body"] = self.parse_block()
            return self.finish(node)
        inner = self.parse_statement()
        inner.fields["declare"] = True
        inner.start, inner.line, inner.col = start.start, start.line, start.col
        return inner

    def stmt_namespace(self) -> Optional[JsNode]:
        if not self.ts:
            return None
        p = self.peek()
        if p.nl or p.kind not in ("name", "str"):
            return None
        node = self.node("TSModuleDeclaration", declare=False)
        self.next()
        if self.tok.kind == "str":
            node.fields["id"] = _js_unquote(self.next().value)
        else:
            node.fields["id"] = self.parse_entity_name()
        if self.is_p("{"):
            node.fields["body"] = self.parse_block()
        else:
            node.fields["body"] = None
            self.semicolon()
        return self.finish(node)

    def stmt_abstract(self) -> Optional[JsNode]:
        if not self.ts:
            return None
        p = self.peek()
        if p.kind == "name" and p.value == "class" and not p.nl:
            start = self.next()
            node = self.parse_class(declaration=True)
            node.fields["abstract"] = True
            node.start, node.line, node.col = start.start, start.line, start.col
            return node
        return None

    def stmt_global(self) -> Optional[JsNode]:
        if self.ts and self.is_p("{") is False and self.peek().kind == "punct" and self.peek().value == "{":
            node = self.node("TSModuleDeclaration", id="global", declare=True)
            self.next()
            node.fields["body"] = self.parse_block()
            return self.finish(node)
        return None


_JS_LABEL_AHEAD_RE = re.compile(r"(?:\s|//[^\n]*|/\*.*?\*/)*:", re.DOTALL)
_JS_STATEMENT_DISPATCH = {
    "var": JsParser.stmt_var, "let": JsParser.stmt_var, "const": JsParser.stmt_const,
    "function": JsParser.stmt_function, "async": JsParser.stmt_async, "class": JsParser.stmt_class,
    "if": JsParser.stmt_if, "for": JsParser.stmt_for, "while": JsParser.stmt_while, "do": JsParser.stmt_do,
    "return": JsParser.stmt_return, "break": JsParser.stmt_jump, "continue": JsParser.stmt_jump,
    "throw": JsParser.stmt_throw, "try": JsParser.stmt_try, "switch": JsParser.stmt_switch,
    "with": JsParser.stmt_with, "debugger": JsParser.stmt_debugger, "import": JsParser.stmt_import,
    "export": JsParser.stmt_export, "type": JsParser.stmt_type, "interface": JsParser.stmt_interface,
    "enum": JsParser.stmt_enum, "declare": JsParser.stmt_declare, "namespace": JsParser.stmt_namespace,
    "module": JsParser.stmt_namespace, "abstract": JsParser.stmt_abstract, "global": JsParser.stmt_global,
}


def _js_unquote(raw: str) -> str:
    """Cooked value of a string token (simple escapes only; good enough for specifiers)."""
    body = raw[1:-1] if len(raw) >= 2 else raw
    if "\\" not in body:
        return body
    return re.sub(r"\\(?:\r\n|\n)", "", body).replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")


class JsParserExpressions:
    """Expression grammar (mixed into JsParser)."""

    def parse_expression(self, no_in: bool = False) -> JsNode:
        first = self.parse_assignment(no_in)
        if not self.is_p(","):
            return first
        node = JsNode("SequenceExpression", first.start, first.line, first.col, {"expressions": [first]})
        exprs: List[JsNode] = node.fields["expressions"]  # type: ignore[assignment]
        while self.eat(","):
            exprs.append(self.parse_assignment(no_in))
        return self.finish(node)

    def parse_assignment(self, no_in: bool = False) -> JsNode:
        self.depth += 1
        if self.depth > JS_PARSER_MAX_DEPTH:
            raise _JsParseAbort("nesting deeper than %d" % JS_PARSER_MAX_DEPTH)
        node = self._parse_assignment(no_in)
        self.depth -= 1
        return node

    def _parse_assignment(self, no_in: bool) -> JsNode:
        t = self.tok
        kind = t.kind
        if kind == "name":
            v = t.value
            if v == "yield":
                return self.parse_yield(no_in)
            if v == "async":
                arrow = self.try_async_arrow(no_in)
                if arrow is not None:
                    return arrow
            elif v not in _JS_RESERVED and _JS_ARROW_AHEAD_RE.match(self.text, t.end):
                self.next()
                param = self.finish(JsNode("Identifier", t.start, t.line, t.col, {"name": t.value}))
                self.expect("=>")
                return self.parse_arrow_body(t, [param], is_async=False, no_in=no_in)
        elif kind == "punct":
            v = t.value
            if v == "(" and t.start not in self.failed_arrow:
                arrow = self.try_paren_arrow(t, is_async=False, no_in=no_in)
                if arrow is not None:
                    return arrow
            elif v == "<" and self.ts and t.start not in self.failed_arrow and self.looks_like_generic_arrow():
                arrow = self.try_generic_arrow(t, no_in)
                if arrow is not None:
                    return arrow
        left = self.parse_conditional(no_in)
        t = self.tok
        if t.kind == "punct":
            op = t.value
            if op == ">":
                op = self.greater_operator()
            if op in _JS_ASSIGN_OPS:
                if len(op) > 1 and op[0] == ">":
                    self.lexer.rescan_greater(t, op)
                self.next()
                node = JsNode("AssignmentExpression", left.start, left.line, left.col, {"operator": op})
                node.fields["left"] = self.to_pattern(left) if op == "=" else left
                node.fields["right"] = self.parse_assignment(no_in)
                return self.finish(node)
        return left

    def greater_operator(self) -> str:
        m = _JS_GREATER_RE.match(self.text, self.tok.start)
        return m.group() if m else ">"

    def parse_yield(self, no_in: bool) -> JsNode:
        t = self.next()
        node = self.node("YieldExpression", t, delegate=False, argument=None)
        n = self.tok
        if n.nl or n.kind == "eof":
            return self.finish(node)
        if n.kind == "punct":
            if n.value == "*":
                self.next()
                node.fields["delegate"] = True
            elif n.value in (")", "]", "}", ",", ";", ":") or n.value in _JS_BINARY_PREC and n.value not in ("<", "+", "-", "/"):
                return self.finish(node)
        node.fields["argument"] = self.parse_assignment(no_in)
        return self.finish(node)

    # -- arrow functions ----------------------------------------------------
    def try_async_arrow(self, no_in: bool) -> Optional[JsNode]:
        t = self.tok
        p = self.peek()
        if p.nl:
            return None
        if p.kind == "name":
            if p.value == "function":
                return None
            if p.value not in _JS_RESERVED and _JS_ARROW_AHEAD_RE.match(self.text, p.end):
                self.next()
                pt = self.next()
                param = self.finish(JsNode("Identifier", pt.start, pt.line, pt.col, {"name": pt.value}))
                self.expect("=>")
                return self.parse_arrow_body(t, [param], is_async=True, no_in=no_in)
            return None
        if p.kind == "punct":
            if p.value == "(" and p.start not in self.failed_arrow:
                state = self._snapshot()
                self.next()
                arrow = self.try_paren_arrow(t, is_async=True, no_in=no_in)
                if arrow is not None:
                    return arrow
                self._restore(state)
            elif p.value == "<" and self.ts:
                state = self._snapshot()
                self.next()
                if self.looks_like_generic_arrow():
                    arrow = self.try_generic_arrow(t, no_in, is_async=True)
                    if arrow is not None:
                        return arrow
                self._restore(state)
        return None

    def looks_like_generic_arrow(self) -> bool:
        if not self.jsx:
            return True
        return bool(_JS_TSX_GENERIC_ARROW_RE.match(self.text, self.tok.end))

    def try_generic_arrow(self, start: JsToken, no_in: bool, is_async: bool = False) -> Optional[JsNode]:
        state = self._snapshot()
        self.speculating += 1
        try:
            self.parse_type_parameters()
            if not self.is_p("("):
                raise self.error()
            params = self.parse_params()
            if self.eat(":"):
                self.parse_return_type()
            if not self.is_p("=>"):
                raise self.error("expected '=>'")
        except _JsParseError:
            self.speculating -= 1
            self._restore(state)
            self.failed_arrow.add(start.start)
            return None
        self.speculating -= 1
        self.next()
        return self.parse_arrow_body(start, params, is_async=is_async, no_in=no_in)

    def try_paren_arrow(self, start: JsToken, is_async: bool, no_in: bool) -> Optional[JsNode]:
        """Speculatively parse `( params ) [: type] =>`; restore on failure."""
        paren = self.tok
        state = self._snapshot()
        self.speculating += 1
        try:
            params = self.parse_params()
            if self.is_p(":"):
                self.next()
                self.parse_return_type()
            t = self.tok
            if not (t.kind == "punct" and t.value == "=>") or t.nl:
                raise self.error("expected '=>'")
        except _JsParseError:
            self.speculating -= 1
            self._restore(state)
            self.failed_arrow.add(paren.start)
            return None
        self.speculating -= 1
        self.next()
        return self.parse_arrow_body(start, params, is_async=is_async, no_in=no_in)

    def parse_arrow_body(self, start: JsToken, params: List[JsNode], is_async: bool, no_in: bool) -> JsNode:
        node = JsNode("ArrowFunctionExpression", start.start, start.line, start.col,
                      {"params": params, "async": is_async, "generator": False, "id": None})
        if self.is_p("{"):
            node.fields["expression"] = False
            node.fields["body"] = self.parse_block()
        else:
            node.fields["expression"] = True
            node.fields["body"] = self.parse_assignment(no_in)
        return self.finish(node)

    # -- conditional / binary / unary ---------------------------------------
    def parse_conditional(self, no_in: bool) -> JsNode:
        test = self.parse_binary(0, no_in)
        if not self.is_p("?"):
            return test
        self.next()
        node = JsNode("ConditionalExpression", test.start, test.line, test.col, {"test": test})
        node.fields["consequent"] = self.parse_assignment(False)
        self.expect(":")
        node.fields["alternate"] = self.parse_assignment(no_in)
        return self.finish(node)

    def parse_binary(self, min_prec: int, no_in: bool) -> JsNode:
        left = self.parse_unary()
        while True:
            t = self.tok
            if t.kind == "punct":
                op = t.value
                if op == ">":
                    op = self.greater_operator()
                    if op[-1] == "=" and op != ">=":
                        break  # `>>=` style assignment: handled by the assignment parser
                prec = _JS_BINARY_PREC.get(op)
                if prec is None or prec <= min_prec and not (op == "**" and prec == min_prec):
                    break
                if len(op) > 1 and op[0] == ">":
                    self.lexer.rescan_greater(t, op)
                self.next()
                right = self.parse_binary(prec - 1 if op == "**" else prec, no_in)
                type_ = "LogicalExpression" if op in ("&&", "||", "??") else "BinaryExpression"
                left = self.finish(JsNode(type_, left.start, left.line, left.col, {"operator": op, "left": left, "right": right}))
            elif t.kind == "name":
                op = t.value
                if op == "in":
                    if no_in:
                        break
                    prec = 8
                elif op == "instanceof":
                    prec = 8
                elif (op == "as" or op == "satisfies") and self.ts and not t.nl:
                    prec = 8
                    if prec <= min_prec:
                        break
                    self.next()
                    type_node = self.parse_const_or_type()
                    kind = "TSAsExpression" if op == "as" else "TSSatisfiesExpression"
                    left = self.finish(JsNode(kind, left.start, left.line, left.col, {"expression": left, "typeAnnotation": type_node}))
                    continue
                else:
                    break
                if prec <= min_prec:
                    break
                self.next()
                right = self.parse_binary(prec, no_in)
                left = self.finish(JsNode("BinaryExpression", left.start, left.line, left.col, {"operator": op, "left": left, "right": right}))
            else:
                break
        return left

    def parse_const_or_type(self) -> JsNode:
        if self.is_n("const"):
            t = self.next()
            return self.finish(JsNode("TSType", t.start, t.line, t.col, {"kind": "TypeRef", "name": "const"}))
        return self.parse_type()

    def parse_unary(self) -> JsNode:
        t = self.tok
        kind = t.kind
        if kind == "punct":
            v = t.value
            if v in ("!", "~", "+", "-"):
                self.next()
                node = JsNode("UnaryExpression", t.start, t.line, t.col, {"operator": v, "prefix": True})
                node.fields["argument"] = self.parse_unary()
                return self.finish(node)
            if v == "++" or v == "--":
                self.next()
                node = JsNode("UpdateExpression", t.start, t.line, t.col, {"operator": v, "prefix": True})
                node.fields["argument"] = self.parse_unary()
                return self.finish(node)
            if v == "<" and self.ts and not self.jsx:
                return self.parse_type_assertion()
        elif kind == "name":
            v = t.value
            if v in ("typeof", "void", "delete"):
                self.next()
                node = JsNode("UnaryExpression", t.start, t.line, t.col, {"operator": v, "prefix": True})
                node.fields["argument"] = self.parse_unary()
                return self.finish(node)
            if v == "await":
                p = self.peek()
                if not p.nl and (p.kind in ("name", "num", "str", "tpl", "priv") or
                                 (p.kind == "punct" and p.value in ("(", "[", "{", "!", "~", "+", "-", "++", "--", "/", "<", "`"))) \
                        and not (p.kind == "punct" and p.value in (")", ";", ",", "]", "}", ":", "=", "=>", ".", "?.")):
                    if p.kind == "name" and p.value in ("in", "of", "instanceof", "as"):
                        pass
                    else:
                        self.next()
                        node = JsNode("AwaitExpression", t.start, t.line, t.col, {})
                        node.fields["argument"] = self.parse_unary()
                        return self.finish(node)
        return self.parse_postfix()

    def parse_type_assertion(self) -> JsNode:
        t = self.next()  # <
        node = JsNode("TSTypeAssertion", t.start, t.line, t.col, {})
        node.fields["typeAnnotation"] = self.parse_type()
        self.expect(">")
        node.fields["expression"] = self.parse_unary()
        return self.finish(node)

    def parse_postfix(self) -> JsNode:
        expr = self.parse_lhs_expression(allow_call=True)
        t = self.tok
        if t.kind == "punct" and (t.value == "++" or t.value == "--") and not t.nl:
            self.next()
            expr = self.finish(JsNode("UpdateExpression", expr.start, expr.line, expr.col,
                                      {"operator": t.value, "prefix": False, "argument": expr}))
        return expr

    # -- call / member ------------------------------------------------------
    def parse_lhs_expression(self, allow_call: bool) -> JsNode:
        t = self.tok
        if t.kind == "name" and t.value == "new":
            expr = self.parse_new()
        else:
            expr = self.parse_primary()
        return self.parse_call_tail(expr, allow_call)

    def parse_new(self) -> JsNode:
        t = self.next()
        if self.is_p("."):
            self.next()
            prop = self.next().value
            return self.finish(JsNode("MetaProperty", t.start, t.line, t.col, {"meta": "new", "property": prop}))
        node = JsNode("NewExpression", t.start, t.line, t.col, {"arguments": []})
        if self.is_n("new"):
            callee = self.parse_new()
        else:
            callee = self.parse_primary()
            callee = self.parse_call_tail(callee, allow_call=False)
        node.fields["callee"] = callee
        if self.is_p("<") and self.ts:
            if not self.try_type_arguments():
                pass
        if self.is_p("("):
            node.fields["arguments"] = self.parse_arguments()
        return self.finish(node)

    def parse_arguments(self) -> List[JsNode]:
        self.expect("(")
        args: List[JsNode] = []
        while not self.is_p(")"):
            if self.is_p("..."):
                st = self.next()
                arg = JsNode("SpreadElement", st.start, st.line, st.col, {})
                arg.fields["argument"] = self.parse_assignment()
                args.append(self.finish(arg))
            else:
                args.append(self.parse_assignment())
            if not self.eat(","):
                break
        self.expect(")")
        return args

    def parse_call_tail(self, expr: JsNode, allow_call: bool) -> JsNode:
        while True:
            t = self.tok
            kind = t.kind
            if kind == "punct":
                v = t.value
                if v == ".":
                    self.next()
                    p = self.tok
                    if p.kind == "name" or p.kind == "priv":
                        self.next()
                        expr = self.finish(JsNode("MemberExpression", expr.start, expr.line, expr.col,
                                                  {"object": expr, "property": p.value, "computed": False, "optional": False}))
                    else:
                        raise self.error("expected property name")
                    continue
                if v == "?.":
                    self.next()
                    p = self.tok
                    if p.kind == "punct" and p.value == "(":
                        if not allow_call:
                            raise self.error()
                        args = self.parse_arguments()
                        expr = self.finish(JsNode("CallExpression", expr.start, expr.line, expr.col,
                                                  {"callee": expr, "arguments": args, "optional": True}))
                    elif p.kind == "punct" and p.value == "[":
                        self.next()
                        prop = self.parse_expression()
                        self.expect("]")
                        expr = self.finish(JsNode("MemberExpression", expr.start, expr.line, expr.col,
                                                  {"object": expr, "property": prop, "computed": True, "optional": True}))
                    elif p.kind == "punct" and p.value == "<" and self.ts:
                        if not self.try_type_arguments():
                            raise self.error()
                        args = self.parse_arguments()
                        expr = self.finish(JsNode("CallExpression", expr.start, expr.line, expr.col,
                                                  {"callee": expr, "arguments": args, "optional": True}))
                    elif p.kind in ("name", "priv"):
                        self.next()
                        expr = self.finish(JsNode("MemberExpression", expr.start, expr.line, expr.col,
                                                  {"object": expr, "property": p.value, "computed": False, "optional": True}))
                    else:
                        raise self.error()
                    continue
                if v == "[":
                    self.next()
                    prop = self.parse_expression()
                    self.expect("]")
                    expr = self.finish(JsNode("MemberExpression", expr.start, expr.line, expr.col,
                                              {"object": expr, "property": prop, "computed": True, "optional": False}))
                    continue
                if v == "(":
                    if not allow_call:
                        return expr
                    args = self.parse_arguments()
                    expr = self.finish(JsNode("CallExpression", expr.start, expr.line, expr.col,
                                              {"callee": expr, "arguments": args, "optional": False}))
                    continue
                if v == "!" and self.ts and not t.nl:
                    # non-null assertion: `x!` followed by something that cannot start an operand
                    p = self.peek()
                    if p.kind == "punct" and p.value in (".", "?.", "[", "(", ")", ";", ",", "]", "}", "=", ":", "?") \
                            or p.kind == "eof" or p.nl or (p.kind == "punct" and p.value in _JS_BINARY_PREC and p.value not in ("+", "-")):
                        self.next()
                        expr = self.finish(JsNode("TSNonNullExpression", expr.start, expr.line, expr.col, {"expression": expr}))
                        continue
                    return expr
                if v == "<" and self.ts and t.start not in self.failed_typeargs:
                    state = self._snapshot()
                    if self.try_type_arguments():
                        n = self.tok
                        if n.kind == "punct" and n.value == "(" and allow_call:
                            args = self.parse_arguments()
                            expr = self.finish(JsNode("CallExpression", expr.start, expr.line, expr.col,
                                                      {"callee": expr, "arguments": args, "optional": False}))
                            continue
                        if n.kind == "tpl" or (n.kind == "punct" and n.value == "`"):
                            continue  # tagged template handled below on the next loop
                        if n.kind == "eof" or n.nl or (n.kind == "punct" and n.value in (")", "]", ",", ";", ".", "?.", "}", "=", "?", ":")) \
                                or (n.kind == "name" and n.value in ("as", "satisfies")):
                            expr = self.finish(JsNode("TSInstantiationExpression", expr.start, expr.line, expr.col, {"expression": expr}))
                            continue
                    self._restore(state)
                    self.failed_typeargs.add(t.start)
                    return expr
                return expr
            if kind == "tpl" or (kind == "bad" and t.value == "`"):
                quasi = self.parse_template()
                expr = self.finish(JsNode("TaggedTemplateExpression", expr.start, expr.line, expr.col, {"tag": expr, "quasi": quasi}))
                continue
            return expr

    def try_type_arguments(self) -> bool:
        """Speculatively parse `<T, U>` at the current `<`. True on success (consumed)."""
        start = self.tok
        state = self._snapshot()
        self.speculating += 1
        try:
            self.next()
            while True:
                self.parse_type()
                if not self.eat(","):
                    break
            if not self.is_p(">"):
                raise self.error("expected '>'")
            self.next()
        except _JsParseError:
            self.speculating -= 1
            self._restore(state)
            self.failed_typeargs.add(start.start)
            return False
        self.speculating -= 1
        return True

    # -- primary ------------------------------------------------------------
    def parse_primary(self) -> JsNode:
        t = self.tok
        kind = t.kind
        if kind == "name":
            v = t.value
            if v in _JS_RESERVED:
                if v == "this":
                    self.next()
                    return self.finish(JsNode("ThisExpression", t.start, t.line, t.col, {}))
                if v == "function":
                    return self.parse_function(declaration=False, is_async=False)
                if v == "class":
                    return self.parse_class(declaration=False)
                if v in ("null", "true", "false"):
                    self.next()
                    value = None if v == "null" else (v == "true")
                    return self.finish(JsNode("Literal", t.start, t.line, t.col, {"value": value, "raw": v, "kind": "null" if v == "null" else "boolean"}))
                if v == "super":
                    self.next()
                    return self.finish(JsNode("Super", t.start, t.line, t.col, {}))
                if v == "import":
                    return self.parse_import_expression()
                if v == "new":
                    return self.parse_new()
                raise self.error("unexpected keyword '%s'" % v)
            if v == "async":
                p = self.peek()
                if p.kind == "name" and p.value == "function" and not p.nl:
                    self.next()
                    return self.parse_function(declaration=False, is_async=True)
            self.next()
            return self.finish(JsNode("Identifier", t.start, t.line, t.col, {"name": v}))
        if kind == "num":
            self.next()
            return self.finish(JsNode("Literal", t.start, t.line, t.col, {"value": t.value, "raw": t.value, "kind": "number"}))
        if kind == "str":
            self.next()
            return self.finish(JsNode("Literal", t.start, t.line, t.col, {"value": _js_unquote(t.value), "raw": t.value, "kind": "string"}))
        if kind == "tpl" or (kind == "bad" and t.value == "`"):
            return self.parse_template()
        if kind == "punct":
            v = t.value
            if v == "(":
                self.next()
                expr = self.parse_expression()
                self.expect(")")
                return self.finish(JsNode("ParenthesizedExpression", t.start, t.line, t.col, {"expression": expr}))
            if v == "[":
                return self.parse_array_expression()
            if v == "{":
                return self.parse_object_expression()
            if v == "/" or v == "/=":
                self.tok = self.lexer.rescan_regex(t)
                r = self.next()
                return self.finish(JsNode("Literal", r.start, r.line, r.col, {"value": r.value, "raw": r.value, "kind": "regex"}))
            if v == "<":
                if self.jsx:
                    return self.parse_jsx_element()
                if self.ts:
                    return self.parse_type_assertion()
            if v == "@":
                self.parse_decorators()
                return self.parse_class(declaration=False)
            if v == "#":
                raise self.error()
        if kind == "priv":
            self.next()
            return self.finish(JsNode("PrivateName", t.start, t.line, t.col, {"name": t.value}))
        if kind == "regex":
            self.next()
            return self.finish(JsNode("Literal", t.start, t.line, t.col, {"value": t.value, "raw": t.value, "kind": "regex"}))
        raise self.error()

    def parse_import_expression(self) -> JsNode:
        t = self.next()
        if self.eat("."):
            prop = self.next().value
            return self.finish(JsNode("MetaProperty", t.start, t.line, t.col, {"meta": "import", "property": prop}))
        node = JsNode("ImportExpression", t.start, t.line, t.col, {})
        self.expect("(")
        node.fields["source"] = self.parse_assignment()
        if self.eat(","):
            if not self.is_p(")"):
                node.fields["options"] = self.parse_assignment()
                self.eat(",")
        self.expect(")")
        return self.finish(node)

    def parse_template(self) -> JsNode:
        t = self.tok
        if t.kind == "bad":  # the backtick was reached in a mode where the lexer did not scan it
            self.tok = t = self.lexer.rescan_backtick(t)
        node = JsNode("TemplateLiteral", t.start, t.line, t.col, {"quasis": [], "expressions": []})
        quasis: List[str] = node.fields["quasis"]  # type: ignore[assignment]
        exprs: List[JsNode] = node.fields["expressions"]  # type: ignore[assignment]
        while True:
            t = self.tok
            if t.kind != "tpl":
                raise self.error("expected template continuation")
            quasis.append(t.value[:-1])
            if t.value[-1] == "`":
                self.next()
                return self.finish(node)
            self.next()
            exprs.append(self.parse_expression())
            close = self.tok
            if not (close.kind == "punct" and close.value == "}"):
                raise self.error("expected '}' in template literal")
            self.tok = self.lexer.rescan_template_continuation(close)

    def parse_array_expression(self) -> JsNode:
        t = self.next()
        node = JsNode("ArrayExpression", t.start, t.line, t.col, {"elements": []})
        elements: List[Optional[JsNode]] = node.fields["elements"]  # type: ignore[assignment]
        while not self.is_p("]"):
            if self.is_p(","):
                self.next()
                elements.append(None)
                continue
            if self.is_p("..."):
                st = self.next()
                sp = JsNode("SpreadElement", st.start, st.line, st.col, {})
                sp.fields["argument"] = self.parse_assignment()
                elements.append(self.finish(sp))
            else:
                elements.append(self.parse_assignment())
            if not self.eat(","):
                break
        self.expect("]")
        return self.finish(node)

    def parse_property_key(self) -> Tuple[object, bool]:
        """Returns (key, computed). Key is a str for names/strings/numbers, a node when computed."""
        t = self.tok
        if t.kind == "name" or t.kind == "priv":
            self.next()
            return t.value, False
        if t.kind == "str":
            self.next()
            return _js_unquote(t.value), False
        if t.kind == "num":
            self.next()
            return t.value, False
        if t.kind == "punct" and t.value == "[":
            self.next()
            key = self.parse_assignment()
            self.expect("]")
            return key, True
        raise self.error("expected property name")

    def parse_object_expression(self) -> JsNode:
        t = self.next()
        node = JsNode("ObjectExpression", t.start, t.line, t.col, {"properties": []})
        props: List[JsNode] = node.fields["properties"]  # type: ignore[assignment]
        while not self.is_p("}"):
            if self.is_p("..."):
                st = self.next()
                sp = JsNode("SpreadElement", st.start, st.line, st.col, {})
                sp.fields["argument"] = self.parse_assignment()
                props.append(self.finish(sp))
            else:
                props.append(self.parse_object_property())
            if not self.eat(","):
                break
        self.expect("}")
        return self.finish(node)

    def parse_object_property(self) -> JsNode:
        st = self.tok
        prop = JsNode("Property", st.start, st.line, st.col, {"kind": "init", "method": False, "shorthand": False, "computed": False})
        is_async = False
        is_generator = False
        accessor = None
        t = self.tok
        if t.kind == "name" and t.value in ("get", "set", "async") and (self.peek_is_name_like() or
                                                                          (t.value == "async" and self.peek().kind == "punct" and self.peek().value == "*")):
            self.next()
            if t.value == "async":
                is_async = True
            else:
                accessor = t.value
        if is_async and self.is_p("*"):
            self.next()
            is_generator = True
        elif self.is_p("*"):
            self.next()
            is_generator = True
        key, computed = self.parse_property_key()
        prop.fields["key"] = key
        prop.fields["computed"] = computed
        n = self.tok
        if n.kind == "punct" and (n.value == "(" or n.value == "<"):
            if accessor:
                prop.fields["kind"] = accessor
            prop.fields["method"] = True
            prop.fields["value"] = self.parse_function_rest(st, is_async, is_generator, name=None, is_method=True)
            return self.finish(prop)
        if accessor or is_async or is_generator:
            raise self.error("expected method body")
        if n.kind == "punct" and n.value == ":":
            self.next()
            prop.fields["value"] = self.parse_assignment()
            return self.finish(prop)
        # shorthand (`a`, `a = default` cover grammar)
        if computed or t.kind != "name":
            raise self.error("expected ':'")
        prop.fields["shorthand"] = True
        ident = self.finish(JsNode("Identifier", t.start, t.line, t.col, {"name": t.value}))
        if self.is_p("="):
            self.next()
            ap = JsNode("AssignmentPattern", t.start, t.line, t.col, {"left": ident})
            ap.fields["right"] = self.parse_assignment()
            prop.fields["value"] = self.finish(ap)
        else:
            prop.fields["value"] = ident
        return self.finish(prop)

    # -- expression -> pattern (assignment targets) ------------------------
    def to_pattern(self, node: JsNode) -> JsNode:
        """Reinterpret an expression as an assignment pattern (bounded, iterative)."""
        stack = [node]
        while stack:
            n = stack.pop()
            t = n.type
            if t == "ArrayExpression":
                n.type = "ArrayPattern"
                for el in n.fields["elements"]:  # type: ignore[union-attr]
                    if el is not None:
                        stack.append(el)
            elif t == "ObjectExpression":
                n.type = "ObjectPattern"
                for p in n.fields["properties"]:  # type: ignore[union-attr]
                    if p.type == "Property":
                        stack.append(p.fields["value"])  # type: ignore[arg-type]
                    else:
                        stack.append(p)
            elif t == "SpreadElement":
                n.type = "RestElement"
                stack.append(n.fields["argument"])  # type: ignore[arg-type]
            elif t == "AssignmentExpression" and n.fields.get("operator") == "=":
                n.type = "AssignmentPattern"
                stack.append(n.fields["left"])  # type: ignore[arg-type]
            elif t == "ParenthesizedExpression":
                stack.append(n.fields["expression"])  # type: ignore[arg-type]
        return node


class JsParserFunctions:
    """Functions, classes and binding patterns (mixed into JsParser)."""

    def parse_binding_target(self, allow_annotation: bool) -> JsNode:
        t = self.tok
        if t.kind == "punct" and t.value == "[":
            node = self.parse_array_pattern()
        elif t.kind == "punct" and t.value == "{":
            node = self.parse_object_pattern()
        else:
            node = self.identifier()
        if allow_annotation and self.ts:
            if self.is_p("!") and node.type == "Identifier":
                self.next()  # definite assignment
            if self.is_p(":"):
                self.next()
                node.fields["typeAnnotation"] = self.parse_type()
                node.end = self.prev_end
        return node

    def parse_binding_element(self) -> JsNode:
        target = self.parse_binding_target(allow_annotation=False)
        if self.is_p("="):
            self.next()
            ap = JsNode("AssignmentPattern", target.start, target.line, target.col, {"left": target})
            ap.fields["right"] = self.parse_assignment()
            return self.finish(ap)
        return target

    def parse_array_pattern(self) -> JsNode:
        t = self.next()
        node = JsNode("ArrayPattern", t.start, t.line, t.col, {"elements": []})
        elements: List[Optional[JsNode]] = node.fields["elements"]  # type: ignore[assignment]
        while not self.is_p("]"):
            if self.is_p(","):
                self.next()
                elements.append(None)
                continue
            if self.is_p("..."):
                st = self.next()
                rest = JsNode("RestElement", st.start, st.line, st.col, {})
                rest.fields["argument"] = self.parse_binding_target(allow_annotation=False)
                elements.append(self.finish(rest))
            else:
                elements.append(self.parse_binding_element())
            if not self.eat(","):
                break
        self.expect("]")
        return self.finish(node)

    def parse_object_pattern(self) -> JsNode:
        t = self.next()
        node = JsNode("ObjectPattern", t.start, t.line, t.col, {"properties": []})
        props: List[JsNode] = node.fields["properties"]  # type: ignore[assignment]
        while not self.is_p("}"):
            st = self.tok
            if self.is_p("..."):
                self.next()
                rest = JsNode("RestElement", st.start, st.line, st.col, {})
                rest.fields["argument"] = self.parse_binding_target(allow_annotation=False)
                props.append(self.finish(rest))
            else:
                prop = JsNode("Property", st.start, st.line, st.col, {"kind": "init", "method": False, "shorthand": False})
                key, computed = self.parse_property_key()
                prop.fields["key"] = key
                prop.fields["computed"] = computed
                if self.eat(":"):
                    prop.fields["value"] = self.parse_binding_element()
                else:
                    if computed or st.kind != "name":
                        raise self.error("expected ':'")
                    prop.fields["shorthand"] = True
                    ident = self.finish(JsNode("Identifier", st.start, st.line, st.col, {"name": st.value}))
                    if self.is_p("="):
                        self.next()
                        ap = JsNode("AssignmentPattern", st.start, st.line, st.col, {"left": ident})
                        ap.fields["right"] = self.parse_assignment()
                        prop.fields["value"] = self.finish(ap)
                    else:
                        prop.fields["value"] = ident
                props.append(self.finish(prop))
            if not self.eat(","):
                break
        self.expect("}")
        return self.finish(node)

    def parse_params(self) -> List[JsNode]:
        self.expect("(")
        params: List[JsNode] = []
        while not self.is_p(")"):
            if self.is_p("@"):
                self.parse_decorators()
            if self.ts:
                while self.tok.kind == "name" and self.tok.value in ("public", "private", "protected", "readonly", "override") \
                        and self.peek_is_name_like():
                    self.next()
            if self.is_p("..."):
                st = self.next()
                rest = JsNode("RestElement", st.start, st.line, st.col, {})
                rest.fields["argument"] = self.parse_binding_target(allow_annotation=True)
                params.append(self.finish(rest))
            else:
                st = self.tok
                if self.ts and st.kind == "name" and st.value == "this":
                    self.next()
                    target = self.finish(JsNode("Identifier", st.start, st.line, st.col, {"name": "this"}))
                else:
                    target = self.parse_binding_target(allow_annotation=False)
                if self.ts:
                    if self.is_p("?"):
                        self.next()
                        target.fields["optional"] = True
                    if self.is_p(":"):
                        self.next()
                        target.fields["typeAnnotation"] = self.parse_type()
                        target.end = self.prev_end
                if self.is_p("="):
                    self.next()
                    ap = JsNode("AssignmentPattern", st.start, st.line, st.col, {"left": target})
                    ap.fields["right"] = self.parse_assignment()
                    target = self.finish(ap)
                params.append(target)
            if not self.eat(","):
                break
        self.expect(")")
        return params

    def parse_return_type(self) -> JsNode:
        """Return type after `:` (already consumed), including type predicates."""
        t = self.tok
        if t.kind == "name" and t.value == "asserts":
            p = self.peek()
            if p.kind == "name" and not p.nl:
                self.next()
                self.next()
                if self.eat_name("is"):
                    return self.parse_type()
                return self.finish(JsNode("TSType", t.start, t.line, t.col, {"kind": "TypeOther"}))
        if t.kind == "name" and t.value not in _JS_RESERVED or (t.kind == "name" and t.value == "this"):
            p = self.peek()
            if p.kind == "name" and p.value == "is" and not p.nl:
                self.next()
                self.next()
                self.parse_type()
                return self.finish(JsNode("TSType", t.start, t.line, t.col, {"kind": "TypeOther"}))
        return self.parse_type()

    def parse_function(self, declaration: bool, is_async: bool, allow_anonymous: bool = False) -> JsNode:
        start = self.tok
        self.expect_name("function")
        is_generator = self.eat("*")
        name: Optional[str] = None
        if self.tok.kind == "name" and (self.tok.value not in _JS_RESERVED or not declaration):
            if not (self.tok.kind == "punct"):
                name = self.next().value
        elif declaration and not allow_anonymous and not self.is_p("("):
            raise self.error("expected function name")
        node = self.parse_function_rest(start, is_async, is_generator, name, is_method=False)
        node.type = "FunctionDeclaration" if declaration else "FunctionExpression"
        if node.fields.get("body") is None:
            node.type = "TSDeclareFunction"
            self.semicolon()
        return node

    def parse_function_rest(self, start: JsToken, is_async: bool, is_generator: bool, name: Optional[str],
                            is_method: bool) -> JsNode:
        node = JsNode("FunctionExpression", start.start, start.line, start.col,
                      {"id": name, "async": is_async, "generator": is_generator, "params": [], "body": None})
        if self.is_p("<") and self.ts:
            self.parse_type_parameters()
        node.fields["params"] = self.parse_params()
        if self.is_p(":") and self.ts:
            self.next()
            node.fields["returnType"] = self.parse_return_type()
        if self.is_p("{"):
            node.fields["body"] = self.parse_block()
        elif not self.ts:
            raise self.error("expected '{'")
        return self.finish(node)

    # -- classes ------------------------------------------------------------
    def parse_class(self, declaration: bool, allow_anonymous: bool = False) -> JsNode:
        start = self.tok
        self.expect_name("class")
        node = JsNode("ClassDeclaration" if declaration else "ClassExpression", start.start, start.line, start.col,
                      {"id": None, "superClass": None})
        if self.tok.kind == "name" and self.tok.value not in ("extends", "implements") and self.tok.value not in _JS_RESERVED:
            node.fields["id"] = self.next().value
        elif declaration and not allow_anonymous and not self.is_n("extends") and not self.is_p("{"):
            raise self.error("expected class name")
        if self.is_p("<") and self.ts:
            self.parse_type_parameters()
        if self.eat_name("extends"):
            node.fields["superClass"] = self.parse_lhs_expression(allow_call=True)
            if self.is_p("<") and self.ts:
                self.try_type_arguments()
        if self.is_n("implements") and self.ts:
            self.next()
            while True:
                self.parse_type_reference_for_heritage()
                if not self.eat(","):
                    break
        node.fields["body"] = self.parse_class_body(node.fields["id"])  # type: ignore[arg-type]
        return self.finish(node)

    def parse_class_body(self, class_name: Optional[str]) -> JsNode:
        body = self.node("ClassBody", body=[])
        self.expect("{")
        members: List[JsNode] = body.fields["body"]  # type: ignore[assignment]
        base = self.brace_depth
        depth = self.depth
        while not self.is_p("}") and self.tok.kind != "eof":
            if self.eat(";"):
                continue
            start_tok = self.tok
            try:
                member = self.parse_class_member()
                if member is not None:
                    members.append(member)
            except _JsParseError as exc:
                self.depth = depth
                self.record_error(exc)
                self.recover(base)
                if self.tok is start_tok:
                    self.next()
        self.expect("}")
        return self.finish(body)

    def parse_class_member(self) -> Optional[JsNode]:
        st = self.tok
        if self.is_p("@"):
            self.parse_decorators()
        is_static = False
        is_async = False
        accessor: Optional[str] = None
        is_generator = False
        is_abstract = False
        is_declare = False
        while self.tok.kind == "name" and self.tok.value in _JS_MODIFIERS:
            v = self.tok.value
            p = self.peek()
            if v == "static" and p.kind == "punct" and p.value == "{":
                self.next()
                blk = JsNode("StaticBlock", st.start, st.line, st.col, {})
                blk.fields["body"] = self.parse_block().fields["body"]
                return self.finish(blk)
            if not (p.kind in ("name", "str", "num", "priv") or (p.kind == "punct" and p.value in ("[", "*", "{"))) or p.nl and v in ("get", "set"):
                break
            if v in ("public", "private", "protected", "readonly", "override", "accessor") and not self.ts and v != "accessor":
                break
            self.next()
            if v == "static":
                is_static = True
            elif v == "async":
                is_async = True
            elif v in ("get", "set"):
                accessor = v
            elif v == "abstract":
                is_abstract = True
            elif v == "declare":
                is_declare = True
        if self.is_p("*"):
            self.next()
            is_generator = True
        if self.is_p("[") and self.ts and self.looks_like_index_signature():
            self.parse_index_signature()
            self.semicolon_or_comma()
            return None
        key, computed = self.parse_property_key()
        node = JsNode("MethodDefinition", st.start, st.line, st.col,
                      {"key": key, "computed": computed, "static": is_static, "kind": "method"})
        if self.ts:
            if self.is_p("?") or (self.is_p("!") and not self.peek().nl):
                self.next()
        t = self.tok
        if t.kind == "punct" and (t.value == "(" or t.value == "<"):
            if key == "constructor" and not computed and not is_static:
                node.fields["kind"] = "constructor"
            elif accessor:
                node.fields["kind"] = accessor
            fn = self.parse_function_rest(st, is_async, is_generator, None, is_method=True)
            node.fields["value"] = fn
            if fn.fields.get("body") is None:
                node.type = "TSAbstractMethodDefinition" if is_abstract else "TSDeclareMethod"
                self.semicolon_or_comma()
            return self.finish(node)
        node.type = "PropertyDefinition"
        node.fields["declare"] = is_declare
        if self.is_p(":") and self.ts:
            self.next()
            node.fields["typeAnnotation"] = self.parse_type()
        if self.eat("="):
            node.fields["value"] = self.parse_assignment()
        else:
            node.fields["value"] = None
        self.semicolon_or_comma()
        return self.finish(node)

    def semicolon_or_comma(self) -> None:
        if self.eat(";") or self.eat(","):
            return
        t = self.tok
        if t.nl or t.kind == "eof" or (t.kind == "punct" and t.value == "}"):
            return
        raise self.error("expected ';'")

    def looks_like_index_signature(self) -> bool:
        state = self.lexer.snapshot()
        t1 = self.lexer.scan()
        t2 = self.lexer.scan()
        self.lexer.restore(state)
        return t1.kind == "name" and t2.kind == "punct" and t2.value == ":"

    def parse_index_signature(self) -> None:
        self.expect("[")
        self.identifier()
        self.expect(":")
        self.parse_type()
        self.expect("]")
        if self.eat(":"):
            self.parse_type()


class JsParserTypes:
    """TypeScript type grammar: consumed into lightweight TSType nodes."""

    def type_node(self, start: JsToken, kind: str = "TypeOther", name: Optional[str] = None) -> JsNode:
        fields: Dict[str, object] = {"kind": kind}
        if name is not None:
            fields["name"] = name
        return self.finish(JsNode("TSType", start.start, start.line, start.col, fields))

    def parse_type_parameters(self) -> None:
        self.expect("<")
        while not self.is_p(">"):
            if self.tok.kind == "name" and self.tok.value in ("const", "in", "out") and self.peek().kind == "name":
                self.next()
                if self.tok.kind == "name" and self.tok.value in ("in", "out") and self.peek().kind == "name":
                    self.next()
            self.identifier()
            if self.eat_name("extends"):
                self.parse_type()
            if self.eat("="):
                self.parse_type()
            if not self.eat(","):
                break
        self.expect(">")

    def parse_type_reference_for_heritage(self) -> None:
        self.parse_entity_name()
        if self.is_p("<"):
            if not self.try_type_arguments():
                raise self.error("expected type arguments")

    def parse_type(self, no_conditional: bool = False) -> JsNode:
        self.depth += 1
        if self.depth > JS_PARSER_MAX_DEPTH:
            raise _JsParseAbort("nesting deeper than %d" % JS_PARSER_MAX_DEPTH)
        node = self._parse_type(no_conditional)
        self.depth -= 1
        return node

    def _parse_type(self, no_conditional: bool) -> JsNode:
        start = self.tok
        t = start
        # function / constructor types
        if t.kind == "punct" and t.value == "<":
            self.parse_type_parameters()
            params = self.parse_params()
            self.expect("=>")
            self.parse_type()
            return self.type_node(start)
        if t.kind == "name" and t.value in ("new", "abstract") and (t.value == "new" or (self.peek().kind == "name" and self.peek().value == "new")):
            if t.value == "abstract":
                self.next()
            self.next()
            if self.is_p("<"):
                self.parse_type_parameters()
            self.parse_params()
            self.expect("=>")
            self.parse_type()
            return self.type_node(start)
        if t.kind == "punct" and t.value == "(" and self.looks_like_function_type():
            self.parse_params()
            self.expect("=>")
            self.parse_return_type()
            return self.type_node(start)
        node = self.parse_union_type()
        if not no_conditional and self.is_n("extends") and not self.tok.nl:
            self.next()
            self.parse_type(no_conditional=True)
            self.expect("?")
            self.parse_type()
            self.expect(":")
            self.parse_type()
            return self.type_node(start)
        return node

    def looks_like_function_type(self) -> bool:
        """At `(`: is this a function type rather than a parenthesized type?"""
        state = self.lexer.snapshot()
        t1 = self.lexer.scan()
        result: Optional[bool] = None
        if t1.kind == "punct" and t1.value in (")", "...", "{", "["):
            result = True
        elif t1.kind == "name":
            t2 = self.lexer.scan()
            if t2.kind == "punct" and t2.value in (":", ",", "?", "=", ")"):
                if t2.value == ")":
                    t3 = self.lexer.scan()
                    result = t3.kind == "punct" and t3.value == "=>"
                else:
                    result = True
            else:
                result = False
        elif t1.kind == "punct" and t1.value == "@":
            result = True
        self.lexer.restore(state)
        return bool(result)

    def parse_union_type(self) -> JsNode:
        start = self.tok
        self.eat("|")
        first = self.parse_intersection_type()
        if not self.is_p("|"):
            return first
        while self.eat("|"):
            self.parse_intersection_type()
        return self.type_node(start)

    def parse_intersection_type(self) -> JsNode:
        start = self.tok
        self.eat("&")
        first = self.parse_type_operator()
        if not self.is_p("&"):
            return first
        while self.eat("&"):
            self.parse_type_operator()
        return self.type_node(start)

    def parse_type_operator(self) -> JsNode:
        t = self.tok
        if t.kind == "name" and t.value in ("keyof", "unique", "readonly", "infer") and not self.peek().nl \
                and not (self.peek().kind == "punct" and self.peek().value in (")", ",", ">", "]", "=", "|", "&", ";", "}", "?", ":", "[")):
            self.next()
            if t.value == "infer":
                self.identifier()
                if self.is_n("extends") and not self.tok.nl:
                    state = self._snapshot()
                    self.next()
                    self.speculating += 1
                    try:
                        self.parse_type(no_conditional=True)
                        ok = not self.is_p("?")
                    except _JsParseError:
                        ok = False
                    self.speculating -= 1
                    if not ok:
                        self._restore(state)
                return self.type_node(t)
            self.parse_type_operator()
            return self.type_node(t)
        return self.parse_postfix_type()

    def parse_postfix_type(self) -> JsNode:
        start = self.tok
        node = self.parse_primary_type()
        while self.is_p("[") and not self.tok.nl:
            self.next()
            if self.eat("]"):
                node = self.type_node(start)
                continue
            self.parse_type()
            self.expect("]")
            node = self.type_node(start)
        return node

    def parse_primary_type(self) -> JsNode:
        t = self.tok
        kind = t.kind
        if kind == "name":
            v = t.value
            if v == "typeof":
                self.next()
                if self.is_n("import"):
                    self.parse_import_type()
                else:
                    self.parse_entity_name()
                if self.is_p("<") and not self.tok.nl:
                    self.try_type_arguments()
                return self.type_node(t)
            if v == "import":
                self.parse_import_type()
                return self.type_node(t)
            if v == "asserts" and self.peek().kind == "name" and not self.peek().nl:
                self.next()
                self.next()
                if self.eat_name("is"):
                    self.parse_type()
                return self.type_node(t)
            if v in _JS_TS_TYPE_KEYWORDS:
                self.next()
                return self.type_node(t, "TypeRef", v)
            if v == "void" or v == "null" or v == "this":
                self.next()
                return self.type_node(t, "TypeRef", v)
            if v in _JS_RESERVED and v not in ("this", "null", "void", "true", "false"):
                raise self.error("unexpected keyword in type")
            name = self.parse_entity_name()
            if self.is_p("<") and not self.tok.nl:
                if not self.try_type_arguments():
                    raise self.error("expected type arguments")
            return self.type_node(t, "TypeRef", name)
        if kind == "str" or kind == "num":
            self.next()
            return self.type_node(t, "TypeRef", t.value)
        if kind == "tpl" or (kind == "bad" and t.value == "`"):
            self.parse_template_type()
            return self.type_node(t)
        if kind == "punct":
            v = t.value
            if v == "(":
                self.next()
                self.parse_type()
                self.expect(")")
                return self.type_node(t)
            if v == "[":
                self.parse_tuple_type()
                return self.type_node(t)
            if v == "{":
                if self.looks_like_mapped_type():
                    self.parse_mapped_type()
                else:
                    self.parse_object_type()
                return self.type_node(t)
            if v == "-" and self.peek().kind == "num":
                self.next()
                self.next()
                return self.type_node(t, "TypeRef", "-" + t.value)
            if v == "?" or v == "*":
                self.next()  # JSDoc-style types (tolerated)
                return self.type_node(t)
        raise self.error("expected type")

    def parse_import_type(self) -> None:
        self.expect_name("import")
        self.expect("(")
        self.parse_string_literal()
        if self.eat(","):
            if not self.is_p(")"):
                self.parse_assignment()
        self.expect(")")
        while self.eat("."):
            self.next()
        if self.is_p("<") and not self.tok.nl:
            self.try_type_arguments()

    def parse_template_type(self) -> None:
        t = self.tok
        if t.kind == "bad":
            self.tok = t = self.lexer.rescan_backtick(t)
        while True:
            t = self.tok
            if t.kind != "tpl":
                raise self.error("expected template continuation")
            if t.value[-1] == "`":
                self.next()
                return
            self.next()
            self.parse_type()
            close = self.tok
            if not (close.kind == "punct" and close.value == "}"):
                raise self.error("expected '}' in template type")
            self.tok = self.lexer.rescan_template_continuation(close)

    def parse_tuple_type(self) -> None:
        self.expect("[")
        while not self.is_p("]"):
            if self.eat("..."):
                pass
            if self.tok.kind == "name" and self.peek().kind == "punct" and self.peek().value in (":", "?"):
                p = self.peek()
                if p.value == ":" or self.text[p.end:p.end + 1] == ":":
                    self.next()
                    self.eat("?")
                    self.expect(":")
            self.parse_type()
            self.eat("?")
            if not self.eat(","):
                break
        self.expect("]")

    def looks_like_mapped_type(self) -> bool:
        state = self.lexer.snapshot()
        toks = [self.lexer.scan() for _ in range(4)]
        self.lexer.restore(state)
        i = 0
        if toks[i].kind == "punct" and toks[i].value in ("+", "-"):
            i += 1
        if toks[i].kind == "name" and toks[i].value == "readonly":
            i += 1
        if not (toks[i].kind == "punct" and toks[i].value == "["):
            return False
        if i + 2 >= len(toks):
            return True
        return toks[i + 1].kind == "name" and toks[i + 2].kind == "name" and toks[i + 2].value == "in"

    def parse_mapped_type(self) -> None:
        self.expect("{")
        if self.is_p("+") or self.is_p("-"):
            self.next()
        self.eat_name("readonly")
        self.expect("[")
        self.identifier()
        self.expect_name("in")
        self.parse_type()
        if self.eat_name("as"):
            self.parse_type()
        self.expect("]")
        if self.is_p("+") or self.is_p("-"):
            self.next()
        self.eat("?")
        if self.eat(":"):
            self.parse_type()
        self.eat(";")
        self.eat(",")
        self.expect("}")

    def parse_object_type(self) -> JsNode:
        start = self.tok
        self.expect("{")
        while not self.is_p("}"):
            if self.tok.kind == "eof":
                raise self.error()
            self.parse_type_member()
            if not (self.eat(";") or self.eat(",")):
                if not self.is_p("}") and not self.tok.nl:
                    raise self.error("expected ';'")
        self.expect("}")
        return self.type_node(start)

    def parse_type_member(self) -> None:
        t = self.tok
        if t.kind == "punct" and (t.value == "(" or t.value == "<"):
            if t.value == "<":
                self.parse_type_parameters()
            self.parse_params()
            if self.eat(":"):
                self.parse_return_type()
            return
        if t.kind == "name" and t.value == "new" and self.peek().kind == "punct" and self.peek().value in ("(", "<"):
            self.next()
            if self.is_p("<"):
                self.parse_type_parameters()
            self.parse_params()
            if self.eat(":"):
                self.parse_type()
            return
        while self.tok.kind == "name" and self.tok.value in ("readonly", "get", "set", "static", "public", "private", "protected", "abstract", "declare", "accessor", "override") \
                and self.peek_is_name_like() and not self.peek().nl:
            self.next()
        if self.is_p("[") and self.looks_like_index_signature():
            self.parse_index_signature()
            return
        if self.is_p("-") or self.is_p("+"):
            self.next()
        self.parse_property_key()
        self.eat("?")
        if self.is_p("(") or self.is_p("<"):
            if self.is_p("<"):
                self.parse_type_parameters()
            self.parse_params()
            if self.eat(":"):
                self.parse_return_type()
            return
        if self.eat(":"):
            self.parse_type()


class JsParserJsx:
    """JSX grammar (mixed into JsParser)."""

    def next_jsx_tag(self) -> JsToken:
        tok = self.tok
        self.prev_end = tok.end
        self.tok = self.lexer.scan_jsx_tag()
        return tok

    def next_jsx_child(self) -> JsToken:
        tok = self.tok
        self.prev_end = tok.end
        self.tok = self.lexer.scan_jsx_text()
        return tok

    def parse_jsx_element(self, after: str = "default") -> JsNode:
        """At `<` (scanned in default mode). Returns JSXElement or JSXFragment.
        `after` names the lexer mode for the token following the element:
        "default", "child" (nested element) or "tag" (attribute value)."""
        self.depth += 1
        if self.depth > JS_PARSER_MAX_DEPTH:
            raise _JsParseAbort("nesting deeper than %d" % JS_PARSER_MAX_DEPTH)
        node = self._parse_jsx_element(after)
        self.depth -= 1
        return node

    def _advance_after_jsx(self, after: str) -> None:
        if after == "child":
            self.next_jsx_child()
        elif after == "tag":
            self.next_jsx_tag()
        else:
            self.next()

    def _parse_jsx_element(self, after: str) -> JsNode:
        start = self.tok
        self.next_jsx_tag()  # consume `<`, next token in tag mode
        node = JsNode("JSXElement", start.start, start.line, start.col, {"name": None, "attributes": [], "children": []})
        if self.is_p(">"):
            node.type = "JSXFragment"
            self.next_jsx_child()
            self.parse_jsx_children(node, None, after)
            return self.finish(node)
        name = self.parse_jsx_tag_name()
        node.fields["name"] = name
        if self.is_p("<") and self.ts:  # <Foo<T> ...>: type arguments on a component
            self.try_type_arguments_jsx()
        attrs: List[JsNode] = node.fields["attributes"]  # type: ignore[assignment]
        while True:
            t = self.tok
            if t.kind == "punct":
                if t.value == "/":
                    self.next_jsx_tag()
                    if not self.is_p(">"):
                        raise self.error("expected '>'")
                    self._advance_after_jsx(after)  # self-closing
                    return self.finish(node)
                if t.value == ">":
                    self.next_jsx_child()
                    self.parse_jsx_children(node, name, after)
                    return self.finish(node)
                if t.value == "{":
                    st = self.next()  # default mode inside braces
                    self.expect("...")
                    spread = JsNode("JSXSpreadAttribute", st.start, st.line, st.col, {})
                    spread.fields["argument"] = self.parse_assignment()
                    if not self.is_p("}"):
                        raise self.error("expected '}'")
                    self.next_jsx_tag()
                    attrs.append(self.finish(spread))
                    continue
                raise self.error()
            if t.kind == "name":
                attr = JsNode("JSXAttribute", t.start, t.line, t.col, {"value": None})
                attr_name = t.value
                self.next_jsx_tag()
                if self.is_p(":"):
                    self.next_jsx_tag()
                    attr_name += ":" + self.tok.value
                    self.next_jsx_tag()
                attr.fields["name"] = attr_name
                if self.is_p("="):
                    self.next_jsx_tag()
                    v = self.tok
                    if v.kind == "str":
                        attr.fields["value"] = JsNode("Literal", v.start, v.line, v.col, {"value": v.value[1:-1], "raw": v.value, "kind": "string"})
                        self.next_jsx_tag()
                    elif v.kind == "punct" and v.value == "{":
                        self.next()
                        container = JsNode("JSXExpressionContainer", v.start, v.line, v.col, {})
                        container.fields["expression"] = None if self.is_p("}") else self.parse_assignment()
                        if not self.is_p("}"):
                            raise self.error("expected '}'")
                        self.next_jsx_tag()
                        attr.fields["value"] = self.finish(container)
                    elif v.kind == "punct" and v.value == "<":
                        attr.fields["value"] = self.parse_jsx_element(after="tag")
                    else:
                        raise self.error("expected attribute value")
                attrs.append(self.finish(attr))
                continue
            raise self.error("unexpected token in JSX tag")

    def try_type_arguments_jsx(self) -> None:
        if self.try_type_arguments():
            # the lexer scanned one default-mode token after `>`: rescan it in tag mode
            t = self.tok
            self.lexer.pos, self.lexer.line, self.lexer.line_start = t.start, t.line, t.start - t.col + 1
            self.tok = self.lexer.scan_jsx_tag()

    def parse_jsx_tag_name(self) -> str:
        t = self.tok
        if t.kind != "name":
            raise self.error("expected JSX tag name")
        name = t.value
        self.next_jsx_tag()
        if self.is_p(":"):
            self.next_jsx_tag()
            name += ":" + self.tok.value
            self.next_jsx_tag()
        while self.is_p("."):
            self.next_jsx_tag()
            name += "." + self.tok.value
            self.next_jsx_tag()
        return name

    def parse_jsx_children(self, node: JsNode, name: Optional[str], after: str) -> None:
        """After the `>` of an opening tag; the current token is in child mode."""
        children: List[JsNode] = node.fields["children"]  # type: ignore[assignment]
        while True:
            t = self.tok
            if t.kind == "jsxtext":
                children.append(JsNode("JSXText", t.start, t.line, t.col, {"value": t.value}))
                self.next_jsx_child()
                continue
            if t.kind == "eof":
                raise self.error("unterminated JSX element")
            if t.value == "{":
                self.next()  # default mode
                container = JsNode("JSXExpressionContainer", t.start, t.line, t.col, {})
                if self.is_p("}"):
                    container.fields["expression"] = None
                elif self.is_p("..."):
                    self.next()
                    container.fields["expression"] = self.parse_assignment()
                else:
                    container.fields["expression"] = self.parse_assignment()
                if not self.is_p("}"):
                    raise self.error("expected '}'")
                children.append(self.finish(container))
                self.next_jsx_child()
                continue
            # `<`: child element or closing tag
            if self.text.startswith("</", t.start):
                self.next_jsx_tag()  # `<`
                self.next_jsx_tag()  # `/`
                if name is None:
                    if not self.is_p(">"):
                        raise self.error("expected '>'")
                else:
                    close_name = self.parse_jsx_tag_name()
                    if close_name != name:
                        raise self.error("mismatched closing tag </%s>" % close_name)
                    if not self.is_p(">"):
                        raise self.error("expected '>'")
                self._advance_after_jsx(after)  # the element is complete
                return
            children.append(self.parse_jsx_element(after="child"))


class JsParseResult:
    __slots__ = ("ast", "errors", "comments", "aborted", "reason", "lines")

    def __init__(self, ast: Optional[JsNode], errors: List[Tuple[int, int, str]], comments: List[Tuple[int, int]],
                 aborted: bool, reason: str, lines: int) -> None:
        self.ast = ast
        self.errors = errors
        self.comments = comments
        self.aborted = aborted
        self.reason = reason
        self.lines = lines

    @property
    def ok(self) -> bool:
        return self.ast is not None and not self.aborted


class JsFullParser(JsParser, JsParserExpressions, JsParserFunctions, JsParserTypes, JsParserJsx):
    pass


def js_parser_enabled() -> bool:
    """The AST path is on unless REPO_SENTRY_JS_PARSER is 0/false/no/off."""
    return os.environ.get("REPO_SENTRY_JS_PARSER", "1").strip().lower() not in ("0", "false", "no", "off")


def js_is_typescript(rel: str) -> bool:
    return os.path.splitext(rel)[1].lower() in (".ts", ".tsx", ".mts", ".cts")


def js_parse(text: str, rel: str = "file.js") -> JsParseResult:
    """Parse a JS/TS file. Never raises. The result is `ok` when the parse
    finished within the depth guard and the error budget (5 per 100 lines,
    at least 5); recovered errors are listed in `errors`."""
    lines = text.count("\n") + 1
    max_errors = max(5, (5 * lines) // 100)
    parser = JsFullParser(text, ts=js_is_typescript(rel), jsx=js_allows_jsx(rel), max_errors=max_errors)
    old_limit = sys.getrecursionlimit()
    needed = JS_PARSER_MAX_DEPTH * 12 + 200
    if old_limit < needed:
        sys.setrecursionlimit(needed)
    try:
        ast_root = parser.parse_program()
    except _JsParseAbort as exc:
        return JsParseResult(None, parser.errors, parser.lexer.comments, True, str(exc), lines)
    except RecursionError:
        return JsParseResult(None, parser.errors, parser.lexer.comments, True, "nesting too deep", lines)
    except Exception as exc:  # internal error: the caller falls back to the heuristic path
        return JsParseResult(None, parser.errors, parser.lexer.comments, True,
                             "internal parser error: %s: %s" % (type(exc).__name__, exc), lines)
    finally:
        if old_limit < needed:
            sys.setrecursionlimit(old_limit)
    errors = sorted(set(parser.errors + parser.lexer.errors))
    if len(errors) > max_errors:
        return JsParseResult(None, errors, parser.lexer.comments, True, "%d syntax errors" % len(errors), lines)
    return JsParseResult(ast_root, errors, parser.lexer.comments, False, "", lines)


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

_JS_SYNC_BLOCKING_RE = re.compile(
    r"(?<![\w$])(?:([A-Za-z_$][\w$]*)\s*\.\s*)?(readFileSync|writeFileSync|appendFileSync|readdirSync|statSync|lstatSync|"
    r"existsSync|mkdirSync|rmSync|rmdirSync|unlinkSync|copyFileSync|renameSync|execSync|execFileSync|spawnSync|"
    r"pbkdf2Sync|scryptSync|gzipSync|gunzipSync|deflateSync|inflateSync|brotliCompressSync)\s*\(")
_JS_ATOMICS_WAIT_RE = re.compile(r"(?<![\w$])Atomics\s*\.\s*wait\s*\(")
_JS_ASYNC_WORD_RE = re.compile(r"(?<![\w$])async\b")
_JS_STMT_START_RE = re.compile(r"(?:(?:this|self)\s*\.\s*)?([A-Za-z_$#][\w$]*)\s*\(")
_JS_STMT_PROMISE_API_RE = re.compile(
    r"((?:fetch|Promise\s*\.\s*(?:all|allSettled|race|any))|[A-Za-z_$][\w$]*\s*\.\s*promises\s*\.\s*[A-Za-z_$][\w$]*)\s*\(")
_JS_FOREACH_ASYNC_RE = re.compile(r"\.\s*forEach\s*\(\s*async\b")
_JS_RESOURCE_ASSIGN_RE = re.compile(
    r"(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?"
    r"(?:(?:fs|fsp|fsPromises|net|tls|http2)\s*\.\s*(?:promises\s*\.\s*)?(createWriteStream|openSync|open|createConnection|connect)\s*\("
    r"|new\s+(?:net\s*\.\s*)?(WebSocket|Socket)\s*\()")
_JS_JS_KEYWORDS_NOT_FUNCS = frozenset(("if", "for", "while", "switch", "catch", "function", "return", "await", "typeof", "new", "super"))


def _js_at_statement_start(masked: str, i: int) -> bool:
    """True when the previous significant character before offset i ends a statement or opens a block (or there is
    none), i.e. an expression starting at i is a statement, not an operand, argument or arrow-function body."""
    k = i - 1
    while k >= 0 and masked[k] in " \t\r\n":
        k -= 1
    return k < 0 or masked[k] in ";{}"


def _js_top_level_args(masked: str, paren: int) -> int:
    """Number of top-level arguments of the call whose `(` is at `paren` (0 for an empty argument list)."""
    close = _js_match_forward(masked, paren, "(", ")")
    inner = masked[paren + 1:close]
    if not inner.strip():
        return 0
    depth = 0
    count = 1
    for ch in inner:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            count += 1
    return count


def _js_statement_end(masked: str, i: int) -> int:
    """End offset (exclusive) of the statement beginning at i: the first `;` at bracket depth 0, or a newline at
    depth 0 whose next significant character does not continue a method chain."""
    n = len(masked)
    depth = 0
    k = i
    while k < n:
        ch = masked[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return k
        elif depth == 0 and ch == ";":
            return k + 1
        elif depth == 0 and ch == "\n":
            j = k + 1
            while j < n and masked[j] in " \t\r\n":
                j += 1
            if j >= n or masked[j] != ".":
                return k
        k += 1
    return n


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

    # -- RS-ASYNC-001/002 and RS-RES-001 for JS/TS (approximate) ----------------
    def _is_async(self, f: "JsFunction") -> bool:
        masked = self.masked
        return bool(_JS_ASYNC_WORD_RE.search(masked[f.start:f.body_start])
                    or masked[max(0, f.start - 8):f.start].rstrip().endswith("async"))

    def run_async_resources(self) -> None:
        if self.test_file:
            return
        masked = self.masked
        want1, want2, wantr = ("RS-ASYNC-001" in self.enabled, "RS-ASYNC-002" in self.enabled, "RS-RES-001" in self.enabled)
        async_funcs = [f for f in self.funcs if self._is_async(f)]
        if want1:
            for f in async_funcs:
                own = js_own_text(masked, f.body_start + 1, f.body_end, f.children)
                base = f.body_start + 1
                for m in _JS_SYNC_BLOCKING_RE.finditer(own):
                    label = (m.group(1) + "." if m.group(1) else "") + m.group(2)
                    self._finding("RS-ASYNC-001", RULES["RS-ASYNC-001"].severity, "medium", base + m.start(),
                                  "Blocking call %s() inside async function '%s' stalls the event loop (approximate JS/TS check)"
                                  % (label, f.name),
                                  "Use the promise-based API (fs.promises.*, util.promisify(child_process.exec), crypto.pbkdf2 "
                                  "with a callback/promise) or move the work to a worker thread.")
                for m in _JS_ATOMICS_WAIT_RE.finditer(own):
                    self._finding("RS-ASYNC-001", RULES["RS-ASYNC-001"].severity, "medium", base + m.start(),
                                  "Atomics.wait() inside async function '%s' blocks the thread (approximate JS/TS check)" % f.name)
        if want2:
            for m in _JS_FOREACH_ASYNC_RE.finditer(masked):
                self._finding("RS-ASYNC-002", RULES["RS-ASYNC-002"].severity, "medium", m.start(),
                              "forEach(async ...) does not wait for its callbacks; errors and ordering are lost (approximate JS/TS check)",
                              "Use `await Promise.all(items.map(async ...))` or a `for...of` loop with await.")
            names = {f.name for f in async_funcs if f.name not in ("<anonymous>", "default", "constructor")}
            for m in _JS_STMT_START_RE.finditer(masked):
                name = m.group(1)
                if name in _JS_JS_KEYWORDS_NOT_FUNCS or name.lstrip("#") not in {n.lstrip("#") for n in names}:
                    continue
                if not _js_at_statement_start(masked, m.start()):
                    continue
                self._floating(m.start(1), m.end() - 1, "async function '%s'" % name)
            for m in _JS_STMT_PROMISE_API_RE.finditer(masked):
                if not _js_at_statement_start(masked, m.start()):
                    continue
                self._floating(m.start(1), m.end() - 1, re.sub(r"\s+", "", m.group(1)) + "()")
            for m in re.finditer(r"([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*|\s*\([^;{}]*?\))*)\s*\.\s*then\s*\(", masked):
                if not _js_at_statement_start(masked, m.start(1)):
                    continue
                end = _js_statement_end(masked, m.start(1))
                stmt = masked[m.start(1):end]
                if re.search(r"\.\s*(catch|finally)\s*\(", stmt) or _js_top_level_args(masked, m.end() - 1) >= 2:
                    continue  # a rejection handler is attached (`.catch`, `.finally` or then(ok, onError))
                self._finding("RS-ASYNC-002", RULES["RS-ASYNC-002"].severity, "medium", m.start(1),
                              "Promise chain with .then() has no .catch(); a rejection becomes an unhandled rejection (approximate JS/TS check)",
                              "Add `.catch(...)`, or `await` the promise inside try/catch.")
        if wantr:
            seen: Set[int] = set()
            for m in _JS_RESOURCE_ASSIGN_RE.finditer(masked):
                if m.start() in seen:
                    continue
                seen.add(m.start())
                var = m.group(1)
                kind = m.group(2) or m.group(3)
                v = re.escape(var)
                released = re.search(
                    r"(?<![\w$.])%s\s*\.\s*(?:close|end|destroy|unref|terminate|removeAllListeners)\s*\(|"
                    r"(?:closeSync|\.close|fs\.close|pipeline|finished|destroy)\s*\(\s*%s\b|"
                    r"\.pipe\s*\(\s*%s\b|(?<![\w$.])%s\s*\.\s*pipe\s*\(|return\s+%s\b|(?:this|self|module|exports)\s*\.[\w$.]*\s*=\s*%s\b|"
                    r"\bexport\b[^;\n]*\b%s\b|\busing\s+%s\b" % (v, v, v, v, v, v, v, v), masked)
                if released:
                    continue
                self._finding("RS-RES-001", RULES["RS-RES-001"].severity, "low", m.start(1),
                              "Resource from %s() assigned to '%s' is never closed, ended, piped, returned or stored (approximate JS/TS check)"
                              % (kind, var),
                              "Close it in a `finally` block (or with `using`), or pass it to stream.pipeline().")

    def _floating(self, call_start: int, paren: int, what: str) -> None:
        masked = self.masked
        close = _js_match_forward(masked, paren, "(", ")")
        end = _js_statement_end(masked, call_start)
        tail = masked[close + 1:end]
        if re.match(r"\s*\.\s*(catch|finally)\s*\(", tail) or re.search(r"\.\s*catch\s*\(", tail):
            return
        t = re.match(r"\s*\.\s*then\s*\(", tail)
        if t and _js_top_level_args(masked, close + 1 + t.end() - 1) >= 2:
            return
        self._finding("RS-ASYNC-002", RULES["RS-ASYNC-002"].severity, "medium", call_start,
                      "Promise from %s is neither awaited, returned nor given .catch(); rejections are lost (approximate JS/TS check)" % what,
                      "`await` it, return it, add `.catch(...)`, or mark intentional fire-and-forget with `void`.")

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
# JavaScript / TypeScript: AST-based analysis (the accurate path)
# --------------------------------------------------------------------------
_JS_FUNCTION_TYPES = frozenset(("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression", "StaticBlock"))
_JS_LOOP_TYPES = frozenset(("ForStatement", "ForInStatement", "ForOfStatement", "WhileStatement", "DoWhileStatement"))
_JS_NESTING_TYPES = frozenset(("IfStatement", "ForStatement", "ForInStatement", "ForOfStatement", "WhileStatement",
                               "DoWhileStatement", "SwitchStatement", "TryStatement"))
_JS_TAINT_NAMES = frozenset(("req", "request", "ctx", "params", "query", "body", "argv"))
_JS_SHELL_MODULES = frozenset(("child_process", "node:child_process", "execa", "shelljs"))
_JS_SHELL_PREFIXES = frozenset(("child_process", "cp", "childProcess", "proc", "sh", "shell", "shelljs", "execa"))
_JS_FS_MODULES = frozenset(("fs", "node:fs", "fs/promises", "node:fs/promises", "fs-extra", "graceful-fs"))
_JS_FS_PREFIXES = frozenset(("fs", "fsp", "fsPromises", "promises", "fse"))
_JS_FS_PATH_METHODS = frozenset(("readFile", "readFileSync", "createReadStream", "createWriteStream", "writeFile",
                                 "writeFileSync", "appendFile", "appendFileSync", "unlink", "unlinkSync", "readdir",
                                 "readdirSync", "rm", "rmSync", "rmdir", "rmdirSync", "open", "openSync", "stat",
                                 "statSync", "access", "accessSync", "copyFile", "copyFileSync", "rename", "renameSync"))
_JS_SYNC_BLOCKING = frozenset((
    "readFileSync", "writeFileSync", "appendFileSync", "readdirSync", "statSync", "lstatSync", "existsSync", "mkdirSync",
    "rmSync", "rmdirSync", "unlinkSync", "copyFileSync", "renameSync", "execSync", "execFileSync", "spawnSync",
    "pbkdf2Sync", "scryptSync", "randomBytesSync", "gzipSync", "gunzipSync", "deflateSync", "inflateSync",
    "brotliCompressSync", "brotliDecompressSync", "accessSync", "openSync", "readSync", "writeSync", "closeSync",
))
_JS_RESOURCE_METHODS = frozenset(("createWriteStream", "createReadStream", "openSync", "open", "createConnection", "connect"))
_JS_RESOURCE_ROOTS = frozenset(("fs", "fsp", "fsPromises", "promises", "net", "tls", "http2"))
_JS_RELEASE_METHODS = frozenset(("close", "end", "destroy", "unref", "terminate", "removeAllListeners", "pipe"))
_JS_READ_CONSUME_METHODS = frozenset(("on", "once", "read", "resume", "pipe", "addListener"))
_JS_RELEASE_FUNCS = frozenset(("clearInterval", "pipeline", "finished", "closeSync", "close", "destroy"))
_JS_SECRET_IDENT_RE = _JS_SEC_SECRET_IDENT_RE


class JsFunctionInfo:
    __slots__ = ("node", "name", "parent", "children", "is_async", "own", "class_name")

    def __init__(self, node: JsNode, name: str, parent: Optional["JsFunctionInfo"]) -> None:
        self.node = node
        self.name = name
        self.parent = parent
        self.children: List["JsFunctionInfo"] = []
        self.is_async = bool(node.fields.get("async"))
        self.own: List[JsNode] = []   # nodes directly inside this function (nested functions excluded)
        self.class_name = ""


def _js_member_root(node: JsNode) -> Optional[str]:
    """Identifier name at the root of a member chain (`a` for a.b.c), else None."""
    while node.type == "MemberExpression":
        node = node.fields["object"]  # type: ignore[assignment]
    if node.type == "Identifier":
        return node.fields["name"]  # type: ignore[return-value]
    return None


def _js_member_path(node: JsNode) -> Optional[str]:
    """Dotted path for a non-computed member chain rooted at an identifier (`process.env.X`)."""
    parts: List[str] = []
    while node.type == "MemberExpression":
        if node.fields["computed"]:
            prop = node.fields["property"]
            if isinstance(prop, JsNode) and prop.type == "Literal" and prop.fields.get("kind") == "string":
                parts.append(str(prop.fields["value"]))
            else:
                return None
        else:
            parts.append(str(node.fields["property"]))
        node = node.fields["object"]  # type: ignore[assignment]
    if node.type == "Identifier":
        parts.append(node.fields["name"])  # type: ignore[arg-type]
    elif node.type == "ThisExpression":
        parts.append("this")
    else:
        return None
    return ".".join(reversed(parts))


def _js_callee_name(call: JsNode) -> Tuple[Optional[str], Optional[str]]:
    """(identifier name, None) for `f(...)`, (object path, property) for `a.b.f(...)`."""
    callee = call.fields["callee"]
    if callee.type == "Identifier":
        return callee.fields["name"], None  # type: ignore[return-value]
    if callee.type == "MemberExpression" and not callee.fields["computed"]:
        return _js_member_path(callee.fields["object"]), callee.fields["property"]  # type: ignore[return-value]
    return None, None


def _js_pattern_names(node: Optional[JsNode]) -> List[str]:
    """Identifier names bound by a binding pattern."""
    out: List[str] = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n is None:
            continue
        t = n.type
        if t == "Identifier":
            out.append(n.fields["name"])  # type: ignore[arg-type]
        elif t == "ObjectPattern":
            for p in n.fields["properties"]:  # type: ignore[union-attr]
                stack.append(p.fields["value"] if p.type == "Property" else p)
        elif t == "ArrayPattern":
            stack.extend(n.fields["elements"])  # type: ignore[arg-type]
        elif t == "AssignmentPattern":
            stack.append(n.fields["left"])  # type: ignore[arg-type]
        elif t == "RestElement":
            stack.append(n.fields["argument"])  # type: ignore[arg-type]
    return out


def _js_unwrap(node: JsNode) -> JsNode:
    while node.type in ("ParenthesizedExpression", "TSAsExpression", "TSNonNullExpression", "TSTypeAssertion",
                        "TSSatisfiesExpression", "AwaitExpression"):
        node = node.fields.get("expression") or node.fields.get("argument")  # type: ignore[assignment]
    return node


def _js_string_value(node: Optional[JsNode]) -> Optional[str]:
    """The constant string value of a literal or expression-free template, else None."""
    if node is None:
        return None
    node = _js_unwrap(node)
    if node.type == "Literal" and node.fields.get("kind") == "string":
        return str(node.fields["value"])
    if node.type == "TemplateLiteral" and not node.fields["expressions"]:
        return "".join(node.fields["quasis"])  # type: ignore[arg-type]
    return None


class JsAstAnalyzer:
    """All JS/TS rules evaluated on one parsed file. Findings are buffered and
    flushed by the caller so an internal error can fall back cleanly."""

    def __init__(self, sf: SourceFile, parsed: JsParseResult, config: Config, enabled: Set[str]) -> None:
        self.sf = sf
        self.ast = parsed.ast
        self.parsed = parsed
        self.config = config
        self.enabled = enabled
        self.text = sf.text
        self.starts = js_line_starts(sf.text)
        self.test_file = js_is_test_file(sf.rel)
        self.findings: List[Finding] = []
        self.functions: List[JsFunctionInfo] = []
        self.module_own: List[JsNode] = []
        self.all_nodes: List[JsNode] = []
        self.const_literals: Dict[str, JsNode] = {}
        self.module_bindings: Dict[str, Tuple[str, Optional[str]]] = {}   # local name -> (module, member)
        self.module_sources: Set[str] = set()
        self.async_names: Set[str] = set()
        self.declared_names: Set[str] = set()
        self._taint_cache: Dict[int, Set[str]] = {}
        self._code_lines: Optional[List[str]] = None
        self._collect()

    # -- collection ---------------------------------------------------------
    def _collect(self) -> None:
        assert self.ast is not None
        decl_counts: Dict[str, int] = {}
        stack: List[Tuple[JsNode, Optional[str], str, Optional[JsFunctionInfo]]] = [(self.ast, None, "", None)]
        pop, push = stack.pop, stack.append
        while stack:
            node, hint, class_name, func = pop()
            t = node.type
            self.all_nodes.append(node)
            if t in _JS_FUNCTION_TYPES:
                if t == "StaticBlock":
                    name = (class_name + ".<static>") if class_name else "<static>"
                else:
                    name = node.fields.get("id") or hint or "<anonymous>"  # type: ignore[assignment]
                info = JsFunctionInfo(node, str(name), func)
                info.class_name = class_name
                if func is not None:
                    func.children.append(info)
                self.functions.append(info)
                if info.is_async and name not in ("<anonymous>", "default"):
                    self.async_names.add(str(name).split(".")[-1].split(" ")[-1])
                func = info
            else:
                (func.own if func is not None else self.module_own).append(node)
            fields = node.fields
            if t == "VariableDeclaration":
                for d in fields["declarations"]:  # type: ignore[union-attr]
                    ident = d.fields["id"]
                    if ident.type == "Identifier":
                        nm = ident.fields["name"]
                        decl_counts[nm] = decl_counts.get(nm, 0) + 1
                        init = d.fields.get("init")
                        if fields["kind"] == "const" and init is not None and _js_is_literal_like(init):
                            self.const_literals[nm] = init
                    for nm in _js_pattern_names(ident):
                        self.declared_names.add(nm)
                    if func is None:
                        self._record_module_binding(d)
            elif t == "FunctionDeclaration" and fields.get("id"):
                self.declared_names.add(str(fields["id"]))
            elif t == "ImportDeclaration" and func is None:
                self._record_import_binding(node)
            elif t == "TSImportEqualsDeclaration" and fields.get("source") is not None:
                self.module_sources.add(str(fields["source"].fields["value"]))
                self.module_bindings[str(fields["id"])] = (str(fields["source"].fields["value"]), None)
            elif t == "ClassDeclaration" or t == "ClassExpression":
                class_name = str(fields.get("id") or hint or "")
            elif t == "CallExpression" or t == "ImportExpression":
                source = self._require_source(node)
                if source is not None:
                    self.module_sources.add(source)
            # children with naming hints, pushed in reverse so they pop in source order
            kids: List[Tuple[JsNode, Optional[str]]] = []
            if t == "VariableDeclarator":
                ident = fields["id"]
                kids.append((ident, None))
                init = fields.get("init")
                if init is not None:
                    kids.append((init, ident.fields["name"] if ident.type == "Identifier" else None))
            elif t == "Property":
                key = fields["key"]
                kname = None if fields.get("computed") else str(key)
                if fields.get("kind") in ("get", "set") and kname:
                    kname = fields["kind"] + " " + kname
                if isinstance(key, JsNode):
                    kids.append((key, None))
                kids.append((fields["value"], kname))
            elif t == "AssignmentExpression":
                left = fields["left"]
                kids.append((left, None))
                lname: Optional[str] = None
                if fields["operator"] == "=":
                    if left.type == "Identifier":
                        lname = left.fields["name"]
                    elif left.type == "MemberExpression" and not left.fields["computed"]:
                        lname = str(left.fields["property"])
                kids.append((fields["right"], lname))
            elif t == "MethodDefinition" or t == "PropertyDefinition":
                key = fields["key"]
                kname = "[computed]" if fields.get("computed") else str(key)
                qualified = (class_name + "." + kname) if class_name else kname
                kind = fields.get("kind")
                if kind in ("get", "set"):
                    qualified = kind + " " + qualified
                if isinstance(key, JsNode):
                    kids.append((key, None))
                value = fields.get("value")
                if value is not None:
                    kids.append((value, qualified))
            elif t == "ExportDefaultDeclaration":
                kids.append((fields["declaration"], "default"))
            else:
                for value in fields.values():
                    if isinstance(value, JsNode):
                        kids.append((value, None))
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, JsNode):
                                kids.append((item, None))
            for i in range(len(kids) - 1, -1, -1):
                push((kids[i][0], kids[i][1], class_name, func))
        for nm, count in decl_counts.items():
            if count > 1:
                self.const_literals.pop(nm, None)

    def _record_import_binding(self, node: JsNode) -> None:
        source = node.fields.get("source")
        if source is None:
            return
        module = str(source.fields["value"])
        self.module_sources.add(module)
        for spec in node.fields["specifiers"]:  # type: ignore[union-attr]
            local = str(spec.fields["local"])
            if spec.type == "ImportSpecifier":
                self.module_bindings[local] = (module, str(spec.fields["imported"]))
            else:
                self.module_bindings[local] = (module, None)

    def _record_module_binding(self, declarator: JsNode) -> None:
        """`const cp = require('x')`, `const { exec: run } = require('x')`, `const exec = require('x').exec`."""
        init = declarator.fields.get("init")
        if init is None:
            return
        init = _js_unwrap(init)
        member: Optional[str] = None
        if init.type == "MemberExpression" and not init.fields["computed"]:
            member = str(init.fields["property"])
            init = _js_unwrap(init.fields["object"])  # type: ignore[arg-type]
        module = self._require_source(init)
        if module is None:
            return
        self.module_sources.add(module)
        ident = declarator.fields["id"]
        if ident.type == "Identifier":
            self.module_bindings[ident.fields["name"]] = (module, member)  # type: ignore[index]
        elif ident.type == "ObjectPattern" and member is None:
            for p in ident.fields["properties"]:  # type: ignore[union-attr]
                if p.type != "Property" or p.fields.get("computed"):
                    continue
                value = p.fields["value"]
                if value.type == "AssignmentPattern":
                    value = value.fields["left"]
                if value.type == "Identifier":
                    self.module_bindings[value.fields["name"]] = (module, str(p.fields["key"]))  # type: ignore[index]

    @staticmethod
    def _require_source(node: JsNode) -> Optional[str]:
        if node.type == "CallExpression" and node.fields["callee"].type == "Identifier" \
                and node.fields["callee"].fields["name"] == "require" and node.fields["arguments"]:
            return _js_string_value(node.fields["arguments"][0])  # type: ignore[index]
        if node.type == "ImportExpression":
            return _js_string_value(node.fields["source"])  # type: ignore[arg-type]
        return None

    def uses_module(self, modules: "frozenset[str]") -> bool:
        return bool(self.module_sources & modules)

    # -- findings -----------------------------------------------------------
    def _finding(self, rule_id: str, severity: str, confidence: str, offset: int, message: str,
                 remediation: Optional[str] = None) -> None:
        line, col = js_line_col(self.starts, offset)
        self.findings.append(Finding(rule_id, severity, confidence, self.sf.rel, line, col, message,
                                     self.sf.snippet(line), remediation or RULES[rule_id].remediation))

    def end_line(self, node: JsNode) -> int:
        return js_line_col(self.starts, max(node.start, node.end - 1))[0]

    # -- quality ------------------------------------------------------------
    @staticmethod
    def complexity(func: JsFunctionInfo) -> int:
        score = 1
        for n in func.own:
            t = n.type
            if t == "IfStatement" or t == "ConditionalExpression" or t == "CatchClause" or t in _JS_LOOP_TYPES:
                score += 1
            elif t == "LogicalExpression":
                score += 1
            elif t == "SwitchCase":
                if n.fields.get("test") is not None:
                    score += 1
            elif t == "AssignmentExpression":
                if n.fields["operator"] in ("&&=", "||=", "??="):
                    score += 1
        return score

    @staticmethod
    def max_nesting(root: JsNode, skip_root: bool) -> Tuple[int, int]:
        """(max depth, offset of the deepest block statement) counting nested
        if/for/while/do/switch/try; `else if` and catch/finally do not add depth."""
        best_depth, best_pos = 0, -1
        stack: List[Tuple[JsNode, int, bool]] = [(root, 0, False)]
        while stack:
            node, depth, is_else_if = stack.pop()
            t = node.type
            if t in _JS_FUNCTION_TYPES and node is not root:
                continue
            if t in _JS_NESTING_TYPES and not is_else_if:
                depth += 1
                if depth > best_depth:
                    best_depth, best_pos = depth, node.start
            kids = js_children(node)
            for i in range(len(kids) - 1, -1, -1):
                kid = kids[i]
                stack.append((kid, depth, t == "IfStatement" and kid is node.fields.get("alternate") and kid.type == "IfStatement"))
        return best_depth, best_pos

    def run_quality(self) -> None:
        th = self.config.thresholds
        max_cc = th.get("max_cyclomatic_complexity", 10)
        max_depth = th.get("max_nesting_depth", 4)
        want_cc = "RS-QUAL-001" in self.enabled
        want_depth = "RS-QUAL-002" in self.enabled
        if (want_cc or want_depth) and not self.test_file:
            for f in self.functions:
                if want_cc:
                    cc = self.complexity(f)
                    if cc > max_cc:
                        severity = "high" if cc > 2 * max_cc else "medium"
                        self._finding("RS-QUAL-001", severity, "high", f.node.start,
                                      "Function '%s' has cyclomatic complexity %d (threshold %d)" % (f.name, cc, max_cc))
                if want_depth:
                    depth, pos = self.max_nesting(f.node, True)
                    if depth > max_depth and pos >= 0:
                        self._finding("RS-QUAL-002", RULES["RS-QUAL-002"].severity, "high", pos,
                                      "Nesting depth %d exceeds %d in function '%s'" % (depth, max_depth, f.name))
            if want_depth:
                depth, pos = self.max_nesting(self.ast, True)  # type: ignore[arg-type]
                if depth > max_depth and pos >= 0:
                    self._finding("RS-QUAL-002", RULES["RS-QUAL-002"].severity, "high", pos,
                                  "Nesting depth %d exceeds %d in module scope" % (depth, max_depth))
        if "RS-QUAL-004" in self.enabled:
            for n in self.all_nodes:
                if n.type == "CatchClause" and not n.fields["body"].fields["body"]:
                    self._finding("RS-QUAL-004", RULES["RS-QUAL-004"].severity, "high", n.start,
                                  "Empty catch block silently swallows errors")

    # -- imports ------------------------------------------------------------
    def collect_imports(self) -> List["JsImport"]:
        found: Dict[int, JsImport] = {}

        def add(source: Optional[JsNode], soft: bool) -> None:
            if source is None:
                return
            spec = _js_string_value(source)
            if not spec or "\n" in spec or source.start in found:
                return
            line, col = js_line_col(self.starts, source.start)
            found[source.start] = JsImport(spec, line, col, soft, self.sf.snippet(line))

        for n in self.module_own:
            t = n.type
            if t == "ImportDeclaration":
                add(n.fields.get("source"), bool(n.fields.get("typeOnly")))  # type: ignore[arg-type]
            elif t in ("ExportNamedDeclaration", "ExportAllDeclaration"):
                add(n.fields.get("source"), bool(n.fields.get("typeOnly")))  # type: ignore[arg-type]
            elif t == "TSImportEqualsDeclaration":
                add(n.fields.get("source"), False)  # type: ignore[arg-type]
            elif t == "CallExpression":
                if self._require_source(n) is not None:
                    add(n.fields["arguments"][0], False)  # type: ignore[index]
            elif t == "ImportExpression":
                add(n.fields["source"], True)  # type: ignore[arg-type]
        for f in self.functions:
            for n in f.own:
                t = n.type
                if t == "CallExpression" and self._require_source(n) is not None:
                    add(n.fields["arguments"][0], True)  # type: ignore[index]
                elif t == "ImportExpression":
                    add(n.fields["source"], True)  # type: ignore[arg-type]
        return [found[k] for k in sorted(found)]

    # -- taint-lite (intra-function, flow-insensitive) ----------------------
    def tainted_names(self, func: Optional[JsFunctionInfo]) -> Set[str]:
        key = id(func.node) if func is not None else 0
        cached = self._taint_cache.get(key)
        if cached is not None:
            return cached
        names: Set[str] = set() if func is None else set(self.tainted_names(func.parent))
        if func is not None:
            for p in func.node.fields.get("params", ()):  # type: ignore[union-attr]
                target = p.fields["left"] if p.type == "AssignmentPattern" else p
                if target.type == "Identifier" and target.fields["name"] in _JS_TAINT_NAMES:
                    names.add(target.fields["name"])  # type: ignore[arg-type]
        own = self.module_own if func is None else func.own
        for _ in range(3):
            changed = False
            for n in own:
                t = n.type
                if t == "VariableDeclarator":
                    init = n.fields.get("init")
                    if init is not None and self.is_tainted(init, names):
                        for nm in _js_pattern_names(n.fields["id"]):  # type: ignore[arg-type]
                            if nm not in names:
                                names.add(nm)
                                changed = True
                elif t == "AssignmentExpression":
                    left = n.fields["left"]
                    if left.type == "Identifier" and left.fields["name"] not in names and self.is_tainted(n.fields["right"], names):  # type: ignore[arg-type]
                        names.add(left.fields["name"])  # type: ignore[arg-type]
                        changed = True
            if not changed:
                break
        self._taint_cache[key] = names
        return names

    @staticmethod
    def is_tainted(expr: JsNode, names: Set[str]) -> bool:
        stack = [expr]
        while stack:
            n = stack.pop()
            t = n.type
            if t == "Identifier":
                if n.fields["name"] in _JS_TAINT_NAMES or n.fields["name"] in names:
                    return True
                continue
            if t in _JS_FUNCTION_TYPES:
                continue
            if t == "MemberExpression":
                obj = n.fields["object"]
                if obj.type == "Identifier" and obj.fields["name"] == "process" and not n.fields["computed"] \
                        and n.fields["property"] in ("argv", "env"):
                    return True
            stack.extend(js_children(n))
        return False

    def is_constant(self, expr: Optional[JsNode]) -> bool:
        if expr is None:
            return True
        stack = [expr]
        while stack:
            n = _js_unwrap(stack.pop())
            t = n.type
            if t == "Literal":
                continue
            if t == "TemplateLiteral":
                if n.fields["expressions"]:
                    stack.extend(n.fields["expressions"])  # type: ignore[arg-type]
                continue
            if t == "Identifier":
                if n.fields["name"] in self.const_literals and n.fields["name"] not in _JS_TAINT_NAMES:
                    continue
                return False
            if t == "BinaryExpression" and n.fields["operator"] == "+":
                stack.append(n.fields["left"])  # type: ignore[arg-type]
                stack.append(n.fields["right"])  # type: ignore[arg-type]
                continue
            if t == "UnaryExpression":
                stack.append(n.fields["argument"])  # type: ignore[arg-type]
                continue
            return False
        return True

    def tier(self, expr: Optional[JsNode], func: Optional[JsFunctionInfo], levels: Tuple[str, str, str]) -> Tuple[str, str]:
        """(severity, description) for a sink argument: tainted / untainted non-constant / constant."""
        if self.is_constant(expr):
            return levels[2], "constant"
        if expr is not None and self.is_tainted(expr, self.tainted_names(func)):
            return levels[0], "request-tainted"
        return levels[1], "non-constant"


def _js_is_literal_like(node: JsNode) -> bool:
    node = _js_unwrap(node)
    if node.type == "Literal":
        return True
    if node.type == "TemplateLiteral" and not node.fields["expressions"]:
        return True
    if node.type == "UnaryExpression" and node.fields["operator"] in ("-", "+") and _js_unwrap(node.fields["argument"]).type == "Literal":  # type: ignore[arg-type]
        return True
    return False


_JS_RESOURCE_MODULES = _JS_FS_MODULES | frozenset(("net", "node:net", "tls", "node:tls", "http2", "node:http2"))


class JsAstRules(JsAstAnalyzer):
    """Security, async and resource rules on the AST."""

    _EXEC_LEVELS = ("critical", "high", "medium")
    _XSS_LEVELS = ("high", "medium", "low")

    def run(self) -> None:
        self.run_quality()
        if "RS-SEC-003" in self.enabled or "RS-SEC-004" in self.enabled:
            self.run_sinks()
        if "RS-SEC-006" in self.enabled:
            self.run_security()
        if self.enabled & {"RS-ASYNC-001", "RS-ASYNC-002", "RS-RES-001"} and not self.test_file:
            self.run_async_resources()

    def _scopes(self) -> Iterator[Tuple[Optional[JsFunctionInfo], List[JsNode]]]:
        yield None, self.module_own
        for f in self.functions:
            yield f, f.own

    # -- RS-SEC-003 / RS-SEC-004 --------------------------------------------
    def _is_shell_exec(self, call: JsNode) -> Optional[str]:
        """Name of the shell function when `call` runs child_process.exec/execSync (or execa/shelljs)."""
        callee = call.fields["callee"]
        if callee.type == "Identifier":
            name = callee.fields["name"]
            if name not in ("exec", "execSync"):
                return None
            bound = self.module_bindings.get(name)
            if bound is not None:
                return name if bound[0] in _JS_SHELL_MODULES else None
            if self.uses_module(_JS_SHELL_MODULES) and name not in self.declared_names:
                return name
            return None
        if callee.type == "MemberExpression" and not callee.fields["computed"]:
            prop = str(callee.fields["property"])
            if prop not in ("exec", "execSync"):
                return None
            obj = _js_unwrap(callee.fields["object"])  # type: ignore[arg-type]
            if obj.type == "Identifier":
                bound = self.module_bindings.get(obj.fields["name"])  # type: ignore[arg-type]
                if bound is not None:
                    return prop if bound[0] in _JS_SHELL_MODULES and bound[1] is None else None
                if self.uses_module(_JS_SHELL_MODULES) and obj.fields["name"] in _JS_SHELL_PREFIXES:
                    return prop
                return None
            if self._require_source(obj) in _JS_SHELL_MODULES:
                return prop
        return None

    def _is_spawn_with_shell(self, call: JsNode) -> Optional[str]:
        name, prop = _js_callee_name(call)
        fn = prop or name
        if fn not in ("spawn", "spawnSync", "execFile", "execFileSync"):
            return None
        if prop is None:
            bound = self.module_bindings.get(fn)  # type: ignore[arg-type]
            if bound is not None and bound[0] not in _JS_SHELL_MODULES:
                return None
        elif name is not None:
            bound = self.module_bindings.get(name.split(".")[0])
            if bound is not None and bound[0] not in _JS_SHELL_MODULES:
                return None
        if not self.uses_module(_JS_SHELL_MODULES):
            return None
        for arg in call.fields["arguments"]:  # type: ignore[union-attr]
            if arg.type == "ObjectExpression":
                for p in arg.fields["properties"]:  # type: ignore[union-attr]
                    if p.type == "Property" and not p.fields.get("computed") and str(p.fields["key"]) == "shell":
                        v = _js_unwrap(p.fields["value"])  # type: ignore[arg-type]
                        if v.type == "Literal" and v.fields.get("value") is True:
                            return fn
        return None

    def _sink(self, rule_id: str, offset: int, severity: str, message: str) -> None:
        if self.test_file:
            severity = _downgrade(severity)
        self._finding(rule_id, severity, "high", offset, message)

    def run_sinks(self) -> None:
        want3 = "RS-SEC-003" in self.enabled
        want4 = "RS-SEC-004" in self.enabled
        for func, own in self._scopes():
            for n in own:
                t = n.type
                if t == "CallExpression":
                    args = n.fields["arguments"]
                    first = args[0] if args else None  # type: ignore[index]
                    if want3:
                        shell = self._is_shell_exec(n)
                        if shell:
                            sev, desc = self.tier(first, func, self._EXEC_LEVELS)
                            self._sink("RS-SEC-003", n.start, sev,
                                       "Shell command execution via child_process.%s() with %s argument" % (shell, desc))
                            continue
                        spawn = self._is_spawn_with_shell(n)
                        if spawn:
                            sev, desc = self.tier(first, func, self._EXEC_LEVELS)
                            self._sink("RS-SEC-003", n.start, sev,
                                       "child_process.%s() with shell: true and %s command" % (spawn, desc))
                            continue
                    if not want4:
                        continue
                    name, prop = _js_callee_name(n)
                    if prop is None and name == "eval" or prop == "eval" and name in ("window", "globalThis", "global", "self"):
                        sev, desc = self.tier(first, func, self._EXEC_LEVELS)
                        self._sink("RS-SEC-004", n.start, sev, "eval() on a %s expression" % desc)
                    elif prop is None and name == "Function":
                        sev, desc = self.tier(args[-1] if args else None, func, self._EXEC_LEVELS)  # type: ignore[index]
                        self._sink("RS-SEC-004", n.start, sev, "Function() builds code from a %s string" % desc)
                    elif (prop or name) in ("setTimeout", "setInterval") and (prop is None or name in ("window", "globalThis", "global")) and first is not None:
                        if self._is_string_like(first, func):
                            sev, desc = self.tier(first, func, self._EXEC_LEVELS)
                            self._sink("RS-SEC-004", n.start, sev,
                                       "%s() with a string argument is an implicit eval (%s)" % (prop or name, desc))
                    elif prop in ("write", "writeln") and name == "document":
                        sev, desc = self.tier(first, func, self._XSS_LEVELS)
                        self._sink("RS-SEC-004", n.start, sev, "document.%s() with %s HTML (XSS sink)" % (prop, desc))
                    elif prop == "insertAdjacentHTML":
                        sev, desc = self.tier(args[1] if len(args) > 1 else None, func, self._XSS_LEVELS)  # type: ignore[arg-type]
                        self._sink("RS-SEC-004", n.start, sev, "insertAdjacentHTML() injects %s HTML (XSS sink)" % desc)
                elif t == "NewExpression" and want4:
                    callee = n.fields["callee"]
                    if callee.type == "Identifier" and callee.fields["name"] == "Function":
                        args = n.fields["arguments"]
                        sev, desc = self.tier(args[-1] if args else None, func, self._EXEC_LEVELS)  # type: ignore[index]
                        self._sink("RS-SEC-004", n.start, sev, "new Function() builds code from a %s string" % desc)
                elif t == "AssignmentExpression" and want4:
                    left = n.fields["left"]
                    if left.type == "MemberExpression" and n.fields["operator"] in ("=", "+="):
                        prop = left.fields["property"]
                        if left.fields["computed"]:
                            prop = _js_string_value(prop) if isinstance(prop, JsNode) else None
                        if prop in ("innerHTML", "outerHTML"):
                            sev, desc = self.tier(n.fields["right"], func, self._XSS_LEVELS)  # type: ignore[arg-type]
                            self._sink("RS-SEC-004", left.start, sev,
                                       "Assignment to %s with %s HTML (XSS sink)" % (prop, desc))

    def _is_string_like(self, expr: JsNode, func: Optional[JsFunctionInfo]) -> bool:
        """A sink argument that is a string (literal, template, concatenation, string constant or tainted value)."""
        e = _js_unwrap(expr)
        if e.type == "Literal":
            return e.fields.get("kind") == "string"
        if e.type == "TemplateLiteral" or (e.type == "BinaryExpression" and e.fields["operator"] == "+"):
            return True
        if e.type == "Identifier":
            lit = self.const_literals.get(e.fields["name"])  # type: ignore[arg-type]
            if lit is not None:
                return _js_string_value(lit) is not None
            return self.is_tainted(e, self.tainted_names(func))
        return self.is_tainted(e, self.tainted_names(func))

    # -- RS-SEC-006 ---------------------------------------------------------
    def _sec(self, severity: str, confidence: str, offset: int, message: str) -> None:
        if self.test_file:
            severity = _downgrade(severity)
        self._finding("RS-SEC-006", severity, confidence, offset, message)

    def _code_line_window(self, line: int) -> str:
        if self._code_lines is None:
            text = self.text
            if self.parsed.comments:
                pieces: List[str] = []
                pos = 0
                for a, b in self.parsed.comments:
                    if a < pos:
                        continue
                    pieces.append(text[pos:a])
                    pieces.append(_JS_NOT_NEWLINE_RE.sub(" ", text[a:b]))
                    pos = b
                pieces.append(text[pos:])
                text = "".join(pieces)
            self._code_lines = text.splitlines()
        lines = self._code_lines
        return "\n".join(lines[max(0, line - 4):line + 3])

    @staticmethod
    def _prop(obj: JsNode, key: str) -> Optional[JsNode]:
        for p in obj.fields["properties"]:  # type: ignore[union-attr]
            if p.type == "Property" and not p.fields.get("computed") and str(p.fields["key"]) == key:
                return p
        return None

    def _is_fs_call(self, call: JsNode) -> Optional[str]:
        name, prop = _js_callee_name(call)
        fn = prop or name
        if fn not in _JS_FS_PATH_METHODS:
            return None
        if prop is None:
            bound = self.module_bindings.get(fn)  # type: ignore[arg-type]
            if bound is not None:
                return fn if bound[0] in _JS_FS_MODULES else None
            return fn if self.uses_module(_JS_FS_MODULES) and fn not in self.declared_names else None
        root = (name or "").split(".")[0]
        bound = self.module_bindings.get(root)
        if bound is not None:
            return fn if bound[0] in _JS_FS_MODULES else None
        if root in _JS_FS_PREFIXES and self.uses_module(_JS_FS_MODULES):
            return fn
        if name is None:
            obj = _js_unwrap(call.fields["callee"].fields["object"])  # type: ignore[arg-type]
            if self._require_source(obj) in _JS_FS_MODULES:
                return fn
        return None

    def run_security(self) -> None:
        for func, own in self._scopes():
            tainted: Optional[Set[str]] = None
            for n in own:
                t = n.type
                if t == "Property":
                    if n.fields.get("computed") or n.fields.get("shorthand"):
                        continue
                    key = str(n.fields["key"])
                    value = n.fields["value"]
                    if not isinstance(value, JsNode):
                        continue
                    v = _js_unwrap(value)
                    if key == "rejectUnauthorized" and v.type == "Literal" and v.fields.get("value") is False:
                        self._sec("high", "high", n.start, "TLS certificate verification disabled with rejectUnauthorized: false")
                    elif key == "algorithms" and v.type == "ArrayExpression":
                        if any(el is not None and (_js_string_value(el) or "").lower() == "none" for el in v.fields["elements"]):  # type: ignore[union-attr]
                            self._sec("high", "high", n.start, "JWT verification accepts the 'none' algorithm")
                    elif key == "algorithm" and (_js_string_value(v) or "").lower() == "none":
                        self._sec("high", "high", n.start, "JWT signing/verification uses the 'none' algorithm")
                    elif key == "dangerouslySetInnerHTML" and v.type == "ObjectExpression":
                        self._dsih(v, n.start, func)
                elif t == "ObjectExpression":
                    origin = self._prop(n, "origin")
                    cred = self._prop(n, "credentials")
                    if origin is not None and cred is not None and _js_string_value(origin.fields["value"]) == "*":  # type: ignore[arg-type]
                        cv = _js_unwrap(cred.fields["value"])  # type: ignore[arg-type]
                        if cv.type == "Literal" and cv.fields.get("value") is True:
                            self._sec("medium", "high", origin.start, "CORS wildcard origin '*' combined with credentials: true")
                elif t == "AssignmentExpression":
                    left = n.fields["left"]
                    if left.type == "MemberExpression":
                        path = _js_member_path(left)
                        if path == "process.env.NODE_TLS_REJECT_UNAUTHORIZED":
                            v = _js_unwrap(n.fields["right"])  # type: ignore[arg-type]
                            if _js_string_value(v) == "0" or (v.type == "Literal" and v.fields.get("value") == "0"):
                                self._sec("high", "high", n.start, "TLS certificate verification disabled via NODE_TLS_REJECT_UNAUTHORIZED='0'")
                elif t == "CallExpression":
                    name, prop = _js_callee_name(n)
                    fn = prop or name
                    args = n.fields["arguments"]
                    if fn == "createHash" and args:
                        algo = _js_string_value(args[0])  # type: ignore[index]
                        if algo is None and args[0].type == "Identifier":  # type: ignore[index]
                            algo = _js_string_value(self.const_literals.get(args[0].fields["name"]))  # type: ignore[index]
                        if algo and algo.strip().lower() in ("md5", "sha1", "sha-1"):
                            self._sec("medium", "high", n.start,
                                      "Weak hash createHash('%s'); unsuitable for passwords or signatures (fine for non-security checksums)"
                                      % algo.strip().lower())
                    elif prop == "random" and name == "Math":
                        line = js_line_col(self.starts, n.start)[0]
                        ident = _JS_SECRET_IDENT_RE.search(self._code_line_window(line))
                        if ident:
                            self._sec("medium", "medium", n.start,
                                      "Math.random() used near '%s'; not cryptographically secure" % ident.group(0))
                    elif args and fn in _JS_FS_PATH_METHODS:
                        fs_fn = self._is_fs_call(n)
                        if fs_fn:
                            if tainted is None:
                                tainted = self.tainted_names(func)
                            if self.is_tainted(args[0], tainted):  # type: ignore[index]
                                self._sec("medium", "high", n.start,
                                          "fs.%s() path built from request data (possible path traversal)" % fs_fn)
                elif t == "NewExpression":
                    callee = n.fields["callee"]
                    args = n.fields["arguments"]
                    if callee.type == "Identifier" and callee.fields["name"] == "RegExp" and args:
                        if tainted is None:
                            tainted = self.tainted_names(func)
                        if self.is_tainted(args[0], tainted):  # type: ignore[index]
                            self._sec("low", "high", n.start, "new RegExp() built from request data (ReDoS / pattern injection)")
                elif t == "JSXAttribute" and n.fields.get("name") == "dangerouslySetInnerHTML":
                    value = n.fields.get("value")
                    if value is not None and value.type == "JSXExpressionContainer" and value.fields.get("expression") is not None:
                        obj = _js_unwrap(value.fields["expression"])  # type: ignore[arg-type]
                        if obj.type == "ObjectExpression":
                            self._dsih(obj, n.start, func)

    def _dsih(self, obj: JsNode, offset: int, func: Optional[JsFunctionInfo]) -> None:
        html = self._prop(obj, "__html")
        if html is None:
            return
        sev, desc = self.tier(html.fields["value"], func, self._XSS_LEVELS)  # type: ignore[arg-type]
        if desc == "constant":
            self._sec("low", "high", offset, "dangerouslySetInnerHTML with a constant string")
        else:
            self._sec(sev, "high", offset, "dangerouslySetInnerHTML with %s __html (XSS sink)" % desc)

    # -- RS-ASYNC-001 / RS-ASYNC-002 / RS-RES-001 ----------------------------
    def run_async_resources(self) -> None:
        want1 = "RS-ASYNC-001" in self.enabled
        want2 = "RS-ASYNC-002" in self.enabled
        wantr = "RS-RES-001" in self.enabled
        for func, own in self._scopes():
            is_async = func is not None and (func.is_async or any(n.type == "AwaitExpression" for n in own))
            for n in own:
                t = n.type
                if t == "CallExpression":
                    name, prop = _js_callee_name(n)
                    fn = prop or name
                    if want1 and is_async:
                        if fn in _JS_SYNC_BLOCKING:
                            label = (name.split(".")[-1] + "." + prop) if (prop and name) else str(fn)
                            self._finding("RS-ASYNC-001", RULES["RS-ASYNC-001"].severity, "high", n.start,
                                          "Blocking call %s() inside async function '%s' stalls the event loop" % (label, func.name),  # type: ignore[union-attr]
                                          "Use the promise-based API (fs.promises.*, util.promisify(child_process.exec), crypto.pbkdf2 "
                                          "with a callback/promise) or move the work to a worker thread.")
                        elif prop == "wait" and name == "Atomics":
                            self._finding("RS-ASYNC-001", RULES["RS-ASYNC-001"].severity, "high", n.start,
                                          "Atomics.wait() inside async function '%s' blocks the thread" % func.name)  # type: ignore[union-attr]
                    if want2 and prop == "forEach":
                        args = n.fields["arguments"]
                        if args and args[0].type in _JS_FUNCTION_TYPES and args[0].fields.get("async"):  # type: ignore[index]
                            self._finding("RS-ASYNC-002", RULES["RS-ASYNC-002"].severity, "high", n.start,
                                          "forEach(async ...) does not wait for its callbacks; errors and ordering are lost",
                                          "Use `await Promise.all(items.map(async ...))` or a `for...of` loop with await.")
                    if wantr and fn == "setInterval" and prop is None and self._is_discarded_statement(n, own):
                        self._finding("RS-RES-001", RULES["RS-RES-001"].severity, "high", n.start,
                                      "setInterval() handle is discarded, so the timer can never be cleared",
                                      "Keep the handle and clearInterval() it when done.")
                elif t == "ExpressionStatement" and want2:
                    self._check_floating(n)
                elif t == "VariableDeclarator" and wantr:
                    self._check_resource(n, func)

    @staticmethod
    def _is_discarded_statement(call: JsNode, own: List[JsNode]) -> bool:
        for n in own:
            if n.type == "ExpressionStatement" and n.fields["expression"] is call:
                return True
        return False

    def _check_floating(self, stmt: JsNode) -> None:
        expr = stmt.fields["expression"]
        if expr.type != "CallExpression":
            return
        # method calls applied to the root call (`fetch(u).then(a).catch(b)` -> [then, catch] above root fetch(u))
        chain: List[Tuple[str, int]] = []   # (method name, argument count), outermost first
        root = expr
        while True:
            callee = root.fields["callee"]
            if callee.type == "MemberExpression" and not callee.fields["computed"]:
                inner = _js_unwrap(callee.fields["object"])  # type: ignore[arg-type]
                if inner.type == "CallExpression":
                    chain.append((str(callee.fields["property"]), len(root.fields["arguments"])))  # type: ignore[arg-type]
                    root = inner
                    continue
            break
        methods = [m for m, _ in chain]
        if "catch" in methods:
            return
        if chain and chain[0][0] == "then" and chain[0][1] >= 2:
            return
        name, prop = _js_callee_name(root)
        if "then" in methods or (prop == "then" and not chain and len(root.fields["arguments"]) < 2):  # type: ignore[arg-type]
            self._finding("RS-ASYNC-002", RULES["RS-ASYNC-002"].severity, "high", stmt.start,
                          "Promise chain with .then() has no .catch(); a rejection becomes an unhandled rejection",
                          "Add `.catch(...)`, or `await` the promise inside try/catch.")
            return
        if chain:
            return  # some other method applied to the result (e.g. `.finally()` alone)
        what: Optional[str] = None
        if prop is None and name is not None:
            if name in self.async_names:
                what = "async function '%s'" % name
            elif name == "fetch":
                what = "fetch()"
        elif prop is not None:
            if name == "this" and prop in self.async_names:
                what = "async method '%s'" % prop
            elif name == "Promise" and prop in ("all", "allSettled", "race", "any"):
                what = "Promise.%s()" % prop
            elif name is not None and name.endswith(".promises") or name == "promises":
                what = "%s.%s()" % (name, prop)
        if what:
            self._finding("RS-ASYNC-002", RULES["RS-ASYNC-002"].severity, "high", stmt.start,
                          "Promise from %s is neither awaited, returned nor given .catch(); rejections are lost" % what,
                          "`await` it, return it, add `.catch(...)`, or mark intentional fire-and-forget with `void`.")

    def _resource_kind(self, init: JsNode) -> Optional[str]:
        init = _js_unwrap(init)
        if init.type == "CallExpression":
            name, prop = _js_callee_name(init)
            if prop is None:
                if name == "setInterval":
                    return "setInterval"
                if name in ("createWriteStream", "createReadStream"):
                    bound = self.module_bindings.get(name)
                    if bound is None and not self.uses_module(_JS_FS_MODULES):
                        return None
                    return name
                return None
            if prop in _JS_RESOURCE_METHODS and name is not None:
                root = name.split(".")[0]
                bound = self.module_bindings.get(root)
                if bound is not None:
                    return prop if bound[0] in _JS_RESOURCE_MODULES else None
                if root in _JS_RESOURCE_ROOTS:
                    return prop
            return None
        if init.type == "NewExpression":
            callee = init.fields["callee"]
            if callee.type == "Identifier" and callee.fields["name"] in ("WebSocket", "Socket"):
                return callee.fields["name"]  # type: ignore[return-value]
            if callee.type == "MemberExpression" and not callee.fields["computed"] and callee.fields["property"] == "Socket":
                return "Socket"
        return None

    def _check_resource(self, decl: JsNode, func: Optional[JsFunctionInfo]) -> None:
        init = decl.fields.get("init")
        ident = decl.fields["id"]
        if init is None or ident.type != "Identifier":
            return
        kind = self._resource_kind(init)
        if kind is None:
            return
        var = ident.fields["name"]
        scope_root = func.node if func is not None else self.ast
        if self._is_released(var, kind, scope_root, decl):  # type: ignore[arg-type]
            return
        if kind == "setInterval":
            message = "Timer from setInterval() assigned to '%s' is never cleared with clearInterval()" % var
            remediation = "Keep the handle and clearInterval() it when done."
        else:
            message = "Resource from %s() assigned to '%s' is never closed, ended, piped, returned or stored" % (kind, var)
            remediation = "Close it in a `finally` block (or with `using`), or pass it to stream.pipeline()."
        self._finding("RS-RES-001", RULES["RS-RES-001"].severity, "high", ident.start, message, remediation)

    @staticmethod
    def _is_released(var: str, kind: str, scope_root: JsNode, decl: JsNode) -> bool:
        """True when `var` is closed, cleared, piped, returned, awaited later, or escapes
        (argument, property value, array element, field assignment, export) anywhere in the scope."""
        readable = kind == "createReadStream"
        stack = [scope_root]
        while stack:
            n = stack.pop()
            if n is decl:
                continue
            t = n.type
            f = n.fields
            if t == "CallExpression":
                callee = f["callee"]
                if callee.type == "MemberExpression" and not callee.fields["computed"]:
                    obj = callee.fields["object"]
                    prop = str(callee.fields["property"])
                    if obj.type == "Identifier" and obj.fields["name"] == var:
                        if prop in _JS_RELEASE_METHODS or (readable and prop in _JS_READ_CONSUME_METHODS):
                            return True
                for arg in f["arguments"]:  # type: ignore[union-attr]
                    a = _js_unwrap(arg) if arg.type != "SpreadElement" else arg
                    if a.type == "Identifier" and a.fields["name"] == var:
                        return True
            elif t == "ReturnStatement" or t == "YieldExpression" or t == "AwaitExpression":
                arg = f.get("argument")
                if arg is not None and _js_unwrap(arg).type == "Identifier" and _js_unwrap(arg).fields["name"] == var:
                    return True
            elif t == "AssignmentExpression":
                right = _js_unwrap(f["right"])  # type: ignore[arg-type]
                if right.type == "Identifier" and right.fields["name"] == var and f["left"].type == "MemberExpression":
                    return True
            elif t == "Property" and not f.get("computed"):
                v = f["value"]
                if isinstance(v, JsNode) and v.type == "Identifier" and v.fields["name"] == var:
                    return True
            elif t == "ArrayExpression":
                for el in f["elements"]:  # type: ignore[union-attr]
                    if el is not None and el.type == "Identifier" and el.fields["name"] == var:
                        return True
            elif t == "ExportNamedDeclaration":
                for spec in f.get("specifiers", ()):  # type: ignore[union-attr]
                    if spec.fields.get("local") == var:
                        return True
            elif t == "ForOfStatement" and readable:
                right = _js_unwrap(f["right"])  # type: ignore[arg-type]
                if right.type == "Identifier" and right.fields["name"] == var:
                    return True
            stack.extend(js_children(n))
        return False


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
        self._standalone: Dict[str, Set[int]] = {}
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
            standalone = self._standalone.get(finding.file, set())
            for ln in (finding.line, finding.line - 1):
                if ln != finding.line and ln not in standalone:
                    continue
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
        self._standalone[entry.rel] = sf.standalone_directives
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
        """JS/TS: parse once and run every rule on the AST; files the parser
        cannot handle (or REPO_SENTRY_JS_PARSER=0) use the heuristic path.
        Declaration files and minified/bundled files only get secret scanning."""
        if js_is_declaration_file(sf.rel) or is_minified(sf.rel, sf.lines):
            return
        want_graph = "RS-ARCH-001" in self.enabled or "RS-ARCH-002" in self.enabled
        if js_parser_enabled():
            parsed = js_parse(sf.text, sf.rel)
            if parsed.ok:
                try:
                    analyzer = JsAstRules(sf, parsed, self.config, self.enabled)
                    analyzer.run()
                    imports = analyzer.collect_imports() if want_graph else []
                except Exception as exc:  # never crash: fall back to the heuristic path
                    reason = "internal error in the AST analyser: %s: %s" % (type(exc).__name__, exc)
                else:
                    for finding in analyzer.findings:
                        self._emit(finding)
                    if want_graph:
                        self.js_modules.append(JsModule(sf.rel, imports))
                    if parsed.errors:
                        line, col, msg = parsed.errors[0]
                        self._sys_finding(sf.rel, line, "JS/TS file parsed with %d syntax error%s (first at line %d col %d: %s); "
                                          "analysed from the recovered AST"
                                          % (len(parsed.errors), "" if len(parsed.errors) == 1 else "s", line, col, msg))
                    return
            else:
                reason = parsed.reason
            line = parsed.errors[0][0] if parsed.errors else 1
            self._sys_finding(sf.rel, line, "JS/TS parser fell back to the heuristic path (%s)" % reason)
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
        if self.enabled & {"RS-ASYNC-001", "RS-ASYNC-002", "RS-RES-001"}:
            analyzer.run_async_resources()
        if "RS-SEC-006" in self.enabled:
            analyzer.run_security()
        if want_graph:
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
    out.append("Python files are analysed with the `ast` module. JavaScript/TypeScript files are parsed with the")
    out.append("built-in ES2023/TypeScript parser (parser-based, with heuristic fallback): function discovery,")
    out.append("RS-QUAL-001/002/004, the import graph (RS-ARCH-001/002), the sinks RS-SEC-003/004/006 and")
    out.append("RS-ASYNC-001/002, RS-RES-001 run on the AST with confidence high. Sink severities use intra-function,")
    out.append("flow-insensitive taint-lite (req/request/ctx/params/query/body/argv/process.argv/process.env):")
    out.append("tainted arguments keep the top severity, untainted non-constant arguments are one level lower,")
    out.append("constants two. A file the parser cannot handle (too many syntax errors, nesting deeper than 400,")
    out.append("or REPO_SENTRY_JS_PARSER=0) falls back to the lexically masked, pattern-based heuristics with")
    out.append("confidence low or medium and messages marked approximate, plus one RS-SYS-001. C/C++ and")
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
    def heuristics_only():
        """Context manager forcing the pre-parser heuristic path (REPO_SENTRY_JS_PARSER=0)."""
        from unittest import mock
        return mock.patch.dict(os.environ, {"REPO_SENTRY_JS_PARSER": "0"})

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
        # AST path (v1.4): userInput/code/body/userHtml are free identifiers, i.e. untainted non-constants,
        # one level below the tainted severity (critical -> high for exec/eval/Function, high -> medium for innerHTML).
        findings = self.scan_files({"a.js": src})
        sinks = {(f.line, f.rule_id): f.severity for f in findings if f.rule_id in ("RS-SEC-003", "RS-SEC-004")}
        self.assertNotIn((2, "RS-SEC-003"), sinks)
        self.assertEqual(sinks[(3, "RS-SEC-003")], "high")
        self.assertEqual(sinks[(4, "RS-SEC-003")], "medium")
        self.assertEqual(sinks[(5, "RS-SEC-004")], "high")
        self.assertEqual(sinks[(6, "RS-SEC-004")], "critical")  # `body` is a taint-source name (request body)
        self.assertEqual(sinks[(7, "RS-SEC-004")], "medium")
        self.assertEqual(sinks[(8, "RS-SEC-004")], "medium")
        self.assertTrue(all(f.confidence == "high" for f in findings if f.file == "a.js"))
        # heuristic fallback path: the original pattern-based expectations are unchanged
        with self.heuristics_only():
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

    def test_trailing_suppression_does_not_cover_next_line(self):
        # A trailing directive silences its own line only; a comment-only line covers the line below it.
        src = ("import os\nos.system(x)  # reposentry: ignore RS-SEC-003\nos.system(y)\n")
        findings = self.scan_files({"a.py": src})
        self.assertEqual([f.line for f in self.by_rule(findings, "RS-SEC-003")], [3])
        js = "const cp = require('child_process');\ncp.exec(a); // reposentry: ignore RS-SEC-003\ncp.exec(b);\n"
        findings = self.scan_files({"a.js": js})
        self.assertEqual([f.line for f in self.by_rule(findings, "RS-SEC-003")], [3])

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
        self.assertEqual(hits[0].confidence, "high")  # AST path (v1.4): exact McCabe, no longer approximate
        self.assertNotIn("approximate", hits[0].message)
        self.assertIn("complexity 13", hits[0].message)
        self.assertEqual(hits[0].line, 1)
        with self.heuristics_only():
            hits = self.by_rule(self.scan_files({"a.js": src}), "RS-QUAL-001")
        self.assertEqual((len(hits), hits[0].severity, hits[0].confidence, hits[0].line), (1, "medium", "medium", 1))
        self.assertIn("approximate", hits[0].message)
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
        self.assertTrue(all(f.severity == "medium" and f.confidence == "high" for f in hits))  # AST path (v1.4)
        with self.heuristics_only():
            hits = self.by_rule(self.scan_files({"a.js": src}), "RS-QUAL-004")
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
        # AST path (v1.4): userInput, x and dir are untainted non-constants (one level below tainted);
        # constants are two levels below (exec: medium, innerHTML: low).
        findings = self.scan_files({"a.js": src})
        sev = {(f.line, f.rule_id): f.severity for f in findings if f.rule_id in ("RS-SEC-003", "RS-SEC-004")}
        self.assertEqual(sev, {(2, "RS-SEC-003"): "high", (3, "RS-SEC-003"): "medium", (4, "RS-SEC-004"): "high",
                               (7, "RS-SEC-004"): "medium", (8, "RS-SEC-004"): "low", (9, "RS-SEC-003"): "high",
                               (10, "RS-SEC-003"): "high"})
        self.assertTrue(SEVERITY_RANK[sev[(8, "RS-SEC-004")]] < SEVERITY_RANK[sev[(7, "RS-SEC-004")]])
        tainted = src.replace("exec(userInput)", "exec(req.query.cmd)").replace("eval(x)", "eval(req.body.code)")
        sev = {(f.line, f.rule_id): f.severity for f in self.scan_files({"a.js": tainted}) if f.rule_id.startswith("RS-SEC-00")}
        self.assertEqual((sev[(2, "RS-SEC-003")], sev[(4, "RS-SEC-004")]), ("critical", "critical"))
        with self.heuristics_only():
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
        # AST path (v1.4): `html` is a destructured prop, not request data -> untainted non-constant -> medium
        self.assertEqual(hits, [(4, "medium"), (5, "low")])
        tainted = src.replace("{ __html: html }", "{ __html: req.query.html }")
        self.assertEqual(sorted((f.line, f.severity) for f in self.by_rule(self.scan_files({"view.jsx": tainted}), "RS-SEC-006")),
                         [(4, "high"), (5, "low")])
        with self.heuristics_only():
            hits = sorted((f.line, f.severity) for f in self.by_rule(self.scan_files({"view.jsx": src}), "RS-SEC-006"))
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
        # AST path (v1.4): confidence high (Math.random proximity stays medium), no "approximate"
        self.assertEqual({f.line: f.confidence for f in self.by_rule(findings, "RS-SEC-006")},
                         {4: "high", 6: "high", 9: "high", 11: "medium", 21: "high", 23: "high", 26: "high", 28: "high", 29: "high"})
        self.assertFalse(any("approximate" in f.message for f in self.by_rule(findings, "RS-SEC-006")))
        with self.heuristics_only():
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
        # AST path (v1.4): untainted non-constant arguments are high (one below critical); test files one lower again
        self.assertEqual(real, {("RS-SEC-003", 2): "high", ("RS-SEC-004", 3): "high", ("RS-SEC-003", 4): "medium"})
        self.assertEqual(test, {("RS-SEC-003", 2): "medium", ("RS-SEC-004", 3): "medium", ("RS-SEC-003", 4): "low"})
        with self.heuristics_only():
            real = {(f.rule_id, f.line): f.severity for f in self.scan_files({"a.js": code})}
            test = {(f.rule_id, f.line): f.severity for f in self.scan_files({"a.test.js": code})}
        self.assertEqual(real, {("RS-SEC-003", 2): "critical", ("RS-SEC-004", 3): "critical", ("RS-SEC-003", 4): "medium"})
        self.assertEqual(test, {("RS-SEC-003", 2): "high", ("RS-SEC-004", 3): "high", ("RS-SEC-003", 4): "low"})

    def test_list_rules_describes_sec006(self):
        code, out, _ = self.run_cli(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("RS-SEC-006", out)
        self.assertIn("JS/TS: parser-based, with heuristic fallback", out)
        self.assertIn("pattern-based, approximate", out)


class TestJsAsyncAndResources(_ProjectMixin, unittest.TestCase):
    FIXTURE = 'const fs = require(\'fs\');\nconst net = require(\'net\');\nasync function save(x) { await fs.promises.writeFile(\'a\', x); }\nasync function load() {\n  const d = fs.readFileSync(\'a\');            // L5 blocking\n  const e = await fs.promises.readFile(\'a\'); // ok\n  function inner() { return fs.readFileSync(\'b\'); } // sync nested: ok\n  return d;\n}\nconst arrow = async () => { execSync(\'ls\'); };      // L10 blocking\nfunction sync() { return fs.readFileSync(\'c\'); }    // ok (not async)\nasync function main(items) {\n  save(1);                                  // L13 floating\n  await save(2);                            // ok\n  void save(3);                             // ok\n  save(4).catch(console.error);             // ok\n  return save(5);                           // ok\n  items.forEach(async (i) => { await save(i); }); // L17\n  fetch(\'/x\');                              // L18 floating\n  fetch(\'/y\').then(r => r.json());          // L19 then w/o catch\n  fetch(\'/z\').then(r => r.json()).catch(e => e); // ok\n  Promise.all([save(1)]);                   // L21\n  await Promise.all([save(1)]);             // ok\n  const p = save(6);                        // ok (assigned: not flagged by design)\n  // save(7);  "save(8)";\n}\nconst w = fs.createWriteStream(\'out.txt\');          // L26 never closed\nconst ok1 = fs.createWriteStream(\'o2.txt\'); ok1.end();\nconst ok2 = fs.createWriteStream(\'o3.txt\'); src.pipe(ok2);\nconst sock = net.createConnection(80);              // L29 never closed\nconst ok3 = new WebSocket(u); ok3.close();\nconst rs = fs.createReadStream(\'r\');                // read streams: not flagged\n'

    def _hits(self, rel, heuristics=False):
        if heuristics:
            with self.heuristics_only():
                findings = self.scan_files({rel: self.FIXTURE})
        else:
            findings = self.scan_files({rel: self.FIXTURE})
        return sorted((f.rule_id, f.line) for f in findings if f.rule_id in ("RS-ASYNC-001", "RS-ASYNC-002", "RS-RES-001"))

    EXPECTED = [
        ("RS-ASYNC-001", 5), ("RS-ASYNC-001", 10),                       # *Sync inside async (nested sync fn and sync fn are fine)
        ("RS-ASYNC-002", 13), ("RS-ASYNC-002", 18), ("RS-ASYNC-002", 19), ("RS-ASYNC-002", 20), ("RS-ASYNC-002", 22),
        ("RS-RES-001", 27), ("RS-RES-001", 30)]                          # unclosed write stream and socket

    def test_expected_findings(self):
        # AST path (v1.4): the read stream on line 32 is never consumed, piped or closed, so it is a leak too
        self.assertEqual(self._hits("a.js"), self.EXPECTED + [("RS-RES-001", 32)])
        self.assertEqual(self._hits("a.js", heuristics=True), self.EXPECTED)

    def test_not_flagged(self):
        lines = {line for _, line in self._hits("a.js")}
        for ok in (6, 7, 11, 14, 15, 16, 17, 21, 23, 24, 25, 28, 29, 31):
            self.assertNotIn(ok, lines, "line %d should not be flagged" % ok)
        lines = {line for _, line in self._hits("a.js", heuristics=True)}
        for ok in (6, 7, 11, 14, 15, 16, 17, 21, 23, 24, 25, 28, 29, 31, 32):
            self.assertNotIn(ok, lines, "line %d should not be flagged" % ok)

    def test_handled_or_returned_promises_are_not_floating(self):
        src = ("const attempt = (auth) =>\n  fetch(url, { headers: auth });\n"
               "const g = () => fetch(u).then((r) => r.json(), (e) => null);\n"
               "function h() {\n  fetch(a).then(ok, onError);\n  fetch(b).then(ok).catch(log);\n  fetch(c).finally(done).catch(log);\n}\n")
        self.assertEqual([f.line for f in self.scan_files({"a.js": src}) if f.rule_id == "RS-ASYNC-002"], [])

    def test_unhandled_then_chain_is_floating(self):
        src = "function h() {\n  fetch(a).then(ok);\n  load().then((x) => x);\n}\nasync function load() {}\n"
        self.assertEqual(sorted(f.line for f in self.scan_files({"a.js": src}) if f.rule_id == "RS-ASYNC-002"), [2, 3])

    def test_test_files_are_skipped(self):
        self.assertEqual(self._hits("a.test.js"), [])

    def test_rules_can_be_disabled_and_suppressed(self):
        src = "async function f() {\n  // reposentry: ignore RS-ASYNC-001\n  fs.readFileSync('a');\n  fs.readFileSync('b');\n}\n"
        hits = [f.line for f in self.scan_files({"a.js": src}) if f.rule_id == "RS-ASYNC-001"]
        self.assertEqual(hits, [4])
        root = self.make_project({"a.js": self.FIXTURE})
        _, out, _ = self.run_cli([root, "--format", "json", "--ignore-rules", "RS-ASYNC-001", "--fail-on-severity", "critical"])
        ids = {f["rule_id"] for f in json.loads(out)["findings"]}
        self.assertNotIn("RS-ASYNC-001", ids)
        self.assertIn("RS-ASYNC-002", ids)

    def test_comments_and_strings_do_not_trigger(self):
        src = "async function f() {\n  // fs.readFileSync('a'); save(1);\n  const s = \"fs.readFileSync('a')\";\n}\nasync function save() {}\n"
        self.assertEqual([f for f in self.scan_files({"a.js": src}) if f.rule_id.startswith("RS-ASYNC")], [])


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
        # AST path (v1.4): the unterminated template is recovered (one RS-SYS-001 [low]); parens.js, oneline.js
        # and braces.js are single lines over 2000 characters, i.e. minified, and skip structural analysis.
        sys_findings = self.by_rule(result.findings, "RS-SYS-001")
        self.assertEqual(sorted(f.file for f in sys_findings), ["template.js"])
        self.assertIn("parsed with 1 syntax error", sys_findings[0].message)
        self.assertTrue(all(f.severity == "low" for f in sys_findings))
        self.assertEqual([f.file for f in self.by_rule(result.findings, "RS-SEC-004")], ["template.js"])
        self.assertEqual(result.scanned_files, 4)
        with self.heuristics_only():
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

        real_parse = js_parse

        def parser_gives_up(text, rel="file.js"):
            if "const a" in text:
                return JsParseResult(None, [], [], True, "synthetic parser failure", 1)
            return real_parse(text, rel)

        with mock.patch.dict(globals(), {"js_mask": boom, "js_parse": parser_gives_up}):
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


# (label, file name, source) -- every snippet must parse with zero errors
JS_GRAMMAR_CORPUS = [
    # ---- JavaScript statements ----
    ("var/let/const", "a.js", "var a = 1, b; let c = 2; const d = 3;\n"),
    ("if/else chain", "a.js", "if (a) b(); else if (c) d(); else { e(); }\n"),
    ("for classic", "a.js", "for (let i = 0, n = a.length; i < n; i++) { if (i % 2) continue; else break; }\n"),
    ("for-in / for-of / for-await", "a.js", "for (const k in obj) {}\nfor (const [k, v] of Object.entries(o)) {}\nasync function f() { for await (const x of gen()) {} }\n"),
    ("while / do-while", "a.js", "while (x) { x--; }\ndo { x++ } while (x < 10)\n"),
    ("switch", "a.js", "switch (k) { case 1: case 2: f(); break; case 'x': { g(); } default: h(); }\n"),
    ("try/catch/finally", "a.js", "try { a(); } catch (e) { b(e); } finally { c(); }\ntry { d(); } catch { }\ntry { e(); } finally { f(); }\n"),
    ("labels", "a.js", "outer: for (;;) { inner: for (;;) { if (x) break outer; continue inner; } }\nblock: { break block; }\n"),
    ("throw / debugger / empty / with", "a.js", "throw new Error('x');\ndebugger;\n;\nwith (obj) { f(); }\n"),
    ("import forms", "a.mjs", "import a from './a';\nimport * as ns from './ns';\nimport { b, c as d, default as e } from './b';\nimport f, { g } from './f';\nimport './side';\nimport json from './data.json' with { type: 'json' };\n"),
    ("export forms", "a.mjs", "export const x = 1;\nexport function f() {}\nexport default class {}\nexport { x as y, f };\nexport * from './all';\nexport * as star from './star';\nexport { z } from './z';\n"),
    ("export default expression", "a.mjs", "export default () => { run(); };\n"),
    ("export default async function", "a.mjs", "export default async function () { await x; }\n"),
    ("top-level await", "a.mjs", "const data = await fetch(url);\nawait Promise.all([a, b]);\n"),
    ("generators", "a.js", "function* gen() { yield 1; yield* other(); const x = yield; }\nasync function* agen() { for await (const x of y) yield x; }\n"),
    ("class full", "a.js", "class K extends Base {\n  static count = 0;\n  #secret = 1;\n  field;\n  ['computed' + 1] = 2;\n  static { K.count = 1; }\n  constructor(v) { super(); this.v = v; }\n  get value() { return this.#secret; }\n  set value(v) { this.#secret = v; }\n  static async *stream() { yield 1; }\n  #hidden() { return #secret in this; }\n  async method(a, b = 1, ...rest) { return super.method(a); }\n}\n"),
    ("class expression and accessor keyword", "a.js", "const C = class Named extends (mix(A, B)) { accessor x = 1; static accessor y; };\n"),
    ("class fields named get/set/static", "a.js", "class A { get = 1; set = 2; static = 3; async = 4; get; set\n  static\n  getter() {} }\n"),
    ("object literal full", "a.js", "const o = { a, b: 1, 'c': 2, 3: 4, [k]: 5, ...spread, m() {}, async am() {}, *g() {}, async *ag() {}, get p() { return 1; }, set p(v) {}, get: 1, set: 2, async: 3, of: 4, type: 5, static: 6 };\n"),
    ("getters in object literals with computed keys", "a.js", "const o = { get [key]() { return 1; }, set [key](v) {} };\n"),
    ("destructuring with defaults", "a.js", "const { a = 1, b: { c = 2 } = {}, ...rest } = obj;\nconst [x = 1, , [y] = [], ...zs] = arr;\nfunction f({ a, b = 2 } = {}, [c, d] = [], ...e) {}\n"),
    ("assignment patterns", "a.js", "[a, b] = [b, a];\n({ a, b: [c] } = obj);\n[x.y, z[0]] = list;\n"),
    ("arrow forms", "a.js", "const a = x => x + 1;\nconst b = (x, y) => { return x * y; };\nconst c = async x => await x;\nconst d = async (x) => { await x; };\nconst e = () => ({ obj: true });\nconst f = ({ a }, [b]) => a + b;\nconst g = (...args) => args;\nconst h = x => y => z => x + y + z;\n"),
    ("async as identifier", "a.js", "const async = 1;\nasync + 1;\nasync(x);\nconst o = { async };\nfunction g(async) { return async; }\n"),
    ("contextual keywords as identifiers", "a.js", "const get = 1, set = 2, of = 3, type = 4, from = 5, as = 6, let_ = 7;\nget + set + of + type + from + as;\nconst static_ = { of: of, type: type };\nfor (const of of [1]) {}\n"),
    ("label vs object literal", "a.js", "a: { b(); }\n({ a: 1 });\nconst o = { a: 1 };\n"),
    ("block vs object at statement start", "a.js", "{}\n{ a: 1 }\n({});\n"),
    ("optional chaining and nullish", "a.js", "const v = a?.b?.[c]?.(d) ?? e;\na?.b.c?.d;\nf?.(1)?.g;\n"),
    ("logical assignment and exponent", "a.js", "a ??= 1; b ||= 2; c &&= 3; d **= 2; e = 2 ** 3 ** 2; f >>>= 1; g >>= 2; h <<= 3;\n"),
    ("new.target / import.meta / dynamic import", "a.mjs", "function F() { if (!new.target) throw 1; }\nconst u = import.meta.url;\nconst m = await import('./m.js');\nimport('./x').then(f);\n"),
    ("new forms", "a.js", "new A;\nnew A();\nnew A.B.C(1);\nnew (f())();\nnew new X()();\nnew A()[0].b;\n"),
    ("tagged templates and nesting", "a.js", "const s = tag`a ${b} c ${`d ${e} f`} g`;\nconst t = `line1\nline2 ${x ? `y${z}` : 'n'}`;\nString.raw`\\n`;\nf`x`.y;\n"),
    ("regex after ) is a regex", "a.js", "if (x) /re/.test(y);\nwhile (z) /ab+c/gi.exec(s);\n"),
    ("division after ) and ]", "a.js", "const q = (a + b) / 2 / c;\nconst r = arr[0] / 2;\nconst s = f() / g() / 3;\n"),
    ("regex in operand positions", "a.js", "const a = [/x/, /y/g];\nconst b = x ? /c/ : /d/;\nreturnish(/e/);\nconst c = !/f/.test(s) && /g/;\nconst d = {re: /h/};\n"),
    ("regex with class containing slash", "a.js", "const r = /[/]x\\/y/g; const d = (a + b) / 2;\n"),
    ("ASI return newline", "a.js", "function f() {\n  return\n  x\n}\n"),
    ("ASI lines starting with ( [ and template", "a.js", "const a = b\n(c)\nconst d = e\n[0]\nconst f = g\n`tpl`\n"),
    ("ASI postfix and prefix", "a.js", "let x = 1\nlet y = 2\nx\n++y\nx++\ny--\n"),
    ("numeric literals", "a.js", "const n = [0, 1, 1.5, .5, 5., 1e3, 1.5e-3, 0x1F, 0o17, 0b101, 1_000_000, 10n, 0xFFn, 1..toString(), 017];\n"),
    ("string escapes and continuations", "a.js", "const s = 'it\\'s \\\\ \\n \\u0041 \\x41';\nconst t = \"a \\\nb\";\nconst u = 'don\\'t';\n"),
    ("unicode and private identifiers", "a.js", "const café = 1; const $ = 2; const _x = 3;\nclass A { #p = 1; has(o) { return #p in o; } }\n"),
    ("spread / rest / sequence / comma", "a.js", "f(...args, ...[1, 2]);\nconst o = { ...a, ...b };\nfor (let i = 0, j = 0; i < 1; i++, j--) {}\nx = (a, b, c);\n"),
    ("in operator inside for-init parens", "a.js", "for (const x = ('a' in o); x;) {}\nfor (let i = ('a' in o) ? 1 : 0; i < 2; i++) {}\n"),
    ("conditional and comma chains", "a.js", "const v = a ? b : c ? d : e;\nconst w = a ? (b, c) : d;\n"),
    ("delete / void / typeof / instanceof / in", "a.js", "delete o.p; void 0; typeof x === 'string'; a instanceof B; 'k' in o; !a; ~b; -c; +d;\n"),
    ("hashbang and html comment is not special", "a.js", "#!/usr/bin/env node\nconst x = 1 <!--y;\nconst z = a-->b;\n"),
    ("empty file and comments only", "a.js", "// just a comment\n/* block\n comment */\n"),
    ("JSX element with text apostrophes", "a.jsx", "function App() {\n  return <p className='x'>don't {name} won't</p>;\n}\n"),
    ("JSX fragments, nesting, attributes", "a.jsx", "const el = (\n  <>\n    <Foo.Bar a=\"1\" b={2} c {...rest} data-x='y' aria-label=\"it's\">\n      text {\"{\"} {'}'} &amp; more\n      <br />\n      <svg:rect xlink:href=\"#a\" />\n    </Foo.Bar>\n    {items.map(i => <li key={i}>{i}</li>)}\n    {/* comment child */}\n  </>\n);\n"),
    ("JSX attribute element and multiline string", "a.jsx", "const x = <A b=<C /> d=\"multi\nline\" />;\n"),
    ("JSX text with entities and a bare >", "a.jsx", "const c = <div>a &lt; b and c > d</div>;\nconst d = <T>{x}</T>;\n"),
    ("JSX conditional and arrow bodies", "a.jsx", "const r = cond ? <A /> : <B />;\nconst f = () => <C />;\nconst g = () => (<D>\n  <E />\n</D>);\n"),
    ("JSX in .js file with comparisons", "a.js", "const lt = a < b;\nconst el = <span>{a < b ? 'lt' : 'ge'}</span>;\n"),
    ("deep binary chain", "a.js", "const s = " + " + ".join("a%d" % i for i in range(300)) + ";\n"),
    # ---- TypeScript ----
    ("type annotations everywhere", "a.ts", "let a: number = 1;\nconst b: string[] = [];\nlet c: Array<Map<string, number[]>>;\nfunction f(x: number, y?: string, ...rest: boolean[]): void {}\nconst g = (x: number): number => x;\nlet d!: number;\n"),
    ("interface", "a.ts", "interface A<T = string> extends B, C<T> {\n  a: number;\n  b?: string;\n  readonly c: T[];\n  d(x: number): void;\n  e?(): void;\n  (call: number): string;\n  new (x: number): A;\n  [key: string]: any;\n  get p(): number;\n  set p(v: number);\n  method<U>(u: U): U\n}\n"),
    ("type aliases", "a.ts", "type A = string | number;\ntype B<T> = { [K in keyof T]?: T[K] };\ntype C = (x: number) => void;\ntype D = new (...args: any[]) => object;\ntype E = [a: string, b?: number, ...rest: boolean[]];\ntype F = typeof x;\ntype G = keyof typeof obj;\ntype H = A extends B ? C : D;\ntype I = `prefix-${string}`;\ntype J = T extends (infer U)[] ? U : never;\ntype K = T extends [infer H extends string, ...infer R] ? H : never;\ntype L = readonly string[];\ntype M = unique symbol;\ntype N = import('./mod').Type<number>;\ntype O = { readonly [K in keyof T as `get${Capitalize<K & string>}`]-?: () => T[K] };\ntype P = (A | B)[] & { x: 1 } | null;\ntype Q = abstract new () => void;\ntype R = -1 | 'a' | true | undefined | void | this;\ntype S = A.B.C<D>;\n"),
    ("enum and const enum", "a.ts", "enum Color { Red, Green = 2, Blue = Green << 1, 'quoted' = 9 }\nconst enum E { A = 1 }\ndeclare enum F { X }\n"),
    ("namespace / module / declare", "a.ts", "namespace A.B { export const x = 1; export function f(): void {} }\nmodule M { }\ndeclare module 'foo' { export function g(): void; }\ndeclare global { interface Window { x: number } }\ndeclare const VERSION: string;\ndeclare function h(a: number): string;\ndeclare class DC { m(): void; }\ndeclare namespace NS { }\n"),
    ("abstract class, modifiers, parameter properties", "a.ts", "abstract class A<T> implements I, J<T> {\n  private x: number = 1;\n  protected readonly y?: string;\n  public static z = 2;\n  declare w: number;\n  override v!: boolean;\n  abstract run(): void;\n  protected abstract get g(): T;\n  constructor(private readonly a: number, public b?: string, protected c = 1) { super(); }\n  async step(n: number): Promise<number> { return n; }\n  static create<U>(this: void, u: U): A<U> { return null as any; }\n}\nexport abstract class B extends A<number> {}\nexport default abstract class {}\n"),
    ("overload signatures", "a.ts", "function f(a: string): string;\nfunction f(a: number): number;\nfunction f(a: any): any { return a; }\nclass C { m(a: string): void; m(a: number): void; m(a: any) {} }\n"),
    ("as / satisfies / non-null / type assertion", "a.ts", "const a = x as unknown as T;\nconst b = { k: 1 } satisfies Rec;\nconst c = y!.z!;\nconst d = <any>obj;\nconst e = <T>(x: T) => x;\nconst f = x as const;\nconst g = (<string>v).length;\nfoo!(1);\n"),
    ("generic calls and instantiation", "a.ts", "f<T>(x);\na.b<T, U>(y);\nnew Map<string, number>();\nconst g = f<T>;\nconst h = a < b > c;\nconst i = a < b && c > d;\nconst j = f<T>`tpl`;\ncall(a < b, c > d);\n"),
    ("arrow generics in .ts", "a.ts", "const id = <T>(x: T): T => x;\nconst ext = <T extends object>(x: T) => x;\nconst two = <T, U>(x: T, y: U) => [x, y];\nconst asy = async <T>(x: T) => x;\n"),
    ("arrow generics in .tsx", "a.tsx", "const id = <T,>(x: T) => x;\nconst ext = <T extends object>(x: T) => x;\nconst el = <div>{id(1)}</div>;\nconst c = <Comp<number> value={1} />;\n"),
    ("type-only imports/exports and import equals", "a.ts", "import type { A, B } from './a';\nimport { type C, D } from './c';\nimport type E from './e';\nimport fs = require('fs');\nimport Alias = NS.Inner;\nexport type { A };\nexport type * from './types';\nexport = fs;\nexport as namespace Lib;\nexport import X = NS.X;\n"),
    ("decorators", "a.ts", "@Component({ selector: 'x' })\nexport class C {\n  @Input() name: string;\n  @Output() @Other change = new E();\n  constructor(@Inject(TOKEN) private t: T) {}\n  @HostListener('click', ['$event'])\n  onClick(e: Event) {}\n}\n@dec class D {}\nexport default @dec class E {}\n"),
    ("index signatures and mapped modifiers", "a.ts", "class M { [key: string]: unknown; static [k: number]: string; }\ntype RO = { +readonly [K in Keys]+?: T[K] };\n"),
    ("definite assignment, optional methods, this types", "a.ts", "class A { x!: number; y?: string; m?(): void; f(this: A): this { return this; } }\n"),
    ("function type in union needs parens", "a.ts", "let cb: (() => void) | null = null;\nlet fn: ((x: number) => string) | undefined;\ntype G = Array<() => void>;\n"),
    ("type predicates and asserts", "a.ts", "function isS(x: unknown): x is string { return typeof x === 'string'; }\nfunction assertS(x: unknown): asserts x is string {}\nfunction assertT(x: unknown): asserts x {}\nconst p = (x: unknown): x is number => true;\n"),
    ("generics with defaults, constraints and variance", "a.ts", "function f<const T extends readonly unknown[], U = T[number]>(x: T): U { return x[0] as U; }\ninterface I<in out T> { v: T }\nclass K<T extends keyof any = string> {}\n"),
    ("optional chaining with generics and templates", "a.ts", "a?.b<T>();\nconst t = obj?.tag`x`;\n"),
    ("object type literals and call signatures inline", "a.ts", "let o: { a: number; b?: string, c(): void; readonly d: 1; (x: number): string; new (): o };\n"),
    ("accessors in interfaces and abstract members", "a.ts", "abstract class A { abstract x: number; abstract get y(): number; abstract set y(v: number); }\n"),
    ("conditional type inside function body does not confuse expressions", "a.ts", "function f<T>(x: T) {\n  type Inner = T extends string ? 'a' : 'b';\n  const y = (x as any) ? 1 : 2;\n  return y;\n}\n"),
    ("tsx component with hooks", "a.tsx", "export function List<T>({ rows }: { rows: T[] }) {\n  const [s, setS] = useState<string>('');\n  return (\n    <ul className=\"list\">\n      {rows.map((r) => <li key={String(r)}>it's {r} here</li>)}\n    </ul>\n  );\n}\n"),
    ("enum member access and namespaces merged", "a.ts", "namespace Color { export const extra = 1; }\nconst c = Color.Red | Color.extra;\n"),
    ("satisfies on object and as const arrays", "a.ts", "export const routes = [{ path: '/', name: 'home' }] as const satisfies readonly Route[];\n"),
    ("class implements with generics and extends call", "a.ts", "class A extends mixin(B)<T> implements C<T> {}\n"),
    ("ts: using as identifier and accessor property", "a.ts", "const using = 1; using + 1;\nclass A { accessor x = 1; }\n"),
    ("unicode escapes in strings, line separators", "a.js", "const s = 'a\\u2028b';\nconst t = \"x\";\n"),
    ("getter named get and static named static", "a.js", "class A { get get() { return 1; } set set(v) {} static static() {} static async async() {} }\n"),
    ("object with keyword keys and numeric/string keys", "a.js", "const o = { if: 1, class: 2, 'a-b': 3, 1e3: 4, [Symbol.iterator]() {}, async *[k]() {} };\no.if + o.class + o.default;\n"),
    ("chained calls across lines", "a.js", "const r = api\n  .get('/x')\n  .then(res => res.json())\n  .catch(err => log(err))\n  .finally(() => done());\n"),
    ("comments everywhere", "a.js", "const /* a */ x /* b */ = /* c */ 1 /* d */; // e\nfunction /* f */ g /* h */ (/* i */) /* j */ { /* k */ }\n"),
]


def _js_synthetic_source(target_bytes: int) -> str:
    """Deterministic, realistic-looking JS (modules, classes, async functions,
    loops, objects, templates, regexes, comments) of at least `target_bytes`."""
    chunks: List[str] = []
    i = 0
    size = 0
    template = (
        "// Module @N: handles widget @N\n"
        "import { helper@N } from './helpers/h@N';\n"
        "const CONFIG_@N = { retries: @N, name: 'widget-@N', tags: ['a', 'b', 'c'], nested: { deep: { value: @N } } };\n"
        "export class Widget@N extends Base {\n"
        "  #count = 0;\n"
        "  static registry = new Map();\n"
        "  constructor(opts = {}) {\n"
        "    super(opts);\n"
        "    this.opts = { ...CONFIG_@N, ...opts };\n"
        "    this.items = [];\n"
        "  }\n"
        "  get size() { return this.items.length; }\n"
        "  async load(url, { signal } = {}) {\n"
        "    try {\n"
        "      const res = await fetch(`${url}/api/v1/items?page=${this.#count}`, { signal });\n"
        "      if (!res.ok) { throw new Error(`HTTP ${res.status}`); }\n"
        "      const data = await res.json();\n"
        "      for (const item of data.items) {\n"
        "        if (item.kind === 'x' && item.weight > 0.5 || item.force) {\n"
        "          this.items.push({ id: item.id, label: item.label ?? 'n/a', weight: item.weight * 2 });\n"
        "        } else if (item.kind === 'y') {\n"
        "          this.items.unshift(item);\n"
        "        }\n"
        "      }\n"
        "      return this.items.filter((it) => it.weight > 1).map((it) => it.id);\n"
        "    } catch (err) {\n"
        "      console.error('load failed', err);\n"
        "      return [];\n"
        "    } finally {\n"
        "      this.#count++;\n"
        "    }\n"
        "  }\n"
        "  render(el) {\n"
        "    const rows = this.items.map((it, idx) => `<tr class=\"${idx % 2 ? 'odd' : 'even'}\"><td>${it.label}</td></tr>`);\n"
        "    el.textContent = rows.join('\\n');\n"
        "    switch (this.opts.mode) {\n"
        "      case 'fast': return helper@N(el, 1);\n"
        "      case 'slow': return helper@N(el, 2);\n"
        "      default: return null;\n"
        "    }\n"
        "  }\n"
        "}\n"
        "export function compute@N(a, b, c) {\n"
        "  let total = 0;\n"
        "  for (let i = 0; i < a.length; i++) {\n"
        "    const v = a[i] / (b[i] || 1) - c;\n"
        "    total += v > 0 ? Math.sqrt(v) : -v;\n"
        "  }\n"
        "  while (total > 1e6) { total /= 2; }\n"
        "  return /^\\d+$/.test(String(total)) ? total : Math.round(total);\n"
        "}\n"
        "export const handlers@N = {\n"
        "  onClick: (e) => { e.preventDefault(); return compute@N([1, 2, 3], [4, 5, 6], 0.5); },\n"
        "  async onSubmit(form) { const w = new Widget@N(); await w.load(form.action); w.render(form); },\n"
        "  'on-close': function () { Widget@N.registry.delete(this.id); },\n"
        "};\n\n"
    )
    while size < target_bytes:
        s = template.replace("@N", str(i))
        chunks.append(s)
        size += len(s)
        i += 1
    return "".join(chunks)


class TestJsParser(unittest.TestCase):
    def test_grammar_corpus_parses_with_zero_errors(self):
        self.assertGreaterEqual(len(JS_GRAMMAR_CORPUS), 60)
        js = [c for c in JS_GRAMMAR_CORPUS if not c[1].endswith((".ts", ".tsx"))]
        ts = [c for c in JS_GRAMMAR_CORPUS if c[1].endswith((".ts", ".tsx"))]
        self.assertGreaterEqual(len(js), 30)
        self.assertGreaterEqual(len(ts), 25)
        for label, rel, src in JS_GRAMMAR_CORPUS:
            result = js_parse(src, rel)
            self.assertTrue(result.ok, "%s: %s" % (label, result.reason))
            self.assertEqual(result.errors, [], label)
            self.assertEqual(result.ast.type, "Program", label)

    def test_regex_division_jsx_and_type_assertion_disambiguation(self):
        ast_root = js_parse("if (x) /re/.test(y);\nconst d = (a + b) / 2 / c;\n", "a.js").ast
        if_stmt, decl = ast_root.body
        call = if_stmt.consequent.expression
        self.assertEqual((call.type, call.callee.object.type, call.callee.object.kind), ("CallExpression", "Literal", "regex"))
        div = decl.declarations[0].init
        self.assertEqual((div.type, div.operator, div.left.operator), ("BinaryExpression", "/", "/"))
        tsx = js_parse("const id = <T,>(x: T) => x;\nconst el = <div className='a'>it's</div>;\nconst c = <T extends X>(y: T) => y;\n", "a.tsx").ast
        self.assertEqual([d.declarations[0].init.type for d in tsx.body],
                         ["ArrowFunctionExpression", "JSXElement", "ArrowFunctionExpression"])
        ts = js_parse("const v = <any>obj;\nconst f = <T>(x: T) => x;\nconst g = a < b > c;\n", "a.ts").ast
        self.assertEqual([d.declarations[0].init.type for d in ts.body],
                         ["TSTypeAssertion", "ArrowFunctionExpression", "BinaryExpression"])
        js = js_parse("const g = a < b > c;\nf(a < b, c > d);\n", "a.js").ast
        self.assertEqual(js.body[0].declarations[0].init.type, "BinaryExpression")
        self.assertEqual(len(js.body[1].expression.arguments), 2)
        tpl = js_parse("const t = `a ${b ? `c ${d}` : 'e'} f`;\n", "a.js").ast.body[0].declarations[0].init
        self.assertEqual((tpl.type, tpl.quasis, len(tpl.expressions)), ("TemplateLiteral", ["a ", " f"], 1))
        self.assertEqual(tpl.expressions[0].consequent.quasis, ["c ", ""])

    def test_comments_are_trivia_and_async_as_identifier(self):
        result = js_parse("// a\nconst x = 1; /* b */ const async = 2; async(x); const o = { async };\n", "a.js")
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.comments), 2)
        self.assertEqual([n.type for n in result.ast.body],
                         ["VariableDeclaration", "VariableDeclaration", "ExpressionStatement", "VariableDeclaration"])
        self.assertEqual(result.ast.body[2].expression.callee.name, "async")

    def test_error_recovery_keeps_functions_before_and_after(self):
        src = ("function before(a) {\n  if (a) { return 1; }\n  return 2;\n}\n"
               "const broken = { a: 1, b: , c: 3 };\n"
               "function after(b) {\n  while (b) { b--; }\n  return b;\n}\n"
               "class C { m() { return 1; } }\n")
        result = js_parse(src, "a.js")
        self.assertTrue(result.ok)
        self.assertEqual([(ln, col) for ln, col, _ in result.errors], [(5, 27)])
        self.assertEqual([(n.type, n.line, n.get("id")) for n in result.ast.body],
                         [("FunctionDeclaration", 1, "before"), ("FunctionDeclaration", 6, "after"), ("ClassDeclaration", 10, "C")])
        self.assertEqual((result.ast.body[1].end, src[result.ast.body[1].end - 1]), (src.index("}\nclass") + 1, "}"))
        inner = js_parse("function f() {\n  const x = (1 + ;\n  return x;\n}\nfunction g() { return 2; }\n", "a.js")
        self.assertEqual([n.get("id") for n in inner.ast.body], ["f", "g"])
        self.assertEqual(len(inner.errors), 1)

    def test_garbage_and_too_many_errors_fall_back_without_exception(self):
        garbage = js_parse("}{)(][ ;; ??? <<>> `\n" * 500, "a.js")
        self.assertFalse(garbage.ok)
        self.assertIn("syntax errors", garbage.reason)
        many = js_parse("let = ;\n" * 300, "a.ts")
        self.assertFalse(many.ok)
        binary = js_parse("\x00\x01\x02eval(x)\n" * 100, "a.js")
        self.assertIsNotNone(binary)
        self.assertEqual(js_parse("", "a.js").ast.body, [])

    def test_pathological_inputs_finish_quickly(self):
        import time as _time
        cases = {
            "parens": "f" + "(" * 200000 + ")" * 200000 + ";\n",
            "terms": "const s = " + "+".join(["a"] * 100000) + ";\n",
            "oneline": "var x = 1;" + " x = x + 1;" * 90000 + "\n",
            "template": "const t = `never closed ${a + b\nfunction f() { if (x) { eval(x); } }\n",
            "string": "const s = 'never closed\nfunction g() {}\n",
            "regex": "const r = /never closed\nfunction g() {}\n",
            "jsx": "const e = <div><p>never closed\nfunction g() {}\n",
            "arrays": "x = " + "[" * 100000 + "]" * 100000 + ";\n",
            "objects": "x = " + "{a:" * 50000 + "1" + "}" * 50000 + ";\n",
            "arrows": "x = " + "a => " * 50000 + "1;\n",
            "braces": "{" * 100000 + "}" * 100000 + "\n",
        }
        for name, src in cases.items():
            started = _time.time()
            result = js_parse(src, "x.jsx")
            self.assertLess(_time.time() - started, 5.0, name)
            if name in ("parens", "arrays", "objects", "arrows", "braces"):
                self.assertFalse(result.ok, name)
                self.assertIn("nesting", result.reason, name)
            elif name in ("terms", "oneline"):
                self.assertTrue(result.ok and not result.errors, name)
            else:
                self.assertTrue(result.ok, name)
                self.assertEqual(len(result.errors), 1, name)

    def test_one_megabyte_parses_within_budget(self):
        import time as _time
        src = _js_synthetic_source(1024 * 1024)
        self.assertGreaterEqual(len(src), 1024 * 1024)
        started = _time.time()
        result = js_parse(src, "big.js")
        elapsed = _time.time() - started
        self.assertLess(elapsed, 15.0)
        self.assertTrue(result.ok)
        self.assertEqual(result.errors, [])
        self.assertGreater(len(result.ast.body), 1000)

    def test_walk_is_iterative_and_lines_match_crlf(self):
        src = "x = " + "(" * 350 + "1" + ")" * 350 + ";\n"
        result = js_parse(src, "a.js")
        self.assertTrue(result.ok)
        limit = sys.getrecursionlimit()
        sys.setrecursionlimit(200)
        try:
            nodes = list(js_walk(result.ast))
        finally:
            sys.setrecursionlimit(limit)
        self.assertEqual(sum(1 for n in nodes if n.type == "ParenthesizedExpression"), 350)
        self.assertEqual(js_children(result.ast)[0].type, "ExpressionStatement")
        src = "const a = 1;\nfunction f() {\n  return `x\ny ${z}`;\n}\n/* c\n */ class K { m() {} }\n"
        lf = [(n.type, n.line, n.col) for n in js_walk(js_parse(src, "a.js").ast)]
        crlf = [(n.type, n.line, n.col) for n in js_walk(js_parse(src.replace("\n", "\r\n"), "a.js").ast)]
        self.assertEqual(lf, crlf)
        self.assertIn(("ClassDeclaration", 7, 5), lf)

    def test_function_node_spans_and_names(self):
        src = ("function decl() {}\nasync function af() {}\nfunction* gen() {}\nconst arrow = (a) => {\n  return a;\n};\n"
               "export default () => 1;\nclass K {\n  m() {}\n  static s() {}\n  get g() { return 1; }\n  set g(v) {}\n"
               "  constructor() {}\n}\nconst o = { om() {} };\nrun(function () {});\n")
        result = js_parse(src, "a.js")
        self.assertEqual(result.errors, [])
        funcs = [n for n in js_walk(result.ast) if n.type in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression")]
        self.assertEqual(len(funcs), 12)
        arrow = result.ast.body[3].declarations[0].init
        self.assertEqual((arrow.line, src.count("\n", 0, arrow.end) + 1), (4, 6))



class TestJsAstAnalysis(_ProjectMixin, unittest.TestCase):
    """Acceptance tests for the parser-based JS/TS rules (v1.4)."""

    @staticmethod
    def analyze(src: str, rel: str = "a.js", config: Optional[Dict[str, object]] = None) -> "JsAstRules":
        parsed = js_parse(src, rel)
        assert parsed.ok, parsed.reason
        cfg, _ = config_from_dict(config or {})
        analyzer = JsAstRules(SourceFile(rel, rel, src, "js"), parsed, cfg, set(RULES))
        analyzer.run()
        return analyzer

    def test_syntax_error_mid_file_recovers_and_reports_sys_finding(self):
        src = ("const { exec } = require('child_process');\n"
               "function before(req) {\n  exec(req.query.a);\n}\n"
               "const broken = { a: 1, b: , c: 3 };\n"
               "function after(req) {\n  exec(req.query.b);\n}\n")
        root = self.make_project({"a.js": src})
        result = scan(root)
        sys_hits = self.by_rule(result.findings, "RS-SYS-001")
        self.assertEqual([(f.line, f.severity) for f in sys_hits], [(5, "low")])
        self.assertIn("parsed with 1 syntax error", sys_hits[0].message)
        self.assertEqual([(f.line, f.severity) for f in self.by_rule(result.findings, "RS-SEC-003")], [(3, "critical"), (7, "critical")])
        names = [f.name for f in self.analyze(src).functions]
        self.assertEqual(names, ["before", "after"])

    def test_garbage_file_falls_back_to_heuristics(self):
        garbage = "}{)(][ ;; ??? ::: ,,\n" * 200 + "eval(x);\n"
        result = scan(self.make_project({"junk.js": garbage, "ok.js": "const a = 1;\n"}))
        sys_hits = self.by_rule(result.findings, "RS-SYS-001")
        self.assertEqual([f.file for f in sys_hits], ["junk.js"])
        self.assertIn("fell back to the heuristic path", sys_hits[0].message)
        self.assertEqual(sys_hits[0].severity, "low")
        evals = self.by_rule(result.findings, "RS-SEC-004")
        self.assertEqual([(f.file, f.confidence) for f in evals], [("junk.js", "medium")])
        self.assertEqual(result.scanned_files, 2)

    def test_function_discovery_names_and_line_ranges(self):
        src = ("function decl(a) {\n  return a;\n}\n"                     # 1-3
               "async function fetchIt() {\n  await x;\n}\n"               # 4-6
               "function* gen() {\n  yield 1;\n}\n"                        # 7-9
               "const arrow = (a) => {\n  return a;\n};\n"                 # 10-12
               "export default () => {\n  run();\n};\n"                    # 13-15
               "class K extends Base {\n"                                  # 16
               "  method(v) {\n    return v;\n  }\n"                       # 17-19
               "  static load(id) {\n    return id;\n  }\n"                # 20-22
               "  get value() {\n    return 1;\n  }\n"                     # 23-25
               "  set value(v) {\n    this.v = v;\n  }\n"                  # 26-28
               "  constructor(v) {\n    super();\n  }\n"                   # 29-31
               "}\n"                                                       # 32
               "const obj = {\n  handler(e) {\n    return e;\n  },\n};\n"  # 33-37 (method 34-36)
               "items.map(function (x) {\n  return x;\n});\n")             # 38-40
        analyzer = self.analyze(src)
        got = [(f.name, js_line_col(analyzer.starts, f.node.start)[0], analyzer.end_line(f.node)) for f in analyzer.functions]
        self.assertEqual(got, [
            ("decl", 1, 3), ("fetchIt", 4, 6), ("gen", 7, 9), ("arrow", 10, 12), ("default", 13, 15),
            ("K.method", 17, 19), ("K.load", 20, 22), ("get K.value", 23, 25), ("set K.value", 26, 28),
            ("K.constructor", 29, 31), ("handler", 34, 36), ("<anonymous>", 38, 40)])
        self.assertEqual([f.parent for f in analyzer.functions], [None] * 12)
        nested = self.analyze("function outer() {\n  const inner = () => { if (x) {} };\n  return inner;\n}\n")
        self.assertEqual([(f.name, f.parent.name if f.parent else None) for f in nested.functions], [("outer", None), ("inner", "outer")])
        self.assertEqual([c.name for c in nested.functions[0].children], ["inner"])
        more = self.analyze("module.exports = function () {};\nobj.handler = async () => {};\nclass A { static { init(); } }\n"
                            "const B = class { run() {} };\nexport default class { go() {} }\n")
        self.assertEqual([f.name for f in more.functions], ["exports", "handler", "A.<static>", "B.run", "default.go"])

    def metrics(self, src: str, rel: str = "a.ts") -> Dict[str, Tuple[int, int]]:
        analyzer = self.analyze(src, rel)
        return {f.name: (analyzer.complexity(f), analyzer.max_nesting(f.node, True)[0]) for f in analyzer.functions}

    def test_complexity_and_nesting_on_the_ast(self):
        # the v1.2 hand-computed samples, now exact on the AST
        a = "function a(x) { if (x) {} if (x > 1) {} if (x > 2) {} return x; }\n"
        self.assertEqual(self.metrics(a)["a"][0], 4)                       # 1 + 3 if
        b = ("function b(x, y, z, k) {\n"
             "  if (x) { } else if (y) { } else { }\n"
             "  for (const i of z) { }\n"
             "  const v = x && y || z ?? k;\n"
             "  const w = x ? 1 : 2;\n"
             "  switch (k) { case 1: break; case 2: break; case 3: break; default: break; }\n"
             "  try { run(); } catch (e) { log(e); }\n"
             "  return v + w;\n}\n")
        self.assertEqual(self.metrics(b)["b"][0], 12)                      # 1 + 2 + 1 + 3 + 1 + 3 + 1
        self.assertEqual(self.metrics("function c(a) { return a?.b ?? c; }\n")["c"][0], 2)
        d = ("function d(a) {\n  const inner = (q) => { if (q) { return 1; } return 2; };\n"
             "  if (a) { return inner(a); }\n  return 0;\n}\n")
        self.assertEqual((self.metrics(d)["d"][0], self.metrics(d)["inner"][0]), (2, 2))
        e = "function e(a?: number, b?: string) { const o: { p?: number } = {}; return a ? o : b; }\n"
        self.assertEqual(self.metrics(e)["e"][0], 2)
        # cases the old heuristic could get wrong: all still 1 + 1 (one real `if`)
        tricky = ("function t(a: unknown, b: string) {\n"
                  "  const s = 'if (x) { for (y) {} } && z';\n"            # text in a string
                  "  const r = /a && b \\|\\| c \\? d : e/;\n"              # operators in a regex
                  "  // for (;;) { if (q) {} } while (z) {} case 1:\n"      # comment
                  "  /* catch (e) {} ?? && */\n"
                  "  type R = typeof a extends string ? 'y' : 'n';\n"     # type-level conditional
                  "  const o: { k?: number } = {};\n"
                  "  if (b) { return r.test(s) ? o : null; }\n"             # if + ternary
                  "  return o;\n}\n")
        self.assertEqual(self.metrics(tricky)["t"], (3, 1))               # 1 + if + ternary; nesting 1
        logical = "function l(a, b) { a ||= b; a &&= b; a ??= b; return a; }\n"
        self.assertEqual(self.metrics(logical)["l"][0], 4)
        deep = ("function f(a) {\n  if (a) {\n    for (;;) {\n      while (a) {\n        try {\n"
                "          if (a) { run(); }\n        } catch (e) { log(e); }\n      }\n    }\n  }\n}\n")
        analyzer = self.analyze(deep)
        depth, pos = analyzer.max_nesting(analyzer.functions[0].node, True)
        self.assertEqual((depth, js_line_col(analyzer.starts, pos)[0]), (5, 6))
        chain = "function g(a) {\n  if (a === 0) { run(); }\n" + "".join("  else if (a === %d) { run(); }\n" % i for i in range(1, 7)) + "  else { run(); }\n}\n"
        self.assertEqual(self.metrics(chain)["g"], (8, 1))                 # 1 + 7 if; else-if adds no depth
        findings = self.scan_files({"a.ts": deep})
        hits = self.by_rule(findings, "RS-QUAL-002")
        self.assertEqual([(f.line, f.confidence) for f in hits], [(6, "high")])
        self.assertNotIn("approximate", hits[0].message)

    def test_import_graph_forms(self):
        files = {"a.ts": "export * from './b';\n", "b.ts": "export { c } from './c';\n",
                 "c.ts": "import d = require('./d');\nexport const c = d;\n", "d.ts": "import { a } from './a';\nexport default 1;\n"}
        cycles = self.by_rule(self.scan_files(files), "RS-ARCH-001")
        self.assertEqual(len(cycles), 1)
        self.assertEqual(cycles[0].severity, "high")
        self.assertIn("a -> b -> c -> d -> a", cycles[0].message)
        soft = {"a.ts": "import type { B } from './b';\nexport type { B2 } from './b';\nexport class A {}\n",
                "b.ts": "export function f() { const a = require('./a'); return a; }\nexport type B2 = number;\n"}
        cycles = self.by_rule(self.scan_files(soft), "RS-ARCH-001")
        self.assertEqual([c.severity for c in cycles], ["low"])
        imports = self.analyze("import { x } from './x';\nimport type { T } from './t';\nimport { type U, v } from './u';\n"
                               "function f() { return import('./dyn'); }\nconst r = require('./r');\nexport * from './all';\n"
                               "// import './comment';\nconst s = \"import './string'\";\n", "a.ts").collect_imports()
        self.assertEqual([(i.specifier, i.soft) for i in imports],
                         [("./x", False), ("./t", True), ("./u", False), ("./dyn", True), ("./r", False), ("./all", False)])
        self.assertEqual([(i.lineno, i.col) for i in imports][:2], [(1, 19), (2, 24)])

    def test_sinks_true_positives_negatives_and_old_regex_mistakes(self):
        src = ("const { exec } = require('child_process');\n"                      # 1
               "app.get('/run', (req, res) => {\n"                                  # 2
               "  exec(req.query.cmd);\n"                                           # 3 critical (tainted)
               "  const c = req.body.c;\n"                                          # 4
               "  exec(c);\n"                                                       # 5 critical (taint-lite)
               "  const { cmd } = req.query;\n"                                     # 6
               "  exec(`ls ${cmd}`);\n"                                             # 7 critical
               "  exec(userInput);\n"                                               # 8 high (untainted)
               "  exec('ls');\n"                                                    # 9 medium
               "  exec(CMD);\n"                                                     # 10 medium (const)
               "  exec(process.argv[2]);\n"                                         # 11 critical
               "});\n"
               "const CMD = 'ls -la';\n"                                            # 13
               "const api = { exec(cmd) { return run(cmd); }, eval(x) { return x; } };\n"  # 14 not a call
               "re.exec(str);\n"                                                    # 15 RegExp.exec: not flagged
               "window.eval(code);\n"                                               # 16 high
               "obj.eval(x);\n"                                                     # 17 not flagged
               "eval('1 + 1');\n"                                                   # 18 medium
               "let innerHTML = userHtml;\n"                                        # 19 not an assignment to the DOM
               "const h = { innerHTML: userHtml };\n"                               # 20 not flagged
               "if (el.innerHTML === x) {}\n"                                       # 21 not flagged
               "el.innerHTML = userHtml;\n"                                         # 22 medium
               "el.innerHTML = '<b>ok</b>';\n"                                      # 23 low
               "el['outerHTML'] = req.body.html;\n"                                 # 24 high
               "document.write(req.query.x);\n"                                     # 25 high
               "el.insertAdjacentHTML('beforeend', frag);\n"                        # 26 medium
               "setTimeout('tick()', 10);\n"                                        # 27 medium
               "setTimeout(() => tick(), 10);\n"                                    # 28 not flagged
               "setTimeout(req.body.code, 10);\n"                                   # 29 critical
               "const F = new Function('a', 'return a');\n"                         # 30 medium
               "const G = Function(req.query.src);\n")                              # 31 critical
        findings = self.scan_files({"a.js": src})
        got = {f.line: f.severity for f in findings if f.rule_id in ("RS-SEC-003", "RS-SEC-004")}
        self.assertEqual(got, {3: "critical", 5: "critical", 7: "critical", 8: "high", 9: "medium", 10: "medium",
                               11: "critical", 16: "high", 18: "medium", 22: "medium", 23: "low", 24: "high",
                               25: "high", 26: "medium", 27: "medium", 29: "critical", 30: "medium", 31: "critical"})
        self.assertTrue(all(f.confidence == "high" and "approximate" not in f.message
                            for f in findings if f.rule_id in ("RS-SEC-003", "RS-SEC-004")))
        # the old regex path reports the method definitions on line 14 and misses window.eval
        with self.heuristics_only():
            old = {f.line for f in self.scan_files({"a.js": src}) if f.rule_id in ("RS-SEC-003", "RS-SEC-004")}
        self.assertIn(14, old)
        self.assertNotIn(16, old)
        spawn = ("import { spawn, execFile } from 'node:child_process';\nspawn('ls', [], { shell: true });\n"
                 "spawn(req.query.c, { shell: true });\nspawn('ls', []);\nexecFile(cmd, args, { shell: false });\n")
        got = {f.line: f.severity for f in self.by_rule(self.scan_files({"s.mjs": spawn}), "RS-SEC-003")}
        self.assertEqual(got, {2: "medium", 3: "critical"})
        shadow = "const exec = (x) => x;\nexec(cmd);\nconst cp = require('child_process');\ncp.exec(cmd);\nrequire('child_process').execSync(c);\n"
        self.assertEqual(sorted(f.line for f in self.by_rule(self.scan_files({"b.js": shadow}), "RS-SEC-003")), [4, 5])

    def test_insecure_configuration_on_the_ast(self):
        src = ("import https from 'node:https';\nimport { createHash } from 'crypto';\nimport * as fs from 'fs';\n"
               "const agent = new https.Agent({ rejectUnauthorized: false });\n"                     # 4 high
               "const txt = 'rejectUnauthorized: false';\n"                                           # 5 string: no
               "const opts = { rejectUnauthorized: flag };\n"                                         # 6 no
               "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n"                                    # 7 high
               "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0;\n"                                   # 8 high
               "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';\n"                                    # 9 no
               "const ALGO = 'md5';\n"                                                                # 10
               "createHash(ALGO).update(pw);\n"                                                       # 11 medium (const)
               "createHash('sha1');\n"                                                                # 12 medium
               "createHash('sha256');\n"                                                              # 13 no
               "const sessionToken = Math.random().toString(36);\n"                                   # 14 medium
               "const n1 = 1;\nconst n2 = 2;\nconst n3 = 3;\n"                                      # 15-17 (out of the window)
               "const jitter = Math.random();\n"                                                      # 18 no
               "jwt.verify(t, k, { algorithms: ['HS256', 'none'] });\n"                               # 19 high
               "jwt.verify(t, k, { algorithms: ['HS256'] });\n"                                       # 20 no
               "jwt.sign(p, k, { algorithm: 'none' });\n"                                             # 21 high
               "app.use(cors({ origin: '*', credentials: true }));\n"                                 # 22 medium
               "app.use(cors({ origin: '*' }));\n"                                                    # 23 no
               "app.use(cors({ credentials: true, origin: 'https://a.example' }));\n"                 # 24 no
               "function h(req, res) {\n"                                                             # 25
               "  const name = req.params.name;\n"                                                    # 26
               "  fs.readFile(`${base}/${name}`, cb);\n"                                              # 27 medium (taint-lite)
               "  fs.readFile('/etc/hosts', cb);\n"                                                   # 28 no
               "  fs.promises.unlink(path.join(base, req.query.id));\n"                               # 29 medium
               "  const re = new RegExp(req.query.q);\n"                                              # 30 low
               "  const ok = new RegExp('^a+$');\n"                                                   # 31 no
               "  return React.createElement('div', { dangerouslySetInnerHTML: { __html: req.body.html } });\n"  # 32 high
               "}\n")
        findings = self.scan_files({"server.mjs": src})
        got = {f.line: f.severity for f in self.by_rule(findings, "RS-SEC-006")}
        self.assertEqual(got, {4: "high", 7: "high", 8: "high", 11: "medium", 12: "medium", 14: "medium", 19: "high",
                               21: "high", 22: "medium", 27: "medium", 29: "medium", 30: "low", 32: "high"})
        self.assertEqual({f.line: f.confidence for f in self.by_rule(findings, "RS-SEC-006") if f.line in (14, 27, 30)},
                         {14: "medium", 27: "high", 30: "high"})
        jsx = ("export function View({ html, req }) {\n  return (\n    <div>\n      <p dangerouslySetInnerHTML={{ __html: html }} />\n"
               "      <p dangerouslySetInnerHTML={{ __html: req.body.html }} />\n      <p dangerouslySetInnerHTML={{ __html: '<b>x</b>' }} />\n"
               "    </div>\n  );\n}\n")
        got = {f.line: f.severity for f in self.by_rule(self.scan_files({"v.tsx": jsx}), "RS-SEC-006")}
        self.assertEqual(got, {4: "medium", 5: "high", 6: "low"})

    def test_async_and_resource_rules_on_the_ast(self):
        src = ("const fs = require('fs');\nconst net = require('net');\n"
               "async function save(x) { await fs.promises.writeFile('a', x); }\n"                   # 3
               "class Svc {\n  async run() { this.save(); await this.save(); }\n  async save() {} }\n"  # 5 floating this.save()
               "function usesAwait() {\n  const d = fs.readFileSync('a');\n  return (async () => { await d; })();\n}\n"  # 7-10: no await directly
               "async function main(items) {\n"                                                       # 11
               "  save(1);\n"                                                                           # 12 floating
               "  await save(2);\n  void save(3);\n  save(4).catch(log);\n  return save(5);\n"         # 13-16 ok
               "}\n"
               "function sync(items) {\n"                                                               # 18
               "  const data = fs.readFileSync('x');\n"                                                 # 19 ok: not async
               "  items.forEach(async (i) => { await save(i); });\n"                                    # 20 forEach(async)
               "  fetch('/a');\n"                                                                        # 21 floating
               "  fetch('/b').then((r) => r.json());\n"                                                 # 22 then w/o catch
               "  fetch('/c').then(ok, onError);\n  fetch('/d').then(ok).catch(log);\n  log(fetch('/e'));\n"  # 23-25 ok
               "  Promise.all([save(1)]);\n"                                                             # 26 floating
               "  const p = fetch('/f');\n  p.then(use);\n"                                              # 27 ok, 28 then w/o catch
               "  somethingElse().finally(done);\n"                                                      # 29 not flagged
               "}\n"
               "async function withAwait() {\n  await x;\n  const n = fs.readFileSync('n');\n"            # 31-33 blocking
               "  const cb = () => fs.readFileSync('m');\n  return cb;\n}\n"                             # 34 nested sync: ok
               "const w = fs.createWriteStream('out');\n"                                                # 37 leak
               "const piped = fs.createWriteStream('p'); src.pipe(piped);\n"                             # 38 ok
               "const rs = fs.createReadStream('r');\n"                                                  # 39 leak (never consumed)
               "const rs2 = fs.createReadStream('r2'); rs2.on('data', use);\n"                           # 40 ok
               "function openIt() { const fh = fs.openSync('f'); return fh; }\n"                         # 41 ok (returned)
               "function closeIt() { const fh = fs.openSync('f'); try { use(fh); } finally { fs.closeSync(fh); } }\n"  # 42 ok
               "const sock = net.createConnection(80);\n"                                                # 43 leak
               "const ws = new WebSocket(u); ws.close();\n"                                              # 44 ok
               "const timer = setInterval(tick, 10);\n"                                                  # 45 leak
               "const t2 = setInterval(tick, 10); clearInterval(t2);\n"                                  # 46 ok
               "setInterval(tick, 50);\n"                                                                # 47 discarded
               "class Poller { start() { this.timer = setInterval(tick, 1); } }\n")                      # 48 ok (field)
        findings = self.scan_files({"a.js": src})
        got = sorted((f.rule_id, f.line) for f in findings if f.rule_id in ("RS-ASYNC-001", "RS-ASYNC-002", "RS-RES-001"))
        self.assertEqual(got, [("RS-ASYNC-001", 33),
                               ("RS-ASYNC-002", 5), ("RS-ASYNC-002", 12), ("RS-ASYNC-002", 20), ("RS-ASYNC-002", 21),
                               ("RS-ASYNC-002", 22), ("RS-ASYNC-002", 26), ("RS-ASYNC-002", 28),
                               ("RS-RES-001", 37), ("RS-RES-001", 39), ("RS-RES-001", 43), ("RS-RES-001", 45), ("RS-RES-001", 47)])
        self.assertTrue(all(f.confidence == "high" and "approximate" not in f.message
                            for f in findings if f.rule_id in ("RS-ASYNC-001", "RS-ASYNC-002", "RS-RES-001")))
        self.assertEqual([f for f in self.scan_files({"a.test.js": src}) if f.rule_id.startswith(("RS-ASYNC", "RS-RES"))], [])

    PARITY = {
        "app.js": ("const { exec } = require('child_process');\nconst util = require('./util');\n"
                   "app.get('/x', (req, res) => {\n  exec(req.query.cmd);\n  const c = req.body.c;\n  exec(c);\n});\n"
                   "const api = { exec(cmd) { return util.run(cmd); } };\n"           # old FP: method named exec
                   "window.eval(code);\n"                                            # old FN: eval as a global member
                   "try { api.exec('ls'); } catch (e) {}\n"
                   "module.exports = api;\n"),
        "util.js": ("const app = require('./app');\n"
                    "function run(cmd, x: T) {\n"
                    "  const t = (x as any) as (T extends U ? A : B);\n"          # old FP: type-level `?` counted
                    "  if (cmd === 1) {} if (cmd === 2) {} if (cmd === 3) {} if (cmd === 4) {} if (cmd === 5) {}\n"
                    "  if (cmd === 6) {} if (cmd === 7) {} if (cmd === 8) {} if (cmd === 9) {}\n"
                    "  return t;\n}\nmodule.exports = { run, app };\n"),
    }

    def test_fallback_parity_with_parser_disabled(self):
        files = {"app.js": self.PARITY["app.js"], "util.ts": self.PARITY["util.js"]}
        new = {(f.rule_id, f.file, f.line) for f in self.scan_files(files)}
        with self.heuristics_only():
            old_findings = self.scan_files(files)
        old = {(f.rule_id, f.file, f.line) for f in old_findings}
        true_positives = {("RS-SEC-003", "app.js", 4), ("RS-SEC-003", "app.js", 6), ("RS-QUAL-004", "app.js", 10),
                          ("RS-ARCH-001", "app.js", 2)}
        old_false_positives = {("RS-SEC-003", "app.js", 8), ("RS-QUAL-001", "util.ts", 2)}
        self.assertEqual(old, true_positives | old_false_positives)
        self.assertEqual(new, true_positives | {("RS-SEC-004", "app.js", 9)})
        self.assertTrue(all(f.confidence in ("low", "medium") or f.rule_id == "RS-ARCH-001" for f in old_findings))
        self.assertTrue(all("approximate" in f.message for f in old_findings if f.rule_id.startswith("RS-QUAL")))
        self.assertEqual(self.by_rule(old_findings, "RS-SYS-001"), [])

    TS_PROJECT = {
        "src/index.ts": ("export * from './routes/users';\nexport { App } from './app';\nexport type { User } from './models/user';\n"
                         "export { Role, Color } from './models/role';\nexport * as utils from './lib/utils';\n"),
        "src/app.ts": (
            "import express, { Request, Response, NextFunction } from 'express';\nimport { exec } from 'node:child_process';\n"
            "import { usersRouter } from './routes/users';\nimport { Repository } from './lib/repository';\nimport type { User } from './models/user';\n\n"
            "export class App {\n  private readonly app = express();\n  private repo: Repository<User>;\n\n"
            "  constructor(private readonly port: number = 3000) {\n    this.repo = new Repository<User>('users');\n    this.app.use(express.json());\n"
            "    this.app.use('/users', usersRouter);\n    this.app.get('/health', (_req: Request, res: Response) => res.json({ ok: true }));\n"
            "    this.app.get('/run', (req: Request, res: Response, next: NextFunction) => {\n      const cmd = req.query.cmd as string;\n"
            "      exec(cmd, (err, out) => (err ? next(err) : res.send(out)));\n    });\n  }\n\n"
            "  async start(): Promise<void> {\n    await this.repo.connect();\n    this.app.listen(this.port, () => console.log(`listening on ${this.port}`));\n  }\n}\n"),
        "src/routes/users.ts": (
            "import { Router, Request, Response } from 'express';\nimport { User, isAdmin } from '../models/user';\nimport { Role } from '../models/role';\n"
            "import { paginate, Page } from '../lib/utils';\n\nexport const usersRouter = Router();\nconst users: User[] = [];\n\n"
            "usersRouter.get('/', (req: Request, res: Response) => {\n  const page: Page<User> = paginate(users, Number(req.query.page ?? 1), 20);\n  res.json(page);\n});\n\n"
            "usersRouter.post('/', (req: Request<{}, {}, Partial<User>>, res: Response) => {\n  const body = req.body;\n"
            "  if (!body.name || typeof body.name !== 'string') {\n    return res.status(400).json({ error: 'name required' });\n  }\n"
            "  const user: User = { id: users.length + 1, name: body.name, role: body.role ?? Role.Viewer, tags: body.tags ?? [] };\n"
            "  users.push(user);\n  res.status(201).json(user);\n});\n\n"
            "usersRouter.delete('/:id', (req: Request<{ id: string }>, res: Response) => {\n  const idx = users.findIndex((u) => u.id === Number(req.params.id));\n"
            "  if (idx < 0) {\n    return res.sendStatus(404);\n  }\n  if (!isAdmin(users[idx]!)) {\n    users.splice(idx, 1);\n  }\n  try {\n    audit(users[idx]);\n  } catch {\n  }\n  res.sendStatus(204);\n});\n\n"
            "function audit(user?: User): void {\n  if (user) {\n    console.log(`deleted ${user.name}`);\n  }\n}\n"),
        "src/models/user.ts": (
            "import { Role } from './role';\n\nexport interface User {\n  readonly id: number;\n  name: string;\n  role: Role;\n  tags: string[];\n  email?: string;\n}\n\n"
            "export type UserPatch = Partial<Omit<User, 'id'>>;\nexport type Keys = keyof User;\nexport type Getters<T> = { [K in keyof T as `get${Capitalize<K & string>}`]: () => T[K] };\n\n"
            "export function isAdmin(user: User): user is User & { role: Role.Admin } {\n  return user.role === Role.Admin;\n}\n\n"
            "export const DEFAULT_USER = { id: 0, name: 'anonymous', role: Role.Viewer, tags: [] } as const satisfies Readonly<User>;\n"),
        "src/models/role.ts": (
            "export enum Role {\n  Admin = 'admin',\n  Editor = 'editor',\n  Viewer = 'viewer',\n}\n\nexport const enum Color { Red, Green = 2, Blue = Green << 1 }\n\n"
            "export namespace Role {\n  export function parse(value: string): Role {\n    switch (value) {\n      case 'admin': return Role.Admin;\n      case 'editor': return Role.Editor;\n      default: return Role.Viewer;\n    }\n  }\n}\n"),
        "src/lib/utils.ts": (
            "import { Repository } from './repository';\n\nexport interface Page<T> {\n  items: T[];\n  page: number;\n  total: number;\n}\n\n"
            "export function makeRepo<T extends { id: number }>(name: string): Repository<T> {\n  return Repository.create<T>(name);\n}\n\n"
            "export function paginate<T>(items: readonly T[], page: number, size: number): Page<T> {\n  const start = (page - 1) * size;\n"
            "  return { items: items.slice(start, start + size), page, total: items.length };\n}\n\n"
            "export const identity = <T,>(x: T): T => x;\nexport const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));\n"
            "export function assertNever(x: never): never {\n  throw new Error(`unexpected ${JSON.stringify(x)}`);\n}\n\n"
            "export abstract class Base<T extends { id: number }> {\n  protected items = new Map<number, T>();\n  abstract validate(item: T): boolean;\n"
            "  add(item: T): this {\n    if (this.validate(item)) {\n      this.items.set(item.id, item);\n    }\n    return this;\n  }\n}\n"),
        "src/lib/repository.ts": (
            "import { Base } from './utils';\n\nfunction log(target: object, key: string, descriptor: PropertyDescriptor): PropertyDescriptor {\n  return descriptor;\n}\n\n"
            "export class Repository<T extends { id: number }> extends Base<T> {\n  private connected = false;\n  declare readonly kind: 'memory';\n\n"
            "  constructor(public readonly name: string) {\n    super();\n  }\n\n"
            "  validate(item: T): boolean {\n    return item.id > 0;\n  }\n\n"
            "  @log\n  async connect(): Promise<void> {\n    this.connected = true;\n    await Promise.resolve();\n  }\n\n"
            "  get size(): number {\n    return this.items.size;\n  }\n\n"
            "  find(id: number): T | undefined {\n    return this.items.get(id);\n  }\n\n"
            "  static create<U extends { id: number }>(name: string): Repository<U> {\n    return new Repository<U>(name);\n  }\n}\n"),
        "src/ui/UserList.tsx": (
            "import React, { useEffect, useState } from 'react';\nimport type { User } from '../models/user';\nimport { Role } from '../models/role';\n\n"
            "interface Props {\n  users: User[];\n  onSelect?: (user: User) => void;\n  highlight?: Role;\n}\n\n"
            "export function UserList({ users, onSelect, highlight = Role.Admin }: Props) {\n  const [filter, setFilter] = useState<string>('');\n"
            "  const [count, setCount] = useState(0);\n\n  useEffect(() => {\n    setCount(users.length);\n  }, [users]);\n\n"
            "  const visible = users.filter((u) => u.name.toLowerCase().includes(filter.toLowerCase()));\n\n"
            "  return (\n    <section className=\"user-list\">\n      <h2>Users ({count})</h2>\n"
            "      <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder=\"Filter users…\" />\n"
            "      {visible.length === 0 ? (\n        <p>No one's here yet.</p>\n      ) : (\n        <ul>\n"
            "          {visible.map((u) => (\n            <li key={u.id} className={u.role === highlight ? 'hl' : ''} onClick={() => onSelect?.(u)}>\n"
            "              {u.name} <small>{u.role}</small> {u.tags.length > 0 && <em>{u.tags.join(', ')}</em>}\n            </li>\n          ))}\n        </ul>\n      )}\n"
            "      <footer>{\"{\"}{count}{\"}\"} total &amp; {visible.length} shown</footer>\n    </section>\n  );\n}\n\n"
            "export const Badge = <T extends { label: string },>({ item }: { item: T }) => <span className=\"badge\">{item.label}</span>;\n\nexport default UserList;\n"),
        "src/lib/events.ts": (
            "import type { User } from '@/models/user';\n\ntype Listener<T> = (payload: T) => void | Promise<void>;\n\n"
            "export interface EventMap {\n  'user:created': User;\n  'user:deleted': { id: number };\n  tick: void;\n}\n\n"
            "export class Emitter<M extends Record<string, unknown> = EventMap> {\n  readonly #listeners = new Map<keyof M, Set<Listener<any>>>();\n\n"
            "  on<K extends keyof M>(event: K, listener: Listener<M[K]>): () => void;\n  on<K extends keyof M>(event: K, listener: Listener<M[K]>, once: boolean): () => void;\n"
            "  on<K extends keyof M>(event: K, listener: Listener<M[K]>, once = false): () => void {\n    const wrapped: Listener<M[K]> = once\n"
            "      ? (payload) => {\n          this.off(event, wrapped);\n          return listener(payload);\n        }\n      : listener;\n"
            "    let set = this.#listeners.get(event);\n    if (!set) {\n      set = new Set();\n      this.#listeners.set(event, set);\n    }\n    set.add(wrapped);\n"
            "    return () => this.off(event, wrapped);\n  }\n\n"
            "  off<K extends keyof M>(event: K, listener: Listener<M[K]>): void {\n    this.#listeners.get(event)?.delete(listener);\n  }\n\n"
            "  async emit<K extends keyof M>(event: K, payload: M[K]): Promise<number> {\n    const set = this.#listeners.get(event);\n    if (!set) {\n      return 0;\n    }\n"
            "    await Promise.all([...set].map((l) => l(payload)));\n    return set.size;\n  }\n}\n\n"
            "export namespace Events {\n  export const global = new Emitter();\n  export declare const version: string;\n}\n"),
        "src/ui/hooks.tsx": (
            "import { useCallback, useMemo, useRef, useState } from 'react';\nimport { Events } from '@/lib/events';\n\n"
            "export function useToggle(initial = false): [boolean, () => void] {\n  const [on, setOn] = useState(initial);\n"
            "  const toggle = useCallback(() => setOn((v) => !v), []);\n  return [on, toggle];\n}\n\n"
            "export function useLatest<T>(value: T) {\n  const ref = useRef<T>(value);\n  ref.current = value;\n  return ref;\n}\n\n"
            "export function Spinner({ size = 16, label }: { size?: number; label?: string }) {\n"
            "  const style = useMemo(() => ({ width: size, height: size }), [size]);\n"
            "  return (\n    <span role=\"status\" style={style} aria-label={label ?? 'loading'}>\n      {label && <span className=\"sr-only\">{label}</span>}\n    </span>\n  );\n}\n\n"
            "export const subscribe = Events.global.on.bind(Events.global);\n"),
        "tsconfig.json": "{\n  \"compilerOptions\": { \"baseUrl\": \".\", \"paths\": { \"@/*\": [\"src/*\"] }, \"jsx\": \"react\" }\n}\n",
    }

    def test_dogfood_typescript_project(self):
        lines = sum(v.count("\n") for k, v in self.TS_PROJECT.items() if k != "tsconfig.json")
        self.assertGreaterEqual(lines, 250)
        for rel, src in self.TS_PROJECT.items():
            if rel.endswith(".json"):
                continue
            result = js_parse(src, rel)
            self.assertTrue(result.ok, rel)
            self.assertEqual(result.errors, [], rel)
        findings = self.scan_files(self.TS_PROJECT)
        self.assertEqual(sorted({(f.rule_id, f.file) for f in findings}),
                         [("RS-ARCH-001", "src/lib/repository.ts"), ("RS-QUAL-004", "src/routes/users.ts"), ("RS-SEC-003", "src/app.ts")])
        self.assertEqual(len(findings), 3)
        sec = self.by_rule(findings, "RS-SEC-003")[0]
        self.assertEqual((sec.line, sec.severity, sec.confidence), (18, "critical", "high"))
        self.assertEqual(self.by_rule(findings, "RS-SYS-001"), [])
        cycle = self.by_rule(findings, "RS-ARCH-001")[0]
        self.assertIn("src/lib/repository -> src/lib/utils -> src/lib/repository", cycle.message)
        self.assertEqual(cycle.severity, "high")

    def test_json_output_deterministic_and_crlf_identical(self):
        root_lf = self.make_project(self.TS_PROJECT)
        root_crlf = self.make_project({k: v.replace("\n", "\r\n") for k, v in self.TS_PROJECT.items()})
        out1 = self.run_cli([root_lf, "--format", "json"])[1]
        out2 = self.run_cli([root_lf, "--format", "json"])[1]
        out3 = self.run_cli([root_crlf, "--format", "json"])[1]
        self.assertEqual(out1, out2)
        self.assertEqual(out1, out3)
        data = json.loads(out1)
        self.assertEqual(data["version"], __version__)
        self.assertEqual(data["summary"]["total"], 3)

    def test_env_var_forces_heuristics_and_suppression_baseline_still_work(self):
        src = "const { exec } = require('child_process');\nexec(req.query.cmd);\nexec(x); // reposentry: ignore RS-SEC-003\n"
        root = self.make_project({"a.js": src})
        new = scan(root).findings
        self.assertEqual([(f.line, f.confidence) for f in self.by_rule(new, "RS-SEC-003")], [(2, "high")])
        with self.heuristics_only():
            old = scan(root).findings
        self.assertEqual([(f.line, f.confidence) for f in self.by_rule(old, "RS-SEC-003")], [(2, "medium")])
        self.assertEqual(self.by_rule(old, "RS-SYS-001"), [])
        self.assertEqual(new[0].fingerprint(), old[0].fingerprint())  # same rule/file/snippet: baselines stay valid
        baseline = os.path.join(root, "b.json")
        self.assertEqual(self.run_cli([root, "--write-baseline", baseline])[0], 1)
        self.assertEqual(self.run_cli([root, "--baseline", baseline])[0], 0)
        self.assertEqual(self.by_rule(self.scan_files({"a.js": src}, {"severity_overrides": {"RS-SEC-003": "low"}}), "RS-SEC-003")[0].severity, "low")


if __name__ == "__main__":
    sys.exit(main())
