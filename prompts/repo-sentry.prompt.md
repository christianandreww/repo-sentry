ROLE
You are a principal security architect and tooling engineer.

DELIVERABLE (OUTPUT CONTRACT)
- Output exactly ONE fenced code block: the complete `repo_sentry.py`, with its test suite embedded as unittest classes. No prose before or after.
- Python 3.9+ standard library only. No third-party imports, including optional ones (do not use rich or pytest). Guard newer syntax (e.g. ast.Match, sys.stdlib_module_names) with getattr/hasattr so the tool still runs on 3.9.
- No TODOs, placeholders, stubs, or "implement here" comments. Everything is fully implemented and error-handled.
- If you have a code-execution tool, run `python repo_sentry.py --self-test` and `python repo_sentry.py .`, and fix every failure before answering. If you cannot run code, trace each acceptance test by hand.

CLI
- `python repo_sentry.py [path]` (positional, default ".") and `--path PATH` as an alias.
- `--format {terminal,json,markdown}` (default terminal)
- `--fail-on-severity {low,medium,high,critical}` (default high)
- `--rules RULES` select comma-separated rule IDs or globs (e.g. RS-SEC-*); `--ignore-rules RULES`; `--list-rules` prints the catalog and exits 0.
- `--config PATH` (default: `<path>/.reposentry.json` if present), `--baseline PATH`, `--write-baseline PATH`, `--self-test`, `--no-color`, `--max-file-kb N` (default 1024), `--version`.
- Exit codes: 0 = no findings at or above the threshold; 1 = findings at or above it; 2 = tool/config/usage error (message on stderr).

FINDING MODEL (used by every output format)
rule_id, severity (low|medium|high|critical), confidence (low|medium|high), file (path relative to the scan root, forward slashes), line, col, message, snippet (the offending line, trimmed, redacted where required), remediation. Sort deterministically by (severity desc, file, line, rule_id). Suppression: an inline comment `reposentry: ignore RS-XXX-NNN` (any comment syntax) on the same or preceding line. A baseline file stores fingerprints (rule_id + file + normalized snippet hash) and suppresses known findings.

CONFIG (.reposentry.json; validate it, report unknown keys as warnings and invalid values as exit 2)
{
  "ignore_dirs": [".git", "venv", ".venv", "node_modules", "__pycache__", "dist", "build"],
  "ignore_globs": ["*.min.js", "*.lock"],
  "respect_gitignore": true,
  "thresholds": {"max_cyclomatic_complexity": 10, "max_nesting_depth": 4, "entropy_hex": 3.0, "entropy_base64": 4.5, "min_secret_length": 20},
  "severity_overrides": {"RS-QUAL-001": "low"},
  "layers": ["api", "service", "domain"],          // earlier layers may import later ones, never the reverse
  "forbidden_imports": [{"from": "domain", "to": "api"}],
  "package_roots": ["src", "."],
  "extra_blocking_calls": [], "extra_dangerous_sinks": []
}

RULE CATALOG (stable IDs, default severity in brackets)
ARCHITECTURE
- RS-ARCH-001 circular import [high]: report each strongly connected component of size > 1 (and self-imports) once, with the cycle path.
- RS-ARCH-002 layer or forbidden-import violation [high].
  Graph rules: resolve absolute and relative imports (`from . import x`, `from ..a import b`), packages with `__init__.py`, namespace packages, and `package_roots` (src layouts). Drop stdlib and third-party imports. Imports inside functions or under `if TYPE_CHECKING:` are "soft": exclude them from RS-ARCH-001 hard cycles and report cycles that exist only through soft imports as [low]. Implement Tarjan's algorithm ITERATIVELY (no recursion).
ASYNC
- RS-ASYNC-001 blocking call inside `async def` [high]: time.sleep, requests.*, urllib.request.urlopen, subprocess.run/call/check_output, open() and file reads, socket blocking calls, input(). Resolve aliases (`import requests as r`, `from time import sleep`). Do not flag code inside a nested synchronous `def`, or calls wrapped in `asyncio.to_thread(...)` or `loop.run_in_executor(...)`.
- RS-ASYNC-002 fire-and-forget task [medium]: `asyncio.create_task`/`ensure_future`/`loop.create_task` whose result is discarded, or stored in a variable that is never awaited, gathered, returned, or given add_done_callback.
- RS-ASYNC-003 module-level mutable (list/dict/set) mutated inside an `async def` with no lock (`asyncio.Lock`/`threading.Lock`) in scope [low confidence, medium severity].
RESOURCES
- RS-RES-001 unmanaged resource [medium]: open, socket.socket, urlopen, sqlite3.connect, tempfile.NamedTemporaryFile/TemporaryFile, subprocess.Popen, zipfile.ZipFile, not used in `with`/`async with`, `contextlib.closing`, `ExitStack.enter_context`, or closed in a `finally`. Exempt: the value is returned, yielded, or stored on `self`/a container.
QUALITY
- RS-QUAL-001 cyclomatic complexity > threshold [medium; high when > 2x threshold]. McCabe = 1 + if/elif + for/async for + while + except handler + each boolean operator operand beyond the first + ternary + each comprehension for/if + each `match` case + `assert`. Nested functions are scored separately.
- RS-QUAL-002 nesting depth > threshold [low]: count nested if/for/while/try/with/match.
- RS-QUAL-003 bare `except:` [medium].
- RS-QUAL-004 `except Exception`/`BaseException` whose body is only pass/`...`/continue [medium].
SECURITY
- RS-SEC-001 known secret pattern [critical/high]: AWS access key (AKIA/ASIA + 16), GitHub tokens (ghp_/gho_/ghs_/github_pat_), Slack tokens, Stripe live keys, Google API keys (AIza), JWTs (three base64url segments, header starting eyJ), multi-line PEM private key blocks, and hardcoded `password|passwd|secret|api_key|token = "<literal>"` assignments.
- RS-SEC-002 high-entropy string [medium]: quoted or assignment-adjacent tokens >= min_secret_length with Shannon entropy above the charset-specific threshold (hex vs base64 vs mixed). False-positive reducers: skip UUIDs, git SHAs in lockfiles/comments about commits, placeholder words (example, changeme, xxxx, your_, <...>, dummy, test, sample), repeated-character strings, import paths, and URLs without credentials. Skip lockfiles, minified files, binaries, images, and files over the size cap.
- RS-SEC-003 command injection [high]: os.system, os.popen, subprocess.* with shell=True, commands.getoutput; JS child_process.exec/execSync; C system()/popen(); shell `eval` and `curl|sh`/`wget|bash`. Severity [critical] when the argument is non-constant (f-string, concatenation, %-format, .format, a variable); [medium] for a constant string.
- RS-SEC-004 dynamic code execution [high/critical, same constant-vs-nonconstant rule]: eval, exec, compile on non-constants, `pickle.loads`, `yaml.load` without SafeLoader, `marshal.loads`, `__import__` on non-constants; JS eval/new Function/setTimeout(string)/innerHTML=; C gets/strcpy/strcat/sprintf.
- RS-SYS-001 file could not be parsed (SyntaxError, encoding error) [low]: never crash, continue scanning.
- SECRET REDACTION: in ALL output formats, never print a full secret. Show the first 4 characters plus `****` and the length. Snippets containing a match must be redacted the same way.
Non-Python languages (JS/TS, C/C++, shell): pattern-based only. State this in --list-rules output and tag those findings confidence=low/medium. Strip obvious comment-only lines for sink rules (but not for secret rules).

OUTPUT
- terminal: ANSI colors with badges [CRITICAL] [HIGH] [MED] [LOW], `file:line:col`, a trimmed code snippet with a caret, the remediation, and a summary table (counts by severity and by rule). Honour NO_COLOR, --no-color, and non-TTY (plain text). Enable ANSI on Windows terminals when possible and degrade gracefully.
- json: {"tool","version","scanned_files","summary":{...},"findings":[...]} with a stable key order.
- markdown: summary table, then findings grouped by severity, suitable for pasting into a PR comment.

ROBUSTNESS
Skip symlink loops; handle unreadable files, decode with errors="replace" for scanning, skip binaries (NUL byte sniff), respect size caps, and keep scanning after any per-file exception (record it as RS-SYS-001). Output must be deterministic across runs. Performance target: 10k files in a reasonable time (single pass per file; read each file once).

TESTS (unittest, embedded, run via `--self-test`; use tempfile directories and synthetic snippets, no network)
1. Cycle detector: a -> b -> c -> a is reported once as one SCC; an acyclic diamond reports none; a self-import is reported; relative imports resolve; a cycle only via `if TYPE_CHECKING:` is low; a 5,000-module chain does not hit the recursion limit.
2. Layer rule: domain importing api is flagged when configured; api importing domain is not.
3. Async: `async def f(): time.sleep(1)` flagged; `import time as t; t.sleep` flagged; `await asyncio.to_thread(time.sleep, 1)` not flagged; a sync nested def inside an async def not flagged; a discarded `create_task(...)` flagged.
4. Resources: bare `f = open(p)` flagged; `with open(p)` not; `try/finally: f.close()` not; `return open(p)` not.
5. Complexity: a function with exactly N branches yields the expected score (assert exact numbers for 3 hand-computed samples); a 5-deep nesting flagged; a bare except and an `except Exception: pass` flagged.
6. Secrets: a fake AWS key, a fake GitHub token, a fake JWT, and a PEM block are detected; `password = "changeme"`, a UUID, and a SHA-256 in a lockfile are NOT; the redacted output never contains the full secret (assert on the rendered terminal, json, and markdown strings).
7. Injection sinks: `os.system(user_input)` is critical, `os.system("ls")` is medium, `subprocess.run(cmd, shell=True)` flagged, `eval("1+1")` lower than `eval(x)`, aliased imports resolved.
8. Config: invalid JSON -> exit 2; severity override applied; ignore_dirs respected; suppression comment and baseline both work.
9. CLI exit codes: 0 below the threshold, 1 at or above it, 2 on a bad path or config; `--format json` output parses with json.loads and is identical across two runs.
10. Robustness: a file with a SyntaxError yields RS-SYS-001 and the scan continues; a binary file is skipped.
