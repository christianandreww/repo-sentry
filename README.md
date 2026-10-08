# repo_sentry

A zero-dependency static analysis and architecture-audit CLI for repositories, written in pure Python (standard library only).

Planned checks:

- **Architecture:** dependency graph, circular imports (iterative Tarjan), layer violations
- **Async hazards:** blocking calls in `async def`, fire-and-forget tasks, unprotected shared state
- **Resources:** file and socket opens not wrapped in `with` or `try/finally`
- **Quality:** cyclomatic complexity, deep nesting, bare or swallowed exceptions
- **Security:** secret scanning (patterns + Shannon entropy), command injection and dynamic-execution sinks (Python is parsed with `ast`; JS/TS are parsed with a built-in ES2023/TypeScript parser, with a lexical heuristic fallback; C/C++ and shell are pattern-based)
- **JS/TS configuration:** TLS verification off, weak hashes for credentials, `Math.random()` for secrets, JWT `none`, wildcard CORS with credentials, `dangerouslySetInnerHTML`, user-controlled `fs` paths and `RegExp` patterns (RS-SEC-006)
- **JS/TS async and resources:** blocking `*Sync` calls inside `async` functions (RS-ASYNC-001), floating promises, `forEach(async ...)` and `.then()` without a rejection handler (RS-ASYNC-002), and streams / sockets / file handles / `setInterval` timers that are never closed, cleared, piped, returned or stored (RS-RES-001). Decided on the AST (confidence high); test files are skipped.
- **History:** `--history` scans past commits for secrets that were added and later removed (RS-SEC-005; needs `git`)
- **Example files:** `.env.example`, `*.sample.*` etc. skip well-known default passwords and downgrade other heuristic hits to low; real tokens (AWS, GitHub...) stay critical
- **Output:** terminal (ANSI), JSON and Markdown, with CI-friendly exit codes

## Supported languages

| Language | Files | Analysis | Rules | Confidence |
|---|---|---|---|---|
| Python | `.py` `.pyw` `.pyi` | full `ast` parse | all RS-ARCH, RS-ASYNC, RS-RES, RS-QUAL, RS-SEC-001..004, RS-SYS-001 | high |
| JavaScript / TypeScript | `.js` `.jsx` `.mjs` `.cjs` `.ts` `.tsx` `.mts` `.cts` | parser-based (built-in ES2023 + TypeScript parser), with heuristic fallback | RS-ARCH-001/002, RS-ASYNC-001/002, RS-RES-001, RS-QUAL-001/002/004, RS-SEC-001..004, RS-SEC-006 | high (AST path); medium / low (fallback) |
| C / C++ | `.c` `.h` `.cc` `.cpp` `.cxx` `.hpp` `.hh` `.hxx` | comment-stripped regexes | RS-SEC-001..004 | medium / low |
| Shell | `.sh` `.bash` `.zsh` `.ksh` (or shebang) | comment-stripped regexes | RS-SEC-001..003 | medium / low |
| Everything else (text) | any non-binary file | line scan | RS-SEC-001, RS-SEC-002 | high / medium |

### JS/TS analysis: parser-based, with heuristic fallback

Every JS/TS file is parsed once by a hand-written recursive-descent parser (pure Python, standard library only) covering ES2023 plus the TypeScript syntax found in real code: type annotations, interfaces, enums, namespaces, generics at declarations and call sites, `as`/`satisfies`/`<T>x`, decorators (parsed and ignored), overloads, JSX in `.js`/`.jsx`/`.tsx`, `<T,>(x) => x` in `.tsx`, regex-vs-division decided by parser context, and templates with nested `${}`. Types are consumed, not evaluated. All JS rules share the one AST:

- **Function discovery** names every declaration, expression, arrow, method, getter/setter, constructor and static block (variable, property, assignment target, `Class.method`, `default`, `<anonymous>`), with exact line ranges; nested functions are scored separately.
- **RS-QUAL-001** is exact McCabe (1 + if + loops + each `case` with a test + catch + conditional + each `&&` `||` `??` + logical assignment; `else if` counts once, optional chaining does not). **RS-QUAL-002** counts if/for/while/do/switch/try nesting; `else if`, `catch` and `finally` do not add depth. **RS-QUAL-004** flags an empty `catch` body (comments count as empty).
- **RS-ARCH-001/002** build the graph from `import`/`export ... from`/`require('x')`/`import('x')`/`import x = require('x')`. `import type`/`export type`, dynamic `import()` and imports inside function bodies are soft edges.
- **RS-SEC-003/004/006** match call, member and assignment nodes (no regexes): `exec`/`execSync` bound to `child_process`/`execa`/`shelljs`, `spawn(..., {shell: true})`, `eval`/`window.eval`, `new Function`, `setTimeout(string)`, `innerHTML`/`outerHTML` assignment, `document.write`, `insertAdjacentHTML`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED='0'`, `createHash('md5'|'sha1')`, `Math.random()` near secret-like identifiers, JWT `algorithms` containing `'none'`, CORS `origin: '*'` with `credentials: true`, `dangerouslySetInnerHTML`, `fs` path arguments and `new RegExp()` built from request data.
- **Taint-lite** decides sink severity. An argument is *constant* when it is a string/number literal, a template without expressions, or a `const` bound in the same file to such a literal (one level). It is *tainted* when it mentions `req`/`request`/`ctx`/`params`/`query`/`body`/`argv`, `process.argv`/`process.env`, a name destructured from one of those, or a variable assigned from a tainted expression in the same function (straight-line, flow-insensitive, inherited by nested functions). Tainted arguments keep the top severity (critical for exec/eval, high for XSS sinks), untainted non-constant arguments are one level lower, constants two levels lower.
- **RS-ASYNC-001** finds `*Sync`/`execSync`/`pbkdf2Sync`/... calls inside `async` functions or functions that `await`, by AST ancestry; nested synchronous callbacks are not flagged. **RS-ASYNC-002** flags an expression statement that calls a same-file `async` function, `fetch`, `Promise.all/allSettled/race/any`, `*.promises.*`, a `.then()` chain without `.catch()` (or a two-argument `then`), and `forEach(async ...)`; awaited, returned, assigned, `void`-prefixed or argument-passed calls are not flagged. **RS-RES-001** flags `createReadStream`/`createWriteStream`/`fs.open*`/`net.connect`/`createConnection`/`tls.connect`/`new WebSocket`/`new net.Socket`/`setInterval` results that are never closed, ended, destroyed, piped, consumed, cleared, returned, passed on or stored on a field, anywhere in the enclosing function.
- AST-path findings carry confidence `high` (the `Math.random()` proximity check stays `medium`) and no longer say "approximate".

**Error recovery and fallback.** A syntax error is recorded and parsing resumes at the next statement boundary; a file with a few recovered errors is analysed from the recovered AST and gets one RS-SYS-001 [low] saying how many errors were recovered. A file with more than 5 errors per 100 lines (at least 5), nesting deeper than 400 levels, or an internal parser error is handed unchanged to the previous lexical heuristics (`js_mask`, brace-matched function discovery, pattern sinks) with one RS-SYS-001 [low]; those findings keep confidence `medium`/`low` and the word "approximate" in their messages. Setting `REPO_SENTRY_JS_PARSER=0` forces the heuristic path for every file (no RS-SYS-001 in that case). Pathological inputs (200k nested parentheses, 100k-term expressions, a 1 MB single line, unterminated templates/strings/regexes/JSX, binary-looking files) finish in well under 5 seconds each.

**Measured parse speed** (CPython 3.13, one core): about 950 KB/s on realistic module code, about 490 KB/s on TypeScript/TSX and about 320 KB/s on a worst-case flat one-liner of 540k tokens, against a 150 KB/s target. The `--max-file-kb` cap (default 1024) still applies.

**Still approximate on both paths:** test files (`*.test.*`, `*.spec.*`, `__tests__/`) skip complexity, nesting, async and resource rules and downgrade RS-SEC-003/004/006 one level; `*.d.ts`, minified/bundled files (any line over 2000 characters), `*.map` and `node_modules`, `dist`, `build`, `coverage`, `.next`, `.nuxt`, `out` are skipped by default. The import graph resolves only relative specifiers and `tsconfig.json`/`jsconfig.json` `baseUrl`/`paths`; bare package names are dropped. Taint is intra-function and flow-insensitive, so a sanitised value is still reported as tainted.

## Status

`repo_sentry.py` (v1.4.0) is generated and checked in. It implements every
rule and CLI option in `prompts/repo-sentry.prompt.md`, the JS/TS
extension in `prompts/repo-sentry-js-ts.prompt.md` and the JS/TS parser in
`prompts/repo-sentry-js-parser.prompt.md`, and ships with an embedded
unittest suite (136 tests) that runs via
`python repo_sentry.py --self-test`.

Verified on Python 3.11, 3.12 and 3.13. Scanning the CPython standard library
(about 600 files) takes roughly 6 seconds, with no crashes or parse failures.

Scanning this repository with the tool itself reports only quality findings
(cyclomatic complexity and nesting depth in the tool's own larger functions)
and one unmanaged `subprocess.Popen` in the history scanner; the synthetic
secrets used by the test suite carry `reposentry: ignore` directives.

## Usage

Needs Python 3.9+ and nothing else. Copy `repo_sentry.py` anywhere and run it.

```
python repo_sentry.py --self-test           # optional: embedded test suite
python repo_sentry.py path/to/project       # scan a folder (default: .)
```

| Task | Command |
|---|---|
| Scan the current folder | `python repo_sentry.py .` |
| Report to read or share | `python repo_sentry.py . --format markdown > report.md` |
| Machine-readable output | `--format json` |
| Only some rules | `--rules "RS-SEC-*"` |
| Skip a rule | `--ignore-rules RS-QUAL-002` |
| List every rule | `--list-rules` |
| Secrets deleted in later commits | `--history` (needs git; `--history-max N` commits, default 500) |
| Change the pass/fail threshold | `--fail-on-severity medium` (default `high`) |
| Skip big files | `--max-file-kb 512` (default 1024) |

Each finding shows the rule ID, severity, confidence, `file:line:col`, the offending line (secrets
redacted) and a suggested fix.

### Living with findings

- **One line:** add `# reposentry: ignore RS-SEC-003` (or `// …` in JS/TS). A trailing comment silences
  its own line; a comment on a line of its own silences the line below. Omit the ID to silence every rule.
- **Existing debt:** `--write-baseline baseline.json` once, then run with `--baseline baseline.json`
  so only new findings show.
- **Project settings:** a `.reposentry.json` in the scan root is loaded automatically, for example:

```json
{
  "ignore_dirs": [".git", "node_modules", "venv", "dist"],
  "thresholds": {"max_cyclomatic_complexity": 12, "max_nesting_depth": 4},
  "severity_overrides": {"RS-QUAL-002": "low"}
}
```

  The full schema (layers, forbidden imports, package roots, extra sinks) is in
  `prompts/repo-sentry.prompt.md`.

### In CI

```yaml
- run: python repo_sentry.py . --fail-on-severity high --format markdown >> "$GITHUB_STEP_SUMMARY"
```

Exit codes: `0` pass, `1` findings at or above the threshold, `2` tool, config or usage error.

## Repo layout

```
.
├── README.md
├── .gitignore
├── prompts/
│   ├── repo-sentry.prompt.md           # the full spec to give the model
│   ├── repo-sentry-js-ts.prompt.md     # the JS/TS extension spec (v1.2.0)
│   └── repo-sentry-js-parser.prompt.md # the JS/TS parser spec (v1.4.0)
└── repo_sentry.py                    # generated output goes here
```

## Workflow

1. Paste `prompts/repo-sentry.prompt.md` into Claude Fable (or Sonnet to save credits).
2. Save the single code block it returns as `repo_sentry.py` in the repo root.
3. Run `python repo_sentry.py --self-test`, then `python repo_sentry.py .` on a real project.
4. Commit the result.

## Notes

- Exit codes: `0` = pass, `1` = findings at or above `--fail-on-severity`, `2` = tool, config or usage error.
- Secrets are always redacted in the output. The tool should never print a full credential.
- If the model's output truncates, ask it to continue from the exact last line rather than regenerating.
