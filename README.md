# repo_sentry

A zero-dependency static analysis and architecture-audit CLI for repositories, written in pure Python (standard library only).

Planned checks:

- **Architecture:** dependency graph, circular imports (iterative Tarjan), layer violations
- **Async hazards:** blocking calls in `async def`, fire-and-forget tasks, unprotected shared state
- **Resources:** file and socket opens not wrapped in `with` or `try/finally`
- **Quality:** cyclomatic complexity, deep nesting, bare or swallowed exceptions
- **Security:** secret scanning (patterns + Shannon entropy), command injection and dynamic-execution sinks (Python is parsed with `ast`; JS/TS are lexically masked and pattern-analysed; C/C++ and shell are pattern-based)
- **JS/TS configuration:** TLS verification off, weak hashes for credentials, `Math.random()` for secrets, JWT `none`, wildcard CORS with credentials, `dangerouslySetInnerHTML`, user-controlled `fs` paths and `RegExp` patterns (RS-SEC-006)
- **History:** `--history` scans past commits for secrets that were added and later removed (RS-SEC-005; needs `git`)
- **Example files:** `.env.example`, `*.sample.*` etc. skip well-known default passwords and downgrade other heuristic hits to low; real tokens (AWS, GitHub...) stay critical
- **Output:** terminal (ANSI), JSON and Markdown, with CI-friendly exit codes

## Supported languages

| Language | Files | Analysis | Rules | Confidence |
|---|---|---|---|---|
| Python | `.py` `.pyw` `.pyi` | full `ast` parse | all RS-ARCH, RS-ASYNC, RS-RES, RS-QUAL, RS-SEC-001..004, RS-SYS-001 | high |
| JavaScript / TypeScript | `.js` `.jsx` `.mjs` `.cjs` `.ts` `.tsx` `.mts` `.cts` | lexical masking + brace-matched function discovery (no parser) | RS-ARCH-001/002, RS-QUAL-001/002/004, RS-SEC-001..004, RS-SEC-006 | medium / low |
| C / C++ | `.c` `.h` `.cc` `.cpp` `.cxx` `.hpp` `.hh` `.hxx` | comment-stripped regexes | RS-SEC-001..004 | medium / low |
| Shell | `.sh` `.bash` `.zsh` `.ksh` (or shebang) | comment-stripped regexes | RS-SEC-001..003 | medium / low |
| Everything else (text) | any non-binary file | line scan | RS-SEC-001, RS-SEC-002 | high / medium |

### JS/TS accuracy caveats

JS/TS support is deliberately approximate and every JS/TS finding says so:

- `js_mask` blanks comments, strings, template text (code inside `${}` stays visible), regex literals and JSX text before any structural or sink rule runs; secrets are still scanned on the original text. Regex-vs-division is decided by the previous token, and JSX is detected by a cheap heuristic (off for plain `.ts`, where `<Type>value` assertions exist).
- Functions are found by brace matching (`function`, arrows with block bodies, class and object methods, getters/setters, constructors). Expression-bodied arrows belong to their enclosing function. TypeScript return types are skipped heuristically; unusual formatting can merge or miss a function.
- Complexity counts `if`, `for`, `while`, `case`, `catch`, `&&`, `||`, `??` and ternaries on the masked text; nesting counts `if/for/while/do/switch/try` blocks. Both are estimates, reported at confidence `medium`.
- The import graph resolves only relative specifiers and `tsconfig.json`/`jsconfig.json` `baseUrl`/`paths`; bare package names are dropped. `import type`, dynamic `import()` and imports inside functions are soft edges.
- `*.d.ts`, minified/bundled files, `*.map` and `node_modules`, `dist`, `build`, `coverage`, `.next`, `.nuxt`, `out` are skipped by default. Test files (`*.test.*`, `*.spec.*`, `__tests__/`) skip complexity and nesting and downgrade RS-SEC-003, RS-SEC-004 and RS-SEC-006 one level.

## Status

`repo_sentry.py` (v1.2.0) is generated and checked in. It implements every
rule and CLI option in `prompts/repo-sentry.prompt.md` plus the JS/TS
extension in `prompts/repo-sentry-js-ts.prompt.md`, and ships with an
embedded unittest suite (106 tests) that runs via
`python repo_sentry.py --self-test`.

Verified on Python 3.11, 3.12 and 3.13. Scanning the CPython standard library
(about 600 files) takes roughly 6 seconds, with no crashes or parse failures.

Scanning this repository with the tool itself reports only quality findings
(cyclomatic complexity and nesting depth in the tool's own larger functions)
and one unmanaged `subprocess.Popen` in the history scanner; the synthetic
secrets used by the test suite carry `reposentry: ignore` directives.

## Usage

```
python repo_sentry.py [path] [--format terminal|json|markdown]
                      [--fail-on-severity low|medium|high|critical]
                      [--rules RS-SEC-*] [--ignore-rules RS-QUAL-002]
                      [--config .reposentry.json]
                      [--baseline FILE] [--write-baseline FILE]
                      [--max-file-kb N] [--no-color] [--list-rules]
                      [--self-test] [--version]
```

A `.reposentry.json` in the scan root is picked up automatically; see the
config block in `prompts/repo-sentry.prompt.md` for the schema.

## Repo layout

```
.
├── README.md
├── .gitignore
├── prompts/
│   ├── repo-sentry.prompt.md         # the full spec to give the model
│   └── repo-sentry-js-ts.prompt.md   # the JS/TS extension spec (v1.2.0)
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
