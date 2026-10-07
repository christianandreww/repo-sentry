# repo_sentry

A zero-dependency static analysis and architecture-audit CLI for repositories, written in pure Python (standard library only).

Planned checks:

- **Architecture:** dependency graph, circular imports (iterative Tarjan), layer violations
- **Async hazards:** blocking calls in `async def`, fire-and-forget tasks, unprotected shared state
- **Resources:** file and socket opens not wrapped in `with` or `try/finally`
- **Quality:** cyclomatic complexity, deep nesting, bare or swallowed exceptions
- **Security:** secret scanning (patterns + Shannon entropy), command injection and dynamic-execution sinks (Python is parsed with `ast`; JS/TS, C/C++ and shell are pattern-based)
- **History:** `--history` scans past commits for secrets that were added and later removed (RS-SEC-005; needs `git`)
- **Example files:** `.env.example`, `*.sample.*` etc. skip well-known default passwords and downgrade other heuristic hits to low; real tokens (AWS, GitHub...) stay critical
- **Output:** terminal (ANSI), JSON and Markdown, with CI-friendly exit codes

## Status

`repo_sentry.py` is generated and checked in. It implements every rule and
CLI option in `prompts/repo-sentry.prompt.md` and ships with an embedded
unittest suite (64 tests) that runs via `python repo_sentry.py --self-test`.

Verified on Python 3.11, 3.12 and 3.13. Scanning the CPython standard library
(about 600 files) takes roughly 6 seconds, with no crashes or parse failures.

Scanning this repository with the tool itself reports only quality findings
(cyclomatic complexity and nesting depth in the tool's own larger functions);
the synthetic secrets used by the test suite carry `reposentry: ignore`
directives.

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
│   └── repo-sentry.prompt.md   # the full spec to give the model
└── repo_sentry.py              # generated output goes here
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
