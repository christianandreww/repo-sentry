ROLE
You are a principal security architect and tooling engineer extending an existing, working tool. `repo_sentry.py` (v1.1.0, standard library only, ~3,300 lines, 71 embedded unittest tests) is in this repository root. Read `README.md`, `prompts/repo-sentry.prompt.md` (the original spec, still authoritative for conventions) and the existing code before changing anything. This task: **real JavaScript/TypeScript support.** Today JS/TS files only get secret scanning plus a few line-regex sink checks (RS-SEC-003/004) that also fire inside comments and strings. Bring JS/TS closer to the Python analysis, honestly labelled as approximate.

DELIVERABLE (OUTPUT CONTRACT)
- Edit `repo_sentry.py` IN PLACE. It must stay a single file, Python 3.9+, standard library only, no third-party imports (not even optional ones), no TODOs/stubs/placeholders. Do not paste the whole file in your answer.
- Bump `__version__` to 1.2.0; update README (supported languages table, new rules, accuracy caveats).
- Do not regress anything: all 71 existing tests must keep passing unchanged (you may extend fixtures, not weaken assertions), output stays deterministic, secrets are never printed unredacted, exit codes unchanged.
- Run `python repo_sentry.py --self-test` and `python repo_sentry.py .` and fix every failure before finishing. If git is blocked in your session, say so once and keep working; commit on a new branch only if git works.
- Final answer: short summary (what was added, test count, known limitations). No code dumps.

SCOPE (JS/TS only: .js .jsx .mjs .cjs .ts .tsx .mts .cts)
Out of scope: other languages, a real JS parser, type checking, bundler/webpack alias resolution beyond what is listed below.

1. LEXICAL MASKING (foundation, build and test this first)
Implement `js_mask(text) -> str`: returns text of identical length and identical line/column structure in which the contents of comments, string literals, template-literal text and regex literals are replaced by spaces (keep newlines, keep the quote/backtick delimiters). Requirements:
- `//` and `/* */` comments, `'` `"` strings with escapes, template literals including nested `${ ... }` expressions (code inside `${}` stays visible and is masked recursively for its own strings), regex literals vs division disambiguation by previous significant token (after `)` `]` `}` identifier or number => division; after operator, `(`, `,`, `=`, `:`, `[`, `!`, `&`, `|`, `?`, `{`, `;`, `return`, `typeof`, etc. => regex), including character classes `[/]` inside regexes.
- JSX: text between tags may contain apostrophes (`<p>don't</p>`); it must not derail masking of the rest of the file. A cheap heuristic is acceptable (treat `<Tag ...>` text content conservatively) but tests must show a realistic .jsx and .tsx file with apostrophes in text and generics (`Array<string>`, `a < b`) masks correctly.
- Must never raise, never loop forever, must be linear time; on an unterminated construct, mask to end of file.
- Keep the ORIGINAL text for secret scanning and for snippets; use the masked text for all structural and sink rules.
Existing JS sink regexes (RS-SEC-003/004 for JS) must run on masked code so that `// eval(x)` and `"eval(x)"` are no longer reported, while `eval(x)` in code still is.

2. FUNCTION DISCOVERY (approximate, on masked text)
Find function bodies by brace matching: `function name(...) {`, `async function`, generator `function*`, arrow functions with block bodies (`const f = (a) => {`, `async x => {`, `export default () => {`), class methods and object-literal methods (`name(args) {`, `async name(args) {`, `get/set name() {`, `static`, `#private`), constructors. Expression-bodied arrows (`x => x + 1`) count as part of their enclosing function. Control-flow keywords (`if (...) {`, `for`, `while`, `switch`, `catch`, `with`) must never be mistaken for methods. Each function gets (name, start line, end line, body span). Nested functions are scored separately and their bodies are excluded from the parent's score (as for Python).

3. NEW/EXTENDED RULES (all JS/TS findings carry confidence `medium` or `low`; the messages must say "approximate" where relevant)
- RS-QUAL-001 (cyclomatic complexity): extend to JS/TS. McCabe = 1 + `if` + `else if` (counted once) + `for` (incl. `for...in/of`, `for await`) + `while` + `do...while` + each `case` (not `default`) + `catch` + ternary `?` (not `?.`, not `??`, not in types) + each `&&` `||` `??` + optional-chaining NOT counted. Severity rules identical to Python (medium; high above 2x threshold), threshold from config. Message states it is approximate.
- RS-QUAL-002 (nesting depth): extend to JS/TS using block nesting of `if/for/while/do/switch/try` (`catch`/`finally`/`else` do not add depth).
- RS-QUAL-003/004 equivalents for JS: empty `catch {}` / `catch (e) {}` (body empty or only a comment) => RS-QUAL-004 [medium].
- RS-ARCH-001/002 (import graph): build the module graph from `import ... from '...'`, `import '...'`, `export ... from '...'`, `require('...')`, and `import('...')` with a literal. Resolve only relative specifiers (`./`, `../`) and, if present, `tsconfig.json`/`jsconfig.json` `compilerOptions.baseUrl` and `paths` (strip comments and trailing commas before parsing; a malformed file is a warning, not a crash). Resolution order: exact file, then extensions .ts .tsx .js .jsx .mjs .cjs .mts .cts .json, then `/index.*`; TS-style `./x.js` importing `x.ts` must resolve. Bare package specifiers are third-party: dropped. `import type`/`export type` and imports inside functions or dynamic `import()` are "soft" (same semantics as Python: a cycle only through soft edges is [low]). Reuse the existing ITERATIVE Tarjan implementation and the same reporting format (module names = POSIX relative paths without extension). Layer/forbidden-import rules map layer names to the first path segment under each `package_roots` entry.
- RS-SEC-006 (new, "Insecure configuration", severity per item, confidence medium): on masked code with literal inspection of the original text where needed:
  * TLS verification disabled: `rejectUnauthorized: false`, `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'` (string literal in original text) [high].
  * Weak hashing for credentials: `createHash('md5'|'sha1')` [medium] (note "fine for non-security checksums").
  * Predictable randomness for secrets: `Math.random()` within ~3 lines of identifiers matching token|secret|password|nonce|session|csrf|otp [medium].
  * `jwt.verify`/`jsonwebtoken` with `algorithms` containing `'none'`, or `jwt.decode` result used without verify nearby is NOT required; only the `none` case [high].
  * CORS wildcard with credentials: `origin: '*'` together with `credentials: true` in the same object literal [medium].
  * React `dangerouslySetInnerHTML` with a non-constant `__html` [high]; constant string [low].
  * `child_process.exec*` / `spawn(..., {shell: true})` with a template literal or concatenation or identifier argument => critical, constant string => medium (keep existing semantics, now also covering `execa`/`shelljs` style `exec(` only when imported from those modules).
  * `fs` calls (`readFile*`, `createReadStream`, `writeFile*`, `unlink`) whose path argument is a template literal/concatenation containing `req.`, `request.`, `params`, `query`, `body`, `argv` (path traversal, low confidence) [medium].
  * `new RegExp(` built from `req.`/`params`/`query`/`body` identifiers (ReDoS/injection) [low].
  Add the rule to the catalog (`--list-rules` must describe it and say "JS/TS: pattern-based, approximate").
- Keep suppression comments (`// reposentry: ignore RS-XXX-NNN`), baselines, severity overrides, config validation, and `--rules/--ignore-rules` working for every new rule.

4. FALSE-POSITIVE CONTROLS
- Skip minified/bundled files (existing detection), `*.d.ts`, `*.min.js`, `*.map`, and directories `node_modules`, `dist`, `build`, `coverage`, `.next`, `.nuxt`, `out` unless the user config says otherwise (check the existing default `ignore_dirs` and extend it).
- Test files (`*.test.*`, `*.spec.*`, `__tests__/`) get RS-QUAL-001/002 skipped and RS-SEC-006 downgraded one level.
- Never report the same `(rule, file, line, col)` twice.

5. PERFORMANCE AND ROBUSTNESS
- One read per file; masking and function discovery are single-pass or near-linear. A 5 MB synthetic file must be handled within the existing `--max-file-kb` cap behaviour (files over the cap are skipped with the existing mechanism). A pathological input (200k nested parentheses, 1 MB single line, unterminated template literal, binary-looking .js) must not hang or raise; add tests with a generous time budget (e.g. < 5 s).
- A file that cannot be tokenized sanely yields RS-SYS-001 [low] and the scan continues.
- Output must remain deterministic across runs and across `\n` / `\r\n` line endings (add a test: same findings, same line numbers).

ACCEPTANCE TESTS (add to the embedded unittest suite; use temp dirs; no network)
1. Masking: comment `// eval(x)`, string `"exec(cmd)"`, template text `` `eval(x)` `` are masked; code inside `${eval(y)}` is NOT masked and is flagged; length and newline positions are preserved exactly (`len(mask(t)) == len(t)` and same `\n` indices) for 6 tricky inputs (regex with `/` in a class, division after `)`, nested templates 3 deep, JSX with apostrophes, unterminated string, `a < b > c` generics).
2. Function discovery on one fixture: counts and names of exactly 9 discovered functions across the forms listed in section 2, and `if (x) {` / `while (x) {` / `catch (e) {` are never named functions.
3. Complexity, exact numbers on 4 hand-computed samples (write the arithmetic in comments): plain function with 3 `if` => 4; function with `if/else if/else`, `for`, `&&`, `||`, `??`, ternary, `switch` with 3 cases + default, `catch` => the sum you derive; optional chaining `a?.b ?? c` counts only `??`; a nested arrow's branches are not added to its parent.
4. Nesting: 5-deep nested `if` flagged at threshold 4; `else if` chain of 6 is NOT deep.
5. Empty catch flagged; catch with a comment only flagged; catch that logs is not.
6. Import graph: a.ts -> b.ts -> c.ts -> a.ts reported once as one SCC with cycle path; `./x.js` resolving to `x.ts`; `index.ts` directory import; `tsconfig` `paths` alias `@/*` resolution; a cycle only via `import type` is [low]; self-import reported; a 5,000-module chain does not hit the recursion limit; bare package imports ignored; layer rule works with `layers` config.
7. Sinks: `exec(userInput)` critical, `exec("ls")` medium, `eval(x)` in code flagged, `eval(x)` inside a comment/string not flagged, `innerHTML = x` flagged, `innerHTML = "<b>"` lower; `dangerouslySetInnerHTML={{__html: html}}` high, with a constant lower.
8. RS-SEC-006 positives and negatives for each bullet (e.g. `rejectUnauthorized: true` is not flagged; `createHash('sha256')` not flagged; `Math.random()` far from a token identifier not flagged).
9. Secrets: existing behaviour unchanged; a fake AWS key inside a JS comment IS still detected (secrets use unmasked text) and stays redacted in terminal/json/markdown output.
10. Config/CLI: `--rules RS-SEC-006`, `--ignore-rules`, severity override, inline suppression `// reposentry: ignore RS-SEC-006`, baseline, JSON output identical across two runs and across CRLF conversion.
11. Robustness: the pathological inputs of section 5 finish quickly without exceptions; `.d.ts` and `*.min.js` are skipped; a test file skips complexity.
12. Dogfood sanity: create a small realistic project in a temp dir (an Express app with 6 files incl. one import cycle, one `exec(req.query.cmd)`, one empty catch, one 25-branch function) and assert the exact set of (rule, file) pairs reported, nothing more.

DO NOT
- Do not add dependencies, shell out to node/npm/tsc, or make network calls.
- Do not change existing rule IDs, default severities for Python, output formats, or exit codes.
- Do not weaken a test or tolerance to make it pass; if you believe an expected value is wrong, derive it yourself and explain why in your final answer.
