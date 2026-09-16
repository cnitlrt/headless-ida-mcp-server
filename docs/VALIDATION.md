# Validation record — 2026-09-16

## Baselines

- Development branch: `dev`, created from local/upstream `27fbcc2ffd98ef4098c7895e0b48a81a39af0798`.
- Upstream ida-pro-mcp reviewed: `3c97954d74d70063ba076411570a33118a9d691f`.
- Service Python: 3.12.9, MCP SDK 1.26.0, RPyC 6.0.1.
- Actual IDA runtime: Linux, IDA Pro 9.0.0.240925, embedded Python 3.10.
- Test input: `tests/fixtures/hello.c`, compiled with `cc -g -O0 -fno-inline`.
- Test dependencies installed separately in `/tmp/headless-ida-dev-venv`;
  the user's original `.venv` and `.env` were not modified.

## Results

| Check | Result |
| --- | --- |
| Default suite, no IDA environment variables | 88 passed; 2 real-IDA tests explicitly skipped |
| Full suite with sample and IDA opt-in | 90 passed |
| Ruff lint and formatting | Passed |
| `git diff --check` | Passed |
| `uv lock --check` | Passed |
| Wheel and sdist build | Passed |
| Clean non-editable wheel install with locked runtime dependencies | Passed |
| Installed wheel launching real IDA and decompiling the sample | Passed |
| Wheel license and bridge inclusion; sdist docs/sample inclusion | Passed |
| Package exclusion of `.env`, GDB package and experiment artifacts | Passed |
| MCP output schemas | All 20 default tools / all 26 opt-in tools |

The actual sample metadata reported x86-64 (`metapc`), 17 functions and
`decompiler_available=true`; `main` produced 8 pseudocode lines. This explicitly confirms
that the decompiler branch executed, rather than only testing a graceful missing-license path.
After closing, the IDA process quota returned to zero.

## What is covered

- Stdio subprocess handshake and real loopback SSE/Streamable HTTP MCP clients.
- Separate MCP clients cannot list/select/close each other's databases; closing one transport
  does not close another's IDA process. A later client can reconnect to a fresh manager.
- Shared process cap across clients; startup errors and cancellation return quota.
- Startup timeout, active cancellation, queued cancellation/timeout, idle expiry, and shutdown.
- Real child-process termination, including an exited parent whose child still holds stdout.
- Event-loop responsiveness while obtaining remote RPC attributes and serial execution per IDA.
- Number-conversion sign/length boundaries, malformed input, schema validation and defaults.
- Function contract, filtered pagination, optional prototype cost, import pagination,
  string truncation flags, non-function entry points, references, and disassembly comments.
- Modern/legacy IDAPython decompiler dispatch and missing-decompiler/license diagnostics.
- Annotation cache invalidation, type application flags, conservative comment rollback,
  save failures and rejection of existing/out-of-root destinations.
- Actual IDA: metadata, functions, segments, imports, strings, exports, references,
  pseudocode/disassembly, comments, prototype/rename, database save and reopening.
- Actual IDA results passed through MCP output schema validation.

## Limits of the evidence

- Actual compatibility has not been tested on other IDA versions, Windows/macOS, or idalib.
- Not every mutation branch has been executed against real IDA; e.g. local-variable rename
  and every possible interior pseudocode-comment placement need a wider fixture matrix.
- The ordinary Python coverage report excludes execution inside the independent IDA process;
  it must not be interpreted as measuring the live bridge's executed lines.
- No throughput benchmark against the 0.1 implementation was performed. Batching removes
  per-item remote-proxy access by construction, but no numeric speedup is claimed.
- CI configuration was added for Python 3.12/3.13; remote GitHub CI has not been run.
- Scope is the IDA service, not modernization of preserved local GDB/pwntools experiments or
  full feature parity with upstream ida-pro-mcp.

## Reproduce

```bash
uv sync --locked --group dev
uv run ruff check src/headless_ida_mcp_server tests
uv run ruff format --check src/headless_ida_mcp_server tests
uv run pytest -q
cc -g -O0 -fno-inline tests/fixtures/hello.c -o /tmp/ida-mcp-hello
IDA_TEST_EXECUTABLE=/path/to/ida/idat IDA_TEST_BINARY=/tmp/ida-mcp-hello uv run pytest -q
uv build
```

All pre-existing unrelated untracked files and deleted test artifacts remain in their original
state. Validation ran before publication of these changes; no project `AGENTS.md` was overwritten.
