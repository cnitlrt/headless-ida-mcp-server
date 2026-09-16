# Headless IDA MCP Server

A local MCP service for analyzing binaries with IDA Pro **without opening the GUI**.
Version 0.2 replaces the global active database with isolated, explicitly managed sessions.

## Requirements

- Python **3.12+** for the MCP service, `uv`, and a licensed IDA Pro headless executable.
- IDA's embedded Python **3.10+**. Real integration validation currently covers Linux,
  IDA Pro **9.0.0.240925** with Python 3.10. Compatibility fallbacks for other releases
  are unit-tested, **not a claim of full runtime coverage across IDA versions/platforms**.
- Hex-Rays is optional for metadata/disassembly; required for pseudocode and local-variable edits.
- Use `idat` on IDA 9, or the 64-bit-database `idat64` executable on older installations.

## Install and run

```bash
uv sync --locked --group dev
cp .env_example .env   # only if you do not already have an .env
# Set IDA_PATH to your licensed IDA executable.
uv run headless_ida_mcp_server
```

To preserve an existing experimental virtual environment, use a separate environment:

```bash
UV_PROJECT_ENVIRONMENT=.venv-dev uv sync --locked --group dev
UV_PROJECT_ENVIRONMENT=.venv-dev uv run headless_ida_mcp_server
```

Stdio is the default. All diagnostics go to stderr, never the JSON-RPC stdout stream.
For local HTTP clients:

```bash
uv run headless_ida_mcp_server --transport streamable-http --host 127.0.0.1 --port 8888
# Endpoint: http://127.0.0.1:8888/mcp
# Legacy SSE: --transport sse, endpoint /sse
```

Example stdio client configuration:

```json
{
  "mcpServers": {
    "ida": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/headless-ida-mcp-server", "run",
               "headless_ida_mcp_server", "--transport", "stdio", "--host", "127.0.0.1"]
    }
  }
}
```

## Configuration

Precedence: **CLI overrides > environment variables > the explicitly selected .env > defaults**.
Use `--env-file /path/to/config` to change the file. Imports do not read configuration,
search parent directories, or require IDA to be installed.

| Setting | Default | Meaning |
| --- | --- | --- |
| `IDA_PATH` | unset | Full path to `idat`/`idat64`; validated when opening a binary |
| `HOST` | `127.0.0.1` | Loopback only; `localhost` and `::1` also accepted |
| `PORT` | `8888` | HTTP port |
| `TRANSPORT` | `stdio` | `stdio`, `streamable-http`, or `sse` |
| `IDA_READ_ONLY` | `true` | Set `false` to expose annotation/rename/save tools |
| `IDA_MAX_SESSIONS` | `4` | Server-wide IDA process quota, including concurrent MCP clients |
| `IDA_STARTUP_TIMEOUT` | `120` | Seconds allowed for copying, startup and auto-analysis |
| `IDA_REQUEST_TIMEOUT` | `60` | Seconds allowed for queue wait, then separately for execution |
| `IDA_IDLE_TIMEOUT` | `900` | Close idle databases after this many seconds; `0` disables expiry |
| `IDA_MAX_FILE_BYTES` | `536870912` | Maximum source file size |
| `IDA_ALLOWED_ROOTS` | unset | Optional input/export directory allowlist, separated by `os.pathsep` |

Existing configurations using `HOST=0.0.0.0` must change to loopback, or use `--host 127.0.0.1`.
No public, unauthenticated HTTP listener is provided.

## Tools

### Session lifecycle

1. `open_binary(path)` (legacy alias `set_binary_path`) returns `{session_id, path, read_only}`.
2. Pass this `session_id` to analysis tools. It may be omitted only when **exactly one**
   database exists in the current MCP connection.
3. `list_sessions` lists only this client's databases. `health` works without an IDA process.
4. `close_binary(session_id)` discards unsaved changes and reclaims the process/temp files.

Each database runs in its own process and private temporary directory. The input is copied;
its original database/sidecars are not modified. Another client cannot select or close your
session. A transport session's shutdown closes its databases; normal Streamable HTTP clients
should send the protocol's session DELETE. Idle expiry also reclaims abandoned databases.
Session IDs are **not** authentication credentials; HTTP is for trusted local clients.

### Read-only analysis

- `get_metadata`: IDA version, architecture, image bounds, function count, decompiler capability.
- `get_function`, `get_function_by_address`, `get_function_by_name`.
- `list_functions`: optional case-insensitive substring filter and `include_prototype`.
- `list_segments`, `list_imports`, `list_strings`, `get_entry_points`.
- `get_xrefs_to`, `get_xrefs_from`.
- `decompile_function`, `disassemble_function`: paginated lines with addresses.
- `refresh_decompiler_ctext`: invalidate the decompiler cache; no GUI widget required.
- `convert_number`: no IDA needed; explicit byte order, signedness, and optional byte size.

All tools publish output schemas. Paginated operations return:

```json
{"data": [], "offset": 0, "next_offset": null}
```

`limit` defaults to 100, is restricted to 1..1000, and **0 does not mean unlimited**.
Use `next_offset` until null. Functions use `address`, not `start_address`.
Prototype lookup is opt-in for function lists and only runs for returned rows.
String text is capped at 4096 characters; disassembly/pseudocode lines at 16384 characters,
with `truncated: true` when a value is shortened. Responses exceeding 4 MiB are rejected
with a request to use a smaller page. Pagination does not promise an immutable snapshot
across annotation changes.

### Opt-in database annotations

With `IDA_READ_ONLY=false`: `rename_function`, `rename_local_variable`,
`set_function_prototype`, `set_disassembly_comment`, `set_decompiler_comment`, `save_idb_file`.
These tools carry destructive-operation annotations. Saves require a **new `.i64` file**
inside any configured allowed roots; existing files are never overwritten. Save explicitly
before closing, disconnecting, or leaving a session idle. Ambiguous pseudocode comments fail
without deleting unrelated orphan comments.

## Architecture and boundaries

```text
MCP connection -> connection-owned session manager -> one IDA process per database
                                               -> loopback/token-protected JSON bridge
                                               -> fixed analysis operations on IDA's main thread
```

Each request returns plain JSON in one RPC rather than walking remote IDAPython proxy
objects. Calls to the same database are serialized; separate databases can run concurrently.
Timeout/cancellation during an active operation invalidates and closes that database session.
Cancelling a queued request does not kill another request's work. Health/listing remain responsive.
File copies already in progress are allowed to finish before cleanup to avoid deleting an active
copy's source/destination; they are not hard-interruptible by the RPC deadline.

This is **process isolation, not an OS sandbox for hostile binaries or IDA plugins**. Run under
a least-privileged account or a separate VM/container when handling untrusted input. Directory
allowlists are application policy, not a defense against a malicious local user changing symlinks.
No arbitrary Python execution, debugger control, shell tools, or autonomous exploitation prompt
is exposed by this server.

## Development and tests

```bash
uv run ruff check src/headless_ida_mcp_server tests
uv run ruff format --check src/headless_ida_mcp_server tests
uv run pytest --cov=headless_ida_mcp_server --cov-report=term-missing
uv build
```

The default suite needs no IDA or external model/API keys. It covers schemas, stdio/SSE/HTTP,
client isolation, configuration, pagination, number boundaries, and lifecycle failure paths.
Opt-in real IDA tests use a small benign sample (C compiler required):

```bash
cc -g -O0 -fno-inline tests/fixtures/hello.c -o /tmp/ida-mcp-hello
IDA_TEST_EXECUTABLE=/path/to/ida/idat IDA_TEST_BINARY=/tmp/ida-mcp-hello \
  uv run pytest tests/test_integration.py -v
```

The original `test/test_ida_agent.py` is retained as a **legacy demonstration**, not the
regression suite. It uses older LangChain interfaces and is not validated by the new tests.
Local untracked GDB/pwntools experiments are preserved, but not imported or packaged into
this IDA distribution. Optional dependency groups do not imply those experiments are supported.

## Upstream and migration

- Selected analysis/compatibility behavior adapted from
  [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).
- Original project used [DennyDai/headless-ida](https://github.com/DennyDai/headless-ida).
  Version 0.2 replaces its import-hook/RPyC-proxy backend with an explicit managed bridge.
- [Upstream snapshot and port scope](docs/UPSTREAM.md)
- [0.1 to 0.2 migration guide](docs/MIGRATION.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)
- [Validation record](docs/VALIDATION.md)

This is a selective headless adaptation, **not** a full mirror or drop-in replacement for
current upstream `ida-pro-mcp`/`idalib-mcp`.
