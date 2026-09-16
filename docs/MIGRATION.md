# Migration from 0.1 to 0.2

This is a protocol-breaking modernization; do not silently swap it into a client expecting the
old list/string shapes. Version was bumped to 0.2.0 accordingly.

| Previous behavior | New behavior |
| --- | --- |
| Global `ida`, replaced by `set_binary_path` | `open_binary` / `set_binary_path` returns a new `session_id`; pass it with subsequent calls |
| One global binary shared by clients | Database IDs are scoped to the MCP transport session |
| Unlimited whole-function lists and text | `{data, offset, next_offset}` pages; line records contain `line`, `address`, `text`, `truncated` |
| Function TypedDict declared `start_address`, actual output used `address` | Schema and returned value consistently use `address` |
| Every list row always queried its prototype | `include_prototype=false` by default on `list_functions` |
| `Optional[size]` still required | `size=null`/omitted works; optional `signed` and `byteorder` are explicit |
| Positive integers implicitly signed | Automatic conversion is unsigned for nonnegative values, signed for negatives |
| GUI cursor/widget tools | Removed: `get_current_address`, `get_current_function`, `refresh_decompiler_widget` |
| `decompile_checked` returned an opaque object through MCP | Removed from MCP; use typed `decompile_function` |
| GUI refresh after edits | Invalidate pseudocode cache using `mark_cfunc_dirty` |
| Unchecked saves to arbitrary/existing paths | Export to a new `.i64` path; check success, enforce roots, never overwrite |
| Mutation tools always visible | `IDA_READ_ONLY=false` explicitly enables six annotation/save tools |
| SSE default; HOST ignored | Stdio default; HOST honored and restricted to loopback |
| `.env` overrides exported variables at import time | CLI > process environment > explicit .env > defaults, loaded only at startup |
| Legacy headless-ida changes global imports and owns hidden processes | Managed idat bridge, no import hook; explicit termination and cleanup |
| Agent exploit prompt | Conservative `analysis_prompt` for documenting observed behavior |
| Mixed runtime/test/experimental dependencies | Minimal core, development group, optional experiment dependencies; locked build |

The old alias `get_function_by_address` is retained. No `BINARY_PATH`/`IDA_PATH` import-time
constants are exported anymore: use `Settings.load()` or supply `Settings(...)` explicitly.
The old GDB console entry point is not shipped by the core IDA package; its untracked local
source remains untouched. The old LLM-driven demo is not part of default test discovery.

## Important lifecycle behavior

- Opening another binary does not close any existing one. Explicitly close unused databases.
- A timeout/cancellation during an active RPC closes that binary's session; reopen it to retry.
- Unsaved database edits are discarded on close, transport-session termination, or idle expiry.
- `IDA_IDLE_TIMEOUT=0` disables idle expiry; otherwise save work before the configured deadline.
- Abruptly disconnected Streamable HTTP clients may leave a resumable protocol session; the
  IDA idle reaper still releases its process quota. Use protocol DELETE for prompt cleanup.

## Keep the old environment while trying dev

```bash
UV_PROJECT_ENVIRONMENT=.venv-dev uv sync --locked --group dev
UV_PROJECT_ENVIRONMENT=.venv-dev uv run headless_ida_mcp_server --host 127.0.0.1 --transport stdio
```

Do not overwrite an existing `.env` containing your own settings. The `--host` override also
works if the old file contains `HOST=0.0.0.0`. This project does not modify your IDA installation,
plugins, license settings, or original input database.
