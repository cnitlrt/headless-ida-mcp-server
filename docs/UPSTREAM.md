# Upstream synchronization record

Reviewed on 2026-09-16.

- Repository: https://github.com/mrexodia/ida-pro-mcp
- Retrieved HEAD: `3c97954d74d70063ba076411570a33118a9d691f`
- Commit date: 2026-08-28
- License: MIT, copyright (c) 2025 Duncan Ogilvie.
- Full license retained in `licenses/ida-pro-mcp-MIT.txt` and shipped in the wheel.

This snapshot was inspected from a shallow clone, not inferred from old examples or docs.
Upstream now has an idalib server/supervisor/session manager and a modular API. Importing
its entire plugin into the old headless-ida RPyC client would mix incompatible execution
models and expose many unrelated capabilities. We instead port selected analysis behavior
and keep a narrow, explicit bridge.

## Source-to-local mapping

| Upstream file | Local adaptation |
| --- | --- |
| `src/ida_pro_mcp/ida_mcp/compat.py` | `compat.py`: capability-based function-name/prototype fallbacks, including early IDA 9 builds |
| `ida_mcp/utils.py`: `get_prototype`, `decompile_checked`, `decompile_function_safe` | `compat.py` and `helper.py`: checked decompilation, license-aware errors, best-effort line addresses, real head/item/tail objects |
| `ida_mcp/utils.py`: pagination | `helper.page`: bounded generator-based lookahead rather than whole-list slicing; rejects unlimited count |
| `ida_mcp/api_core.py`: function/import/number queries | Filtered/paginated queries and independent number conversion with corrected signed-size boundaries |
| `ida_mcp/api_analysis.py`: analysis surface | Typed/paginated pseudocode, disassembly and references; metadata/segments/strings/imports |
| `ida_mcp/api_modify.py`: annotation operations | Local rename/comment/type handling, cache invalidation, checked saves and conservative orphan-comment preservation |
| `idalib_session_manager.py`, `idalib_supervisor.py` (architecture reviewed, not copied) | New `sessions.py`/`backend.py`: connection-owned databases, process quotas, deadlines, idle expiry and cleanup |

The port deliberately fixes remaining problems rather than treating upstream as an infallible
reference: automatic integer sizes at signed boundaries; raw `decompile_func` address arguments;
parse flags used as apply flags; deletion of unrelated orphan comments. The `decompile_func`
fallback receives a `func_t`; address-based APIs are preferred when available.

## Not imported

Arbitrary Python execution, debugger/runtime control, patching/exploit workflows, GUI state,
plugin installation machinery, full upstream batch-query syntax, full type-editing APIs,
composite whole-binary analysis, and the idalib execution backend. Their absence is intentional,
not evidence that the upstream files were synchronized wholesale. The 0.2 protocol is documented
locally and does not promise upstream wire compatibility.

## Future update procedure

1. Fetch and record an exact upstream commit and license.
2. Compare the specific modules above, including upstream tests and compatibility changes.
3. Adapt only JSON-returning operations to the fixed bridge allowlist; do not import GUI/plugin
   decorators or arbitrary execution endpoints.
4. Add mock regression cases and run the benign real-IDA suite on each supported installation.
5. Update this record and the tested-version matrix. Do not claim an untested version is supported.
