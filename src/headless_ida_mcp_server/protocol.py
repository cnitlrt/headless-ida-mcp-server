"""Explicit internal RPC allowlist; never exposes arbitrary Python execution."""

READ_OPERATIONS = frozenset(
    {
        "get_metadata",
        "get_function",
        "get_function_by_name",
        "list_functions",
        "list_segments",
        "list_strings",
        "list_imports",
        "get_entry_points",
        "get_xrefs_to",
        "get_xrefs_from",
        "decompile_function",
        "disassemble_function",
        "refresh_decompiler_ctext",
    }
)
WRITE_OPERATIONS = frozenset(
    {
        "rename_function",
        "rename_local_variable",
        "set_disassembly_comment",
        "set_decompiler_comment",
        "set_function_prototype",
        "save_idb_file",
    }
)
