"""Trusted IDAPython entry point, run by idat -S, never imported by MCP.

One-shot loopback RPC. Operations run on the IDA main thread. The bridge
accepts JSON and an allowlisted operation, not Python source/module names.
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

# IDA may replace sys.path when executing -S scripts.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main():
    import ida_auto
    import ida_loader
    import ida_pro
    import idc
    import rpyc
    from rpyc.utils.server import OneShotServer

    from headless_ida_mcp_server.helper import IDA
    from headless_ida_mcp_server.protocol import READ_OPERATIONS, WRITE_OPERATIONS

    config = json.loads(Path(idc.ARGV[1]).read_text())
    ida_auto.auto_wait()
    ida_loader.set_database_flag(ida_loader.DBFL_KILL)
    api = IDA()

    class Service(rpyc.Service):
        def exposed_call(self, token, operation, arguments):
            if not isinstance(token, str) or not secrets.compare_digest(token, config["token"]):
                raise ValueError("Invalid bridge token")
            if operation not in READ_OPERATIONS | WRITE_OPERATIONS:
                raise ValueError("Unknown operation")
            if config["read_only"] and operation in WRITE_OPERATIONS:
                raise ValueError("Session is read-only")
            if not isinstance(arguments, str) or len(arguments) > 65536:
                raise ValueError("Invalid request size")
            try:
                args = json.loads(arguments)
                if not isinstance(args, dict):
                    raise ValueError("Arguments must be an object")
                if operation == "save_idb_file":
                    # Only a fixed temporary export destination, never caller-selected paths.
                    args = {"save_path": config["export_path"]}
                result = getattr(api, operation)(**args)
                response = json.dumps({"result": result}, ensure_ascii=True)
                if len(response) > 4 * 1024 * 1024:
                    raise ValueError("Result too large; request a smaller page")
                return response
            except Exception as exc:
                return json.dumps({"error": {"type": type(exc).__name__, "message": str(exc)}})

        def on_disconnect(self, conn):
            ida_pro.qexit(0)

    server = OneShotServer(
        Service,
        hostname="127.0.0.1",
        port=0,
        protocol_config={
            "allow_public_attrs": False,
            "allow_all_attrs": False,
            "allow_pickle": False,
        },
    )
    ready = Path(config["ready_path"])
    temporary = ready.with_suffix(".tmp")
    temporary.write_text(json.dumps({"port": server.port}))
    temporary.replace(ready)
    server.start()


if __name__ == "__main__":
    main()
