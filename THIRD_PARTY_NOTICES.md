# Third-party notices

Selected compatibility and analysis logic in `compat.py` and `helper.py` is adapted from
[ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp), copyright (c) 2025 Duncan Ogilvie
and contributors, under the MIT License. Its complete notice is retained in
[`licenses/ida-pro-mcp-MIT.txt`](licenses/ida-pro-mcp-MIT.txt).

Exact source snapshot, paths, modifications and exclusions: [`docs/UPSTREAM.md`](docs/UPSTREAM.md).
This notice applies to the upstream-derived portions; it does not assign a new license to
unrelated user code or redistribute IDA Pro/Hex-Rays itself.

The original backend used [headless-ida](https://github.com/DennyDai/headless-ida).
The current managed bridge does not vendor that library's implementation.
