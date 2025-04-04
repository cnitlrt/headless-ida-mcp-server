# Acknowledgments

This project builds upon the work of:
- Tools code adapted from [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) by mrexodia
- Utilizes the [headless-ida](https://github.com/DennyDai/headless-ida) library by DennyDai

# Headless IDA MCP Server

If you want to run the server directly as a cli app, rather than an IDA plugin interactively,you can chose it.

## Project Description

This project uses IDA Pro's headless mode to analyze binary files and provides a suite of tools via MCP to manage and manipulate functions, variables, and more.

## Prerequisites

- Python 3.12 or higher
- IDA Pro with headless support (idat) https://github.com/DennyDai/headless-ida

## Installation

1. Clone the project locally:

   ```bash
   git clone https://github.com/cnitlrt/headless-ida-mcp-server.git 
   cd headless-ida-mcp-server
   ```

2. Install dependencies:

   ```bash
   uv python install 3.12
   uv venv --python 3.12
   uv pip install -e .
   ```

## Configuration

1. Copy the example environment file:
   ```bash
   cp .env_example .env
   ```

2. Configure the following environment variables in `.env`:

   - `IDA_PATH`: Path to IDA Pro's headless executable (idat), e.g., `/home/ubuntu/idapro/idat`
   - `PORT`: Port number for the MCP server, e.g., `8888`
   - `HOST`: Host address for the MCP server, e.g., `127.0.0.1`
   - `TRANSPORT`: MCP transport mode (`sse` or `stdio`)

## Usage

1. Start the server:
   ```bash
   uv run headless_ida_mcp_server
   ```

2. Connect to the server using an MCP client:

   Debug it: 
   ```bash
   npx -y @modelcontextprotocol/inspector
   ```
   or
   ```json
   {
   "mcpServers": {
      "ida": {
         "command": "/path/to/uv",
         "args": ["--directory","path/to/headless-ida-mcp-server","run","headless_ida_mcp_server"]
      }
   }
   }
   ```
![](./images/pic.png)

![](./images/pic2.png)