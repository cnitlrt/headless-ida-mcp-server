"""
headless-ida-mcp-server
"""
from dotenv import load_dotenv,find_dotenv,dotenv_values
import os
from .logger import*

__all__ = ['PORT', 'HOST', 'TRANSPORT', 'BINARY_PATH', 'IDA_PATH']

load_dotenv(find_dotenv(),override=True)
PORT = os.environ.get("PORT", 8888)
HOST = os.environ.get("HOST", "0.0.0.0")
TRANSPORT = os.environ.get("TRANSPORT", "sse")
IDA_PATH = os.environ.get("IDA_PATH", "")
if IDA_PATH == "":
    raise ValueError("IDA_PATH is not set")

