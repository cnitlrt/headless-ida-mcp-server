"""
Helper module for IDA Python integration.
Provides configuration and IDA interface initialization.
"""
import os
import logging

from headless_ida import HeadlessIda
import logging
from dotenv import load_dotenv,find_dotenv,dotenv_values

#### ENVIRONMENT VARIABLES ####
load_dotenv(find_dotenv(),override=True)
PORT = os.environ.get("PORT", 8888)
HOST = os.environ.get("HOST", "0.0.0.0")
TRANSPORT = os.environ.get("TRANSPORT", "sse")
BINARY_PATH = os.environ.get("BINARY_PATH", "")
if BINARY_PATH == "":
    raise ValueError("BINARY_PATH is not set")
IDA_PATH = os.environ.get("IDA_PATH", "")
if IDA_PATH == "":
    raise ValueError("IDA_PATH is not set")

#### LOGGING ####
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('headless_ida_mcp_server')
logger.setLevel(logging.DEBUG)

#### headless_ida IDA PYTHON ####
headlessida = HeadlessIda(IDA_PATH, BINARY_PATH)
import idaapi
import idautils
import ida_entry
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_typeinf
import ida_xref
import idc