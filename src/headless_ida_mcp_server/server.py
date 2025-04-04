# -*- coding: utf-8 -*-
from mcp.server import FastMCP
from mcp.server.fastmcp.prompts import base
from functools import wraps
from typing import Any, Callable, get_type_hints, TypedDict, Optional, Annotated
import struct
from headless_ida_mcp_server.helper import IDA
from headless_ida_mcp_server.logger import logger
from headless_ida_mcp_server import PORT,TRANSPORT

mcp = FastMCP("IDA MCP Server", port=PORT)
ida = None

@mcp.tool()
def set_binary_path(path: Annotated[str, "Path to the binary file"]):
    """Set the path to the binary file"""
    global ida
    ida = IDA(path)
    return "Binary path set"

@mcp.tool()
def get_function(address: Annotated[int, "Address of the function"]):
    """Get a function by address"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.get_function(address)
    
@mcp.tool()
def get_function_by_name(name: Annotated[str, "Name of the function"]):
    """Get a function by name"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.get_function_by_name(name)

@mcp.tool()
def get_function_by_address(address: Annotated[int, "Address of the function"]):
    """Get a function by address"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.get_function_by_address(address)

@mcp.tool()
def get_current_address():
    """Get the current address"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.get_current_address()

@mcp.tool()
def get_current_function():
    """Get the current function"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.get_current_function()

@mcp.tool()
def convert_number(text: Annotated[str, "Textual representation of the number to convert"],size: Annotated[Optional[int], "Size of the variable in bytes"]):
    """Convert a number to a different representation"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.convert_number(text, size)

@mcp.tool()
def list_functions():
    """List all functions"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.list_functions()

@mcp.tool()
def decompile_checked(address: Annotated[int, "Address of the function to decompile"]):
    """Decompile a function at the given address"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.decompile_checked(address)

@mcp.tool()
def decompile_function(address: Annotated[int, "Address of the function to decompile"]):
    """Decompile a function at the given address"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.decompile_function(address)

@mcp.tool()
def disassemble_function(address: Annotated[int, "Address of the function to disassemble"]):
    """Disassemble a function at the given address"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.disassemble_function(address)

@mcp.tool()
def get_xrefs_to(address: Annotated[int, "Address to get cross references to"]):
    """Get cross references to a given address"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.get_xrefs_to(address)

@mcp.tool()
def get_entry_points():
    """Get all entry points of the binary"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.get_entry_points()

@mcp.tool()
def set_decompiler_comment(address: Annotated[int, "Address in the function to set the comment for"],comment: Annotated[str, "Comment text (not shown in the disassembly)"]):
    """Set a comment for a given address in the function pseudocode"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.set_decompiler_comment(address, comment)

@mcp.tool()
def set_disassembly_comment(address: Annotated[int, "Address in the function to set the comment for"],comment: Annotated[str, "Comment text (not shown in the pseudocode)"]):
    """Set a comment for a given address in the function disassembly"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.set_disassembly_comment(address, comment)

@mcp.tool()
def refresh_decompiler_widget():
    """Refresh the decompiler widget"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.refresh_decompiler_widget()

@mcp.tool()
def refresh_decompiler_ctext(function_address: Annotated[int, "Address of the function to refresh the decompiler ctext for"]):
    """Refresh the decompiler ctext for a given function"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.refresh_decompiler_ctext(function_address)

@mcp.tool()
def rename_local_variable(function_address: Annotated[int, "Address of the function containing the variable"],old_name: Annotated[str, "Current name of the variable"],new_name: Annotated[str, "New name for the variable"]):
    """Rename a local variable in a function"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.rename_local_variable(function_address, old_name, new_name)

@mcp.tool()
def rename_function(function_address: Annotated[int, "Address of the function to rename"],new_name: Annotated[str, "New name for the function"]):
    """Rename a function"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.rename_function(function_address, new_name)

@mcp.tool()
def set_function_prototype(function_address: Annotated[int, "Address of the function"],prototype: Annotated[str, "New function prototype"]):
    """Set a function's prototype"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.set_function_prototype(function_address, prototype)

@mcp.tool()
def save_idb_file(save_path: Annotated[str, "Path to save the IDB file"]):
    """Save the IDB file"""
    if ida is None:
        raise ValueError("Binary path not set")
    return ida.save_idb_file(save_path)

@mcp.prompt()
def exploit_prompt():
    """Exploit prompt"""
    
    messages = [
        base.UserMessage("You are a helpful assistant that can help me with my exploit."),
        base.UserMessage("""
        你需要遵循以下方式来完成漏洞利用:
        1. 逆向分析二进制文件,获取漏洞位置,分析漏洞类型
            - 获取漏洞位置: 通过IDA Pro的分析功能,获取漏洞位置
            - 需要先进行二进制文件的信息收集,例如使用checksec工具查看二进制文件的保护机制
                - 如果发现保护没有开nx保护,你可以使用ret2shellcode的方法来获取shell.
        2. 根据漏洞类型,选择合适的漏洞利用方式
            - 如果是栈溢出漏洞,需要分析栈溢出的pattern,然后查看二进制文件中有没有后门函数,如果有后门函数则将返回地址修改为后门函数的地址
            - 如果没有后门函数,需要使用ret2libc的方法来做,你不能默认二进制文件中存在你想要的gadget,你需要使用ROPgadget来获取gadget,然后结合gadget来完成pop链的构造.
        """),
    ]
    return messages

def main():
    mcp.run(transport = TRANSPORT)

if __name__ == "__main__":
    main()