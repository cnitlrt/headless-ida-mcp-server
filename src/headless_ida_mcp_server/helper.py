"""
Helper module for IDA Python integration.
Provides configuration and IDA interface initialization.
"""

from headless_ida import HeadlessIda
import logging
from headless_ida_mcp_server import IDA_PATH
import struct
from typing import Optional, TypedDict, Annotated

class Function(TypedDict):
    start_address: int
    end_address: int
    name: str
    prototype: Optional[str]

class IDAError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]

class Xref(TypedDict):
    address: int
    type: str
    function: Optional[Function]

class ConvertedNumber(TypedDict):
    decimal: str
    hexadecimal: str
    bytes: str
    ascii: Optional[str]
    binary: str

class IDA():
    def __init__(self, binary_path: Annotated[str, "Path to the binary file"]):
        self.headlessida = HeadlessIda(IDA_PATH,binary_path)
        self.idaapi = self.headlessida.import_module("idaapi")
        self.idautils = self.headlessida.import_module("idautils")
        self.ida_entry = self.headlessida.import_module("ida_entry")
        self.ida_funcs = self.headlessida.import_module("ida_funcs")
        self.ida_hexrays = self.headlessida.import_module("ida_hexrays")
        self.ida_kernwin = self.headlessida.import_module("ida_kernwin")
        self.ida_lines = self.headlessida.import_module("ida_lines")
        self.ida_nalt = self.headlessida.import_module("ida_nalt")
        self.ida_name = self.headlessida.import_module("ida_name")
        self.ida_typeinf = self.headlessida.import_module("ida_typeinf")
        self.ida_xref = self.headlessida.import_module("ida_xref")
        self.idc = self.headlessida.import_module("idc")
        self.ida_loader = self.headlessida.import_module("ida_loader")
    ######## COPY from https://github.com/mrexodia/ida-pro-mcp ########
    def get_image_size(self):
        try:
            # https://www.hex-rays.com/products/ida/support/sdkdoc/structidainfo.html
            info = self.idaapi.get_inf_structure()
            omin_ea = info.omin_ea
            omax_ea = info.omax_ea
        except AttributeError:
            import ida_ida
            omin_ea = ida_ida.inf_get_omin_ea()
            omax_ea = ida_ida.inf_get_omax_ea()
        # Bad heuristic for image size (bad if the relocations are the last section)
        image_size = omax_ea - omin_ea
        # Try to extract it from the PE header
        header = self.idautils.peutils_t().header()
        if header and header[:4] == b"PE\0\0":
            image_size = struct.unpack("<I", header[0x50:0x54])[0]
        return image_size

    def get_prototype(self,fn) -> Optional[str]:
        try:
            if isinstance(fn, self.ida_funcs.func_t):
                func = fn
            else:
                func = self.idaapi.get_func(fn)
            if func is None:
                return None
            tif = self.ida_typeinf.tinfo_t()
            if self.ida_nalt.get_tinfo(tif, func.start_ea):
                return str(tif)
            return self.idc.get_type(func.start_ea)
        except Exception as e:
            print(f"Error getting function prototype: {e}")
            return None
    
    def get_function(self,address: int, *, raise_error=True) -> Optional[Function]:
        fn = self.idaapi.get_func(address)
        if fn is None:
            if raise_error:
                raise IDAError(f"No function found at address {address}")
            return None

        try:
            name = fn.get_name()
        except AttributeError:
            name = self.ida_funcs.get_func_name(fn.start_ea)
        return {
            "address": fn.start_ea,
            "end_address": fn.end_ea,
            "name": name,
            "prototype": self.get_prototype(fn),
        }

    def get_function_by_name(self,name: Annotated[str, "Name of the function to get"]) -> Function:
        """Get a function by its name"""
        function_address = self.idaapi.get_name_ea(self.idaapi.BADADDR, name)
        if function_address == self.idaapi.BADADDR:
            raise IDAError(f"No function found with name {name}")
        return self.get_function(function_address)

    def get_function_by_address(self,address: Annotated[int, "Address of the function to get"]) -> Function:
        """Get a function by its address"""
        return self.get_function(address)
    
    def get_current_address(self) -> int:
        """Get the address currently selected by the user"""
        return self.idaapi.get_screen_ea()

    def get_current_function(self) -> Optional[Function]:
        """Get the function currently selected by the user"""
        return self.get_function(self.idaapi.get_screen_ea())
    
    def convert_number(self,text: Annotated[str, "Textual representation of the number to convert"],size: Annotated[Optional[int], "Size of the variable in bytes"]) -> ConvertedNumber:
        """Convert a number (decimal, hexadecimal) to different representations"""
        try:
            value = int(text, 0)
        except ValueError:
            raise IDAError(f"Invalid number: {text}")

        # Estimate the size of the number
        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8

        # Convert the number to bytes
        try:
            bytes = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            raise IDAError(f"Number {text} is too big for {size} bytes")

        # Convert the bytes to ASCII
        ascii = ""
        for byte in bytes.rstrip(b"\x00"):
            if byte >= 32 and byte <= 126:
                ascii += chr(byte)
            else:
                ascii = None
                break

        return {
            "decimal": str(value),
            "hexadecimal": hex(value),
            "bytes": bytes.hex(" "),
            "ascii": ascii,
            "binary": bin(value)
        }

    def list_functions(self) -> list[Function]:
        """List all functions in the database"""
        return [self.get_function(address) for address in self.idautils.Functions()]
    
    def decompile_checked(self,address: int):
        if not self.ida_hexrays.init_hexrays_plugin():
            raise IDAError("Hex-Rays decompiler is not available")
        error = self.ida_hexrays.hexrays_failure_t()
        cfunc: self.ida_hexrays.cfunc_t = self.ida_hexrays.decompile_func(address, error, self.ida_hexrays.DECOMP_WARNINGS)
        if not cfunc:
            message = f"Decompilation failed at {address}"
            if error.str:
                message += f": {error.str}"
            if error.errea != self.idaapi.BADADDR:
                message += f" (address: {error.errea})"
            raise IDAError(message)
        return cfunc

    def decompile_function(self,address: Annotated[int, "Address of the function to decompile"]) -> str:
        """Decompile a function at the given address"""
        cfunc = self.decompile_checked(address)
        sv = cfunc.get_pseudocode()
        pseudocode = ""
        for i, sl in enumerate(sv):
            sl: self.ida_kernwin.simpleline_t
            item = self.ida_hexrays.ctree_item_t()
            addr = None if i > 0 else cfunc.entry_ea
            if cfunc.get_line_item(sl.line, 0, False, None, item, None):
                ds = item.dstr().split(": ")
                if len(ds) == 2:
                    try:
                        addr = int(ds[0], 16)
                    except ValueError:
                        pass
            line = self.ida_lines.tag_remove(sl.line)
            if len(pseudocode) > 0:
                pseudocode += "\n"
            if addr is None:
                pseudocode += f"/* line: {i} */ {line}"
            else:
                pseudocode += f"/* line: {i}, address: {addr} */ {line}"

        return pseudocode

    def disassemble_function(self,address: Annotated[int, "Address of the function to disassemble"]) -> str:
        """Get assembly code (address: instruction; comment) for a function"""
        func = self.idaapi.get_func(address)
        if not func:
            raise IDAError(f"No function found at address {address}")

        # TODO: add labels
        disassembly = ""
        for address in self.ida_funcs.func_item_iterator_t(func):
            if len(disassembly) > 0:
                disassembly += "\n"
            disassembly += f"{address}: "
            disassembly += self.idaapi.generate_disasm_line(address, self.idaapi.GENDSM_REMOVE_TAGS)
            comment = self.idaapi.get_cmt(address, False)
            if not comment:
                comment = self.idaapi.get_cmt(address, True)
            if comment:
                disassembly += f"; {comment}"
        return disassembly

    def get_xrefs_to(self,address: Annotated[int, "Address to get cross references to"]) -> list[Xref]:
        """Get all cross references to the given address"""
        xrefs = []
        xref: self.ida_xref.xrefblk_t
        for xref in self.idautils.XrefsTo(address):
            xrefs.append({
                "address": xref.frm,
                "type": "code" if xref.iscode else "data",
                "function": self.get_function(xref.frm, raise_error=False),
            })
        return xrefs

    def get_entry_points(self) -> list[Function]:
        """Get all entry points in the database"""
        result = []
        for i in range(self.ida_entry.get_entry_qty()):
            ordinal = self.ida_entry.get_entry_ordinal(i)
            address = self.ida_entry.get_entry(ordinal)
            func = self.get_function(address, raise_error=False)
            if func is not None:
                result.append(func)
        return result

    def set_decompiler_comment(self,address: Annotated[int, "Address in the function to set the comment for"],comment: Annotated[str, "Comment text (not shown in the disassembly)"]):
        """Set a comment for a given address in the function pseudocode"""

        # Reference: https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/
        # Check if the address corresponds to a line
        cfunc = self.decompile_checked(address)

        # Special case for function entry comments
        if address == cfunc.entry_ea:
            self.idc.set_func_cmt(address, comment, True)
            cfunc.refresh_func_ctext()
            return

        eamap = cfunc.get_eamap()
        if address not in eamap:
            raise IDAError(f"Failed to set comment at {address}")
        nearest_ea = eamap[address][0].ea

        # Remove existing orphan comments
        if cfunc.has_orphan_cmts():
            cfunc.del_orphan_cmts()
            cfunc.save_user_cmts()

        # Set the comment by trying all possible item types
        tl = self.idaapi.treeloc_t()
        tl.ea = nearest_ea
        for itp in range(self.idaapi.ITP_SEMI, self.idaapi.ITP_COLON):
            tl.itp = itp
            cfunc.set_user_cmt(tl, comment)
            cfunc.save_user_cmts()
            cfunc.refresh_func_ctext()
            if not cfunc.has_orphan_cmts():
                return
            cfunc.del_orphan_cmts()
            cfunc.save_user_cmts()
        raise IDAError(f"Failed to set comment at {address}")
    

    def set_disassembly_comment(self,address: Annotated[int, "Address in the function to set the comment for"],comment: Annotated[str, "Comment text (not shown in the pseudocode)"]):
        """Set a comment for a given address in the function disassembly"""
        if not self.idaapi.set_cmt(address, comment, False):
            raise IDAError(f"Failed to set comment at {address}")

    def refresh_decompiler_widget(self):
        widget = self.ida_kernwin.get_current_widget()
        if widget is not None:
            vu = self.ida_hexrays.get_widget_vdui(widget)
            if vu is not None:
                vu.refresh_ctext()

    def refresh_decompiler_ctext(self,function_address: int):
        error = self.ida_hexrays.hexrays_failure_t()
        cfunc: self.ida_hexrays.cfunc_t = self.ida_hexrays.decompile_func(function_address, error, self.ida_hexrays.DECOMP_WARNINGS)
        if cfunc:
            cfunc.refresh_func_ctext()
            
    def rename_local_variable(self,function_address: Annotated[int, "Address of the function containing the variable"],old_name: Annotated[str, "Current name of the variable"],new_name: Annotated[str, "New name for the variable"]):
        """Rename a local variable in a function"""
        func = self.idaapi.get_func(function_address)
        if not func:
            raise IDAError(f"No function found at address {function_address}")
        if not self.ida_hexrays.rename_lvar(func.start_ea, old_name, new_name):
            raise IDAError(f"Failed to rename local variable {old_name} in function {func.start_ea}")
        self.refresh_decompiler_ctext(func.start_ea)

    def rename_function(self,function_address: Annotated[int, "Address of the function to rename"],new_name: Annotated[str, "New name for the function"]):
        """Rename a function"""
        fn = self.idaapi.get_func(function_address)
        if not fn:
            raise IDAError(f"No function found at address {function_address}")
        if not self.idaapi.set_name(fn.start_ea, new_name):
            raise IDAError(f"Failed to rename function {fn.start_ea} to {new_name}")
        self.refresh_decompiler_ctext(fn.start_ea)
    
    def set_function_prototype(self,function_address: Annotated[int, "Address of the function"],prototype: Annotated[str, "New function prototype"]) -> str:
        """Set a function's prototype"""
        fn = self.idaapi.get_func(function_address)
        if not fn:
            raise IDAError(f"No function found at address {function_address}")
        try:
            tif = self.ida_typeinf.tinfo_t(prototype, None, self.ida_typeinf.PT_SIL)
            if not tif.is_func():
                raise IDAError(f"Parsed declaration is not a function type")
            if not self.ida_typeinf.apply_tinfo(fn.start_ea, tif, self.ida_typeinf.PT_SIL):
                raise IDAError(f"Failed to apply type")
            self.refresh_decompiler_ctext(fn.start_ea)
        except Exception as e:
            raise IDAError(f"Failed to parse prototype string: {prototype}")
    def save_idb_file(self,save_path: Annotated[str, "Path to save the IDB file"]):
        self.ida_loader.save_database(save_path, 0)