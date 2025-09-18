import re
from array import array

import jpype

from src.helper import GhidraHelper


class Find_A0:
    def __init__(self, flat_api, helper: GhidraHelper):
        self.helper = helper
        self.flat_api = flat_api

    def hex_to_escaped_bytes(self, hex_pattern: str) -> str:
        # make sure the hex string has even length
        if len(hex_pattern) % 2 != 0:
            raise ValueError("Hex string length must be even")

        # split every two characters and prepend "\x"
        return "".join(f"\\x{hex_pattern[i:i + 2]}" for i in range(0, len(hex_pattern), 2))

    def get_address_from_code(self, field_name: str, code: str) -> int:
        """
            Extracts the integer address for the given field name from a C-style assignment string.
            Handles hexadecimal addresses and symbolic addresses like &UNK_xxxxxxxx.
            """
        # Regex pattern to match lines like:
        # rVar10.a1 = (int *)0x80028058;
        # rVar10.a8 = (int *)&UNK_d00095f8;
        pattern = rf"\b{re.escape(field_name)}\s*=\s*\(int \*\)\s*(&?UNK_)?(0x[0-9a-fA-F]+|[0-9a-fA-F]+);"

        match = re.search(pattern, code)
        if not match:
            raise ValueError(f"Field '{field_name}' not found in code snippet.")

        # The actual address part is in the last captured group
        addr_str = match.group(2)

        # Convert to integer (hex)
        return int(addr_str, 16)

    def get_data_type(self, name: str):
        program = self.flat_api.getCurrentProgram()
        dtm = program.getDataTypeManager()
        dt = dtm.getDataType(name)
        return dt

    def create_data_struct(self):
        data_str = """
        struct register_struct {
    int *a0;
    int *a1;
    int *a8;
}; 
        """
        program = self.flat_api.getCurrentProgram()
        data_type_manager = program.getDataTypeManager()
        from ghidra.app.util.cparser.C import CParser
        parser = CParser(data_type_manager)
        parsed_datatype = parser.parse(data_str)
        from ghidra.program.model.data import DataTypeConflictHandler
        datatype = data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)
        pass
        # field1 = datatype.components[0]
        # field1_settings = field1.getDefaultSettings()
        # Set endianess to big
        # field1_settings.setLong('endian', EndianSettingsDefinition.BIG)
        # return datatype

    def set_function_ret_struct(self, addr):
        program = self.flat_api.getCurrentProgram()
        function = program.functionManager.getFunctionContaining(addr)
        function.setCustomVariableStorage(True)
        from ghidra.program.model.symbol import SourceType
        self.create_data_struct()
        data_type = self.get_data_type("/register_struct")
        from ghidra.program.model.listing import VariableStorage
        # from ghidra.program.model.lang import Register
        a0_reg = program.getRegister("a0")
        a1_reg = program.getRegister("a1")
        a8_reg = program.getRegister("a8")
        regs = [a0_reg, a1_reg, a8_reg]
        # Reverse Array because of little endian
        #regs = regs.reverse()
        regs = list(reversed(regs))

        storage = VariableStorage(program, regs)
        function.setReturn(data_type, storage, SourceType.USER_DEFINED)

    def find(self):
        hex_pattern = "4d40e00f"
        hex_pattern = self.hex_to_escaped_bytes(hex_pattern)
        # hex_pattern = "\\x4d\\x40\\xe0\\x0f"

        matches = self.flat_api.findBytes(self.flat_api.toAddr(0), hex_pattern, 50)
        start_addr = matches[0]
        end_addr = matches[1]
        # end_addr = self.helper.to_addr(0x8012cff8)
        self.helper.disasm(
            from_addr=start_addr,
            to_addr=end_addr
        )
        self.flat_api.createFunction(start_addr, None)
        self.set_function_ret_struct(start_addr)
        c_code = self.helper.decompile_addr(start_addr)

        # print(c_code)

        a0 = self.get_address_from_code("a0", c_code)
        a1 = self.get_address_from_code("a1", c_code)
        a8 = self.get_address_from_code("a8", c_code)
        return {
            "a0": hex(a0),
            "a1": hex(a1),
            "a8": hex(a8)
        }
