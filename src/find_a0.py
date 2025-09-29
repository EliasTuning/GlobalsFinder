import re
from array import array
import jpype
from typing import Any, Dict, List, Optional
from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import VariableStorage
from src.helper import GhidraHelper


class Find_A0:
    """
    A class for finding and analyzing A0 register patterns in Ghidra.
    
    This class provides functionality to locate specific hex patterns in binary code,
    decompile functions containing those patterns, and extract register assignments.
    It is specifically designed to work with MED17 ECU firmware analysis, focusing
    on finding and analyzing A0, A1, and A8 register assignments in decompiled code.
    
    Attributes:
        helper: The GhidraHelper instance for common Ghidra operations
        flat_api: The Ghidra flat API instance for program interaction
    """

    def __init__(self, flat_api: Any, helper: GhidraHelper) -> None:
        """
        Initialize the Find_A0 class with Ghidra API instances.
        
        Args:
            flat_api: The Ghidra flat API instance. Must not be None.
            helper: The GhidraHelper instance for common operations. Must not be None.
            
        Raises:
            AssertionError: If flat_api or helper is None.
        """
        assert flat_api is not None, "flat_api must not be None"
        assert helper is not None, "helper must not be None"
        self.helper = helper
        self.flat_api = flat_api

    def hex_to_escaped_bytes(self, hex_pattern: str) -> str:
        """
        Convert a hex string to escaped byte format for Ghidra pattern matching.
        
        This method takes a hex string and converts it to the escaped byte format
        required by Ghidra's findBytes method. It ensures the hex string has even
        length and formats each byte pair with the prefix.
        
        Args:
            hex_pattern: The hex string to convert (e.g., "4d40e00f"). Must not be None.
            
        Returns:
            str: The escaped byte string
            
        Raises:
            ValueError: If hex_pattern has odd length
            AssertionError: If hex_pattern is None
        """
        assert hex_pattern is not None, "hex_pattern must not be None"
        # make sure the hex string has even length
        if len(hex_pattern) % 2 != 0:
            raise ValueError("Hex string length must be even")

        # split every two characters and prepend "\x"
        return "".join(f"\\x{hex_pattern[i:i + 2]}" for i in range(0, len(hex_pattern), 2))

    def get_address_from_code(self, field_name: str, code: str) -> int:
        """
        Extract the integer address for the given field name from a C-style assignment string.
        
        This method parses decompiled C code to find register assignments and extracts
        the hexadecimal address values. It handles both direct hex addresses and symbolic
        addresses like &UNK_xxxxxxxx patterns commonly found in Ghidra decompiled code.
        
        Args:
            field_name: The field name to search for (e.g., "a0", "a1", "a8"). Must not be None.
            code: The decompiled C code string to search in. Must not be None.
            
        Returns:
            int: The extracted address as an integer
            
        Raises:
            ValueError: If the field_name is not found in the code
            AssertionError: If field_name or code is None
        """
        assert field_name is not None, "field_name must not be None"
        assert code is not None, "code must not be None"
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

    def get_data_type(self, name: str) -> Any:
        """
        Retrieve a data type from the current program's data type manager.
        
        This method accesses the Ghidra program's data type manager to retrieve
        a specific data type by name. It is commonly used to get custom structures
        that have been defined in the program.
        
        Args:
            name: The name of the data type to retrieve. Must not be None.
            
        Returns:
            Any: The data type object from Ghidra's data type manager
            
        Raises:
            AssertionError: If name is None
        """
        assert name is not None, "name must not be None"
        program = self.flat_api.getCurrentProgram()
        dtm = program.getDataTypeManager()
        dt = dtm.getDataType(name)
        return dt

    def create_data_struct(self) -> None:
        """
        Create a custom data structure for register analysis.
        
        This method defines and creates a custom C structure called 'register_struct'
        that contains pointers to the A0, A1, and A8 registers. The structure is
        added to the program's data type manager for use in function return type
        analysis and register assignment tracking.
        
        The structure contains:
        - int *a0: Pointer to A0 register
        - int *a1: Pointer to A1 register  
        - int *a8: Pointer to A8 register
        
        Raises:
            AssertionError: If flat_api is None
        """
        assert self.flat_api is not None, "flat_api must not be None"
        data_str = """
        struct register_struct {
    int *a0;
    int *a1;
    int *a8;
}; 
        """
        program = self.flat_api.getCurrentProgram()
        data_type_manager = program.getDataTypeManager()
        parser = CParser(data_type_manager)
        parsed_datatype = parser.parse(data_str)
        datatype = data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)
        pass
        # field1 = datatype.components[0]
        # field1_settings = field1.getDefaultSettings()
        # Set endianess to big
        # field1_settings.setLong('endian', EndianSettingsDefinition.BIG)
        # return datatype

    def set_function_ret_struct(self, addr: Any) -> None:
        """
        Set the return type and storage for a function containing the specified address.
        
        This method configures a function's return type to use the custom register_struct
        and sets up variable storage using the A0, A1, and A8 registers. It enables
        custom variable storage and creates a return type that maps to the physical
        registers used in the function.
        
        Args:
            addr: The address within the function to configure. Must not be None.
            
        Raises:
            AssertionError: If addr is None
        """
        assert addr is not None, "addr must not be None"
        program = self.flat_api.getCurrentProgram()
        function = program.functionManager.getFunctionContaining(addr)
        function.setCustomVariableStorage(True)
        self.create_data_struct()
        data_type = self.get_data_type("/register_struct")
        # from ghidra.program.model.lang import Register
        a0_reg = program.getRegister("a0")
        a1_reg = program.getRegister("a1")
        a8_reg = program.getRegister("a8")
        regs = [a0_reg, a1_reg, a8_reg]
        # Reverse Array because of little endian
        # regs = regs.reverse()
        regs = list(reversed(regs))

        storage = VariableStorage(program, regs)
        function.setReturn(data_type, storage, SourceType.USER_DEFINED)

    def find(self) -> Optional[Dict[str, str]]:
        """
        Find and analyze A0 register patterns in the current program.
        
        This method searches for a specific hex pattern ("4d40e00f") in the program's
        memory, decompiles functions containing the pattern, and extracts register
        assignments. It creates functions at match locations, sets up custom return
        types, and extracts register values from decompiled code.
        
        The method performs the following operations:
        1. Searches for the hex pattern in program memory
        2. For each match, creates a function and sets up return structure
        3. Decompiles the function to get C code
        4. Extracts A0, A1, and A8 register assignments from the code
        5. Returns a dictionary with the register values
        
        Returns:
            Optional[Dict[str, str]]: Dictionary containing register values as hex strings:
                - "a0": Hex string of A0 register value
                - "a1": Hex string of A1 register value  
                - "a8": Hex string of A8 register value
                Returns None if no valid matches are found
        
        Raises:
            AssertionError: If flat_api or helper is None
        """
        assert self.flat_api is not None, "flat_api must not be None"
        assert self.helper is not None, "helper must not be None"
        hex_pattern = "4d40e00f"
        hex_pattern = self.hex_to_escaped_bytes(hex_pattern)
        # hex_pattern = "\\x4d\\x40\\xe0\\x0f"

        matches = self.flat_api.findBytes(self.flat_api.toAddr(0), hex_pattern, 50)

        for match in matches:
            try:
                start_addr = match
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
                self.helper.set_reg("a1", a0)
                self.helper.set_reg("a1", a1)
                self.helper.set_reg("a8", a8)

                return {
                    "a0": hex(a0),
                    "a1": hex(a1),
                    "a8": hex(a8)
                }
            except ValueError as e:
                print(f"Havent found it on location: {match}")
                pass
