import jpype
from typing import Any, Optional
from ghidra.program.disassemble import Disassembler
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet
from ghidra.app.decompiler import DecompInterface
from ghidra.util import NumericUtilities

class GhidraHelper:
    """
    A helper class for interacting with Ghidra's flat API.
    
    This class provides convenient methods for common Ghidra operations such as
    disassembly, decompilation, address conversion, and register manipulation.
    It acts as a wrapper around Ghidra's flat API to simplify common tasks
    when working with binary analysis and reverse engineering.
    
    Attributes:
        flat_api: The Ghidra flat API instance used for program interaction
    """
    
    def __init__(self, flat_api: Any) -> None:
        """
        Initialize the GhidraHelper with a flat API instance.
        
        Args:
            flat_api: The Ghidra flat API instance. Must not be None.
            
        Raises:
            AssertionError: If flat_api is None.
        """
        assert flat_api is not None, "flat_api must not be None"
        self.flat_api = flat_api

    def disasm(self, from_addr: Any, to_addr: Any) -> None:
        """
        Disassemble instructions in a specified address range.
        
        This method creates a disassembler and processes the instructions
        between the given start and end addresses. The disassembly is performed
        on the current program loaded in Ghidra.
        
        Args:
            from_addr: The starting address for disassembly. Must not be None.
            to_addr: The ending address for disassembly. Must not be None.
            
        Raises:
            AssertionError: If from_addr or to_addr is None.
        """
        assert from_addr is not None, "from_addr must not be None"
        assert to_addr is not None, "to_addr must not be None"
        program = self.flat_api.getCurrentProgram()
        monitor = ConsoleTaskMonitor()
        disasm = Disassembler.getDisassembler(program, monitor, None)
        addr_set = AddressSet()
        addr_set.addRange(from_addr, to_addr)
        instr = disasm.disassemble(from_addr, addr_set)
        # print(instr)

    def get_monitor(self) -> ConsoleTaskMonitor:
        """
        Create and return a new console task monitor.
        
        This method creates a ConsoleTaskMonitor instance that can be used
        for monitoring long-running operations in Ghidra. The monitor provides
        feedback and allows for cancellation of operations.
        
        Returns:
            ConsoleTaskMonitor: A new console task monitor instance.
        """
        monitor = ConsoleTaskMonitor()
        return monitor

    def to_addr(self, addr: int) -> Any:
        """
        Convert an integer address to a Ghidra Address object.
        
        This method takes a Python integer address and converts it to a
        Ghidra Address object that can be used with other Ghidra APIs.
        The conversion uses jpype to handle the Java interop.
        
        Args:
            addr: The integer address to convert. Must be an integer.
            
        Returns:
            Any: A Ghidra Address object corresponding to the input address.
            
        Raises:
            AssertionError: If addr is not an integer.
        """
        assert isinstance(addr, int), "Addr must be int!"
        return self.flat_api.toAddr(jpype.JLong(addr))

    def decompile_addr(self, addr: Any) -> str:
        """
        Decompile the function containing the specified address.
        
        This method attempts to decompile the function that contains the
        given address. It uses Ghidra's decompiler to generate C-like
        pseudocode representation of the function. The operation has a
        timeout to prevent hanging on complex functions.
        
        Args:
            addr: The address within the function to decompile. Must not be None.
            
        Returns:
            str: The decompiled C code as a string, or empty string if:
                - No function contains the address
                - Decompilation times out
                - Decompilation fails
                
        Raises:
            AssertionError: If addr is None.
        """
        assert addr is not None, "addr must not be None"
        TIMEOUT = 1000
        # addr = self.to_addr(addr)
        currentProgram = self.flat_api.getCurrentProgram()
        decomp = DecompInterface()
        decomp.openProgram(currentProgram)
        # functions = list(currentProgram.functionManager.getFunctions(addr, False))
        function = currentProgram.functionManager.getFunctionContaining(addr)
        if not function:
            return ""
        # print(f"Decompiling {function.name}")
        decomp_res = decomp.decompileFunction(function, TIMEOUT, self.get_monitor())
        if decomp_res.isTimedOut():
            # print("Timed out while attempting to decompile '{function.name}'")
            return ""
        elif not decomp_res.decompileCompleted():
            return ""
        return decomp_res.getDecompiledFunction().getC()

    def set_reg(self, regname: str, regvalue: int) -> None:
        """
        Set a register value across a specific address range.
        
        This method sets the value of a specified register for all addresses
        in the range 0x8000000 to 0x8fffffff. This is commonly used for
        setting up initial register states for analysis or emulation.
        
        Args:
            regname: The name of the register to set. Must be a string.
            regvalue: The value to set the register to. Must be an integer.
            
        Raises:
            AssertionError: If regname is not a string or regvalue is not an integer.
        """
        assert isinstance(regname, str), "regname must be a string"
        assert isinstance(regvalue, int), "regvalue must be an integer"
        currentProgram = self.flat_api.getCurrentProgram()
        context = currentProgram.getProgramContext()
        regvalue = NumericUtilities.unsignedLongToBigInteger(regvalue)
        register = context.getRegister(regname)
        start = self.to_addr(0x8000000)
        end = self.to_addr(0x8fffffff)
        context.setValue(register, start, end, regvalue)
