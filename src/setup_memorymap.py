from array import array
import jpype
from typing import Any
from src.helper import GhidraHelper


class SetupMemoryMap:
    """
    A class for setting up memory mapping in Ghidra.
    
    This class provides functionality to configure memory blocks and move
    ROM blocks to specific addresses. It acts as a helper for memory
    management operations in Ghidra binary analysis workflows.
    
    Attributes:
        helper: The GhidraHelper instance for address conversion and monitoring
        flat_api: The Ghidra flat API instance for program interaction
    """
    
    def __init__(self, flat_api: Any, helper: GhidraHelper) -> None:
        """
        Initialize the SetupMemoryMap with flat API and helper instances.
        
        Args:
            flat_api: The Ghidra flat API instance. Must not be None.
            helper: The GhidraHelper instance for address operations. Must not be None.
            
        Raises:
            AssertionError: If flat_api or helper is None.
        """
        assert flat_api is not None, "flat_api must not be None"
        assert helper is not None, "helper must not be None"
        self.helper = helper
        self.flat_api = flat_api

    def setup(self) -> None:
        """
        Set up memory mapping by moving ROM block to the specified address.
        
        This method retrieves the current program, gets the memory manager,
        locates the ROM block at address 0x0, and moves it to address 0x80000000.
        This is commonly used for setting up proper memory layout for analysis.
        
        Raises:
            RuntimeError: If the ROM block cannot be found or moved.
        """
        program = self.flat_api.getCurrentProgram()
        memory = program.getMemory()
        romblock = memory.getBlock(self.helper.to_addr(0x0))
        memory.moveBlock(romblock, self.helper.to_addr(0x80000000), self.helper.get_monitor())
