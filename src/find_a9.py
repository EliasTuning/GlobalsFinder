import re
from array import array
import jpype
from typing import Any, Optional

from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from ghidra.app.util.importer import MessageLog
from src.helper import GhidraHelper


class Find_A9:
    """
    A class for finding and analyzing A9 register patterns in Ghidra.
    
    This class provides functionality to locate specific hex patterns in binary code,
    analyze instruction references, and extract A9 register values. It is specifically
    designed to work with MED17 ECU firmware analysis, focusing on finding and
    analyzing A9 register assignments in decompiled code.
    
    Attributes:
        helper: The GhidraHelper instance for common Ghidra operations
        flat_api: The Ghidra flat API instance for program interaction
    """
    
    def __init__(self, flat_api: Any, helper: GhidraHelper) -> None:
        """
        Initialize the Find_A9 class with Ghidra API instances.
        
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



    def hex_pattern_to_regex(self, hex_pattern: str) -> str:
        """
        Convert a hex-like string with '.' wildcards into a regex byte string.
        
        This method converts hex patterns with wildcard dots into regex patterns
        suitable for Ghidra's findBytes method. Consecutive dots are compressed
        into regex quantifiers for efficiency.
        
        Args:
            hex_pattern: The hex pattern string with dots as wildcards. Must not be None.
            
        Returns:
            str: The regex pattern string with escaped hex bytes and quantifiers
            
        Raises:
            ValueError: If hex pattern has odd length (except for dots)
            AssertionError: If hex_pattern is None
            
        Example:
            "82f2........0000" -> "\\x82\\xF2.{8}\\x00\\x00"
            "aa....bb"        -> "\\xAA.{4}\\xBB"
        """
        assert hex_pattern is not None, "hex_pattern must not be None"
        result = []
        i = 0
        while i < len(hex_pattern):
            if hex_pattern[i] == '.':
                # Count consecutive dots
                dot_count = 1
                while i + dot_count < len(hex_pattern) and hex_pattern[i + dot_count] == '.':
                    dot_count += 1
                if dot_count == 1:
                    result.append('.')  # single dot = . (any byte)
                else:
                    result.append(f".{{{dot_count}}}")  # regex quantifier
                i += dot_count
            else:
                # Make sure we have a full hex byte
                if i + 1 >= len(hex_pattern):
                    raise ValueError("Hex string length must be even (except for dots)")
                result.append(f"\\x{hex_pattern[i:i + 2]}")
                i += 2
        return ''.join(result)

    def run_analyzer(self) -> None:
        """
        Run the Basic Constant Reference Analyzer on the current program.
        
        This method executes Ghidra's Basic Constant Reference Analyzer to
        analyze constant references in the program. It uses the current program's
        memory and a console monitor for the analysis process.
        
        Raises:
            AssertionError: If flat_api or helper is None
        """
        assert self.flat_api is not None, "flat_api must not be None"
        assert self.helper is not None, "helper must not be None"
        currentProgram = self.flat_api.getCurrentProgram()
        # Get the AutoAnalysisManager for the current program
        mgr = AutoAnalysisManager.getAnalysisManager(currentProgram)
        # Get the analyzer by name
        analyzer = mgr.getAnalyzer("Basic Constant Reference Analyzer")
        log = MessageLog()
        addr_set = currentProgram.getMemory()
        success = analyzer.added(currentProgram, addr_set, self.helper.get_monitor(), log)

    def find(self) -> int:
        """
        Find and extract the A9 register value from Dme_GetPtaGroup pattern.
        
        This method searches for a specific hex pattern in the program memory,
        disassembles the code around the match, runs analysis, and extracts
        the A9 register value from the instruction references.
        
        The method performs the following operations:
        1. Searches for the hex pattern "\\x82\\xF2.{6,8}\\x00\\x00" in memory
        2. Disassembles code around the match location
        3. Runs the Basic Constant Reference Analyzer
        4. Extracts instruction references to find the A9 value
        5. Returns the A9 register value as an integer
        
        Returns:
            int: The A9 register value as a 32-bit unsigned integer
            
        Raises:
            ValueError: If the Dme_GetPtaGroup pattern is not found or has multiple matches
            ValueError: If no references are found at the instruction location
            AssertionError: If flat_api or helper is None
        """
        assert self.flat_api is not None, "flat_api must not be None"
        assert self.helper is not None, "helper must not be None"
        # Find Dme_GetPtaGroup
        #hex_pattern = "82 f2 ?? ?? ?? ?? 00 00"
        #hex_pattern = ''.join(['.' if '?' in x else f'\\x{x}' for x in hex_pattern.split()])

        hex_pattern = "\\x82\\xF2.{4}\\x00\\x00"
        #hex_pattern = "82 f2 ?? ?? ?? ?? 00 00"

        #\\x50.
        #{0, 10}\\x55
        match_limit = 50
        alignment = 2
        matches = self.flat_api.findBytes(
            self.helper.to_addr(0x80000000),
            hex_pattern,
            match_limit,
            alignment
        )
        if len(matches) > 1:
            raise ValueError("Dme_GetPtaGroup find multiple times!")
        if len(matches) == 0:
            raise ValueError("Dme_GetPtaGroup Not found...")


        addr = matches[0]
        addr = addr.add(2)
        self.helper.disasm(
            from_addr=addr,
            to_addr=addr.add(4)
        )
        self.run_analyzer()
        instruction = self.flat_api.getInstructionAt(addr)
        op1 = instruction.getOpObjects(0)
        op2 = instruction.getOpObjects(1)
        #print(op1)
        #print(op2)
        #print(instruction.getReferencesFrom())
        #print(instruction)

        currentProgram = self.flat_api.getCurrentProgram()
        refManager = currentProgram.getReferenceManager()
        refs = refManager.getReferencesFrom(addr)
        if len(refs) != 1:
            raise ValueError("No references found!")

        to_addr = refs[0].getToAddress()
        #print(to_addr)
        #self.flat_api.createDWord(to_addr)
        a9 = self.flat_api.getInt(to_addr) & 0xffffffff
        a9 = hex(a9)
        return a9
