import re
from array import array
import jpype
from ghidra.util import NumericUtilities
from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from ghidra.app.util.importer import MessageLog
from src.helper import GhidraHelper


class Find_A9:
    def __init__(self, flat_api, helper: GhidraHelper):
        self.helper = helper
        self.flat_api = flat_api

    import re

    def set_reg(self, regname, regvalue):
        currentProgram = self.flat_api.getCurrentProgram()
        context = currentProgram.getProgramContext()
        regvalue = NumericUtilities.unsignedLongToBigInteger(regvalue)
        register = context.getRegister(regname)
        start = self.helper.to_addr(0x8000000)
        end = self.helper.to_addr(0x8fffffff)
        context.setValue(register, start, end, regvalue)

    def hex_pattern_to_regex(self, hex_pattern: str) -> str:
        """
        Converts a hex-like string with '.' wildcards into a regex byte string.

        Consecutive dots are compressed into regex quantifiers.

        Example:
            "82f2........0000" -> "\\x82\\xF2.{8}\\x00\\x00"
            "aa....bb"        -> "\\xAA.{4}\\xBB"
        """
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

    def run_analyzer(self):
        currentProgram = self.flat_api.getCurrentProgram()
        # Get the AutoAnalysisManager for the current program
        mgr = AutoAnalysisManager.getAnalysisManager(currentProgram)
        # Get the analyzer by name
        analyzer = mgr.getAnalyzer("Basic Constant Reference Analyzer")
        log = MessageLog()
        addr_set = currentProgram.getMemory()
        success = analyzer.added(currentProgram, addr_set, self.helper.get_monitor(), log)

    def find(self):
        self.set_reg("a1",0x80028058)
        # Find Dme_GetPtaGroup
        hex_pattern = "82 f2 ?? ?? ?? ?? 00 00"
        hex_pattern = ''.join(['.' if '?' in x else f'\\x{x}' for x in hex_pattern.split()])
        matches = self.flat_api.findBytes(self.helper.to_addr(0x80000000), hex_pattern, 50)
        if len(matches) != 1:
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
        print(to_addr)
        #self.flat_api.createDWord(to_addr)
        a9 = self.flat_api.getInt(to_addr) & 0xffffffff
        return a9
