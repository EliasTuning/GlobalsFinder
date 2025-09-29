from typing import Any

from src.helper import GhidraHelper
from ghidra.program.flatapi import FlatProgramAPI

class MED17_VAG:
    """
 Finds pattern like:
        80166b12 82 f2           mov        idxGroup_s32,#-0x1
        80166b14 99 12 f0 a8     ld.a       a2=>VECT_MOCADC_Mo_DataCyclicCheckByte,[a1]-0x   = 80041410
        80166b18 00 00           nop
       """

    def __init__(self, flat_api: FlatProgramAPI, helper: GhidraHelper) -> None:
        assert flat_api is not None, "flat_api must not be None"
        assert helper is not None, "helper must not be None"
        self.helper = helper
        self.flat_api = flat_api


    def find(self):
        hex_pattern = r"\x82\xF2.{4}\x00\x00"
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
        # First match
        addr = matches[0]
        # Add two bytes to get into the LD instruction
        addr = addr.add(2)
        # Disasm only the LD instruction
        self.helper.disasm(
            from_addr=addr,
            to_addr=addr.add(4)
        )
        # Run Analyzer
        self.helper.run_analyzer()
        currentProgram = self.flat_api.getCurrentProgram()
        refManager = currentProgram.getReferenceManager()
        refs = refManager.getReferencesFrom(addr)
        if len(refs) > 1:
            raise ValueError("References find multiple times!")
        if len(refs) == 0:
            raise ValueError("References Not found...")

        to_addr = refs[0].getToAddress()
        a9 = self.flat_api.getInt(to_addr) & 0xffffffff
        a9 = hex(a9)
        return a9
