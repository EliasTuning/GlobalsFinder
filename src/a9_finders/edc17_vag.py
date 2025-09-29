from typing import Any

from src.helper import GhidraHelper
from ghidra.program.flatapi import FlatProgramAPI

class EDC17_VAG:
    """
 Finds pattern like:
        8014d964 82 f2           mov        d2,#-0x1
        8014d966 91 30 00 28     movh.a     a2,#0x8003
        8014d96a d9 22 fc 7f     lea        a2,[a2]-0x204
        8014d96e cc 20           ld.a       a15,[a2]#0x0=>Dme_PtaConfig_cs
        8014d970 00 00           nop

       """

    def __init__(self, flat_api: FlatProgramAPI, helper: GhidraHelper) -> None:
        assert flat_api is not None, "flat_api must not be None"
        assert helper is not None, "helper must not be None"
        self.helper = helper
        self.flat_api = flat_api


    def find(self):
        hex_pattern = r"\x82\xF2.{10}\x00\x00"
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
        ld_addr = matches[0]
        # Add two bytes to get into the LD instruction
        ld_addr = ld_addr.add(10)
        # Disasm only the LD instruction
        self.helper.disasm(
            from_addr=matches[0],
            to_addr=ld_addr.add(12)
        )
        # Run Analyzer
        self.helper.run_analyzer()
        currentProgram = self.flat_api.getCurrentProgram()
        refManager = currentProgram.getReferenceManager()
        refs = refManager.getReferencesFrom(ld_addr)
        if len(refs) > 1:
            raise ValueError("References find multiple times!")
        if len(refs) == 0:
            raise ValueError("References Not found...")

        to_addr = refs[0].getToAddress()
        a9 = self.flat_api.getInt(to_addr) & 0xffffffff
        a9 = hex(a9)
        return a9
