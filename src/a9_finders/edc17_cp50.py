from typing import Any

from src.helper import GhidraHelper
from ghidra.program.flatapi import FlatProgramAPI

class EDC17_CP50:
    """
 Finds pattern like:
        800ffba8 b7 04 81 4e     insert     d4,d4,#0x0,#0x1d,#0x1
        800ffbac 99 12 5c a9     ld.a       a2=>DAT_802845a0,[a1]-0x6964=>FUN_8022b524       = 0C00h
        800ffbb0 82 f2           mov        d2,#-0x1


       """

    def __init__(self, flat_api: FlatProgramAPI, helper: GhidraHelper) -> None:
        assert flat_api is not None, "flat_api must not be None"
        assert helper is not None, "helper must not be None"
        self.helper = helper
        self.flat_api = flat_api


    def find(self):
        hex_pattern = r"\xB7\x04\x81\x4e.{4}\x82\xf2"
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
        ld_addr = ld_addr.add(4)
        # Disasm only the LD instruction
        self.helper.disasm(
            from_addr=matches[0],
            to_addr=ld_addr.add(8)
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
