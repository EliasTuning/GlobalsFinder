from typing import Any

from src.helper import GhidraHelper
from ghidra.program.flatapi import FlatProgramAPI

class MED17_BMW:
    """
 Finds pattern like:
        800dd3fe 82 f2           mov        d2,#-0x1
        800dd400 d9 22 1c 73     lea        a2=>DAT_800531dc,[a2]0x31dc                      = 80113C28h
        800dd404 cc 20           ld.a       a15,[a2]#0x0=>DAT_800531dc                       = 80113C28h
        800dd406 00 00           nop

       """

    def __init__(self, flat_api: FlatProgramAPI, helper: GhidraHelper) -> None:
        assert flat_api is not None, "flat_api must not be None"
        assert helper is not None, "helper must not be None"
        self.helper = helper
        self.flat_api = flat_api


    def find(self):
        hex_pattern = r"\x82\xF2.{4}\xCC\x20\x00\x00"
        match_limit = 50
        alignment = 1
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
        #
        # Add two bytes to get into the LD instruction
        ld_addr = ld_addr.add(6)
        # Disasm only the LD instruction
        self.helper.disasm(
            from_addr=matches[0].add(-4),
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
