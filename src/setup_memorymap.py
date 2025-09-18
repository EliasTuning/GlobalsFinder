from array import array

import jpype

from src.helper import GhidraHelper


class SetupMemoryMap:
    def __init__(self, flat_api, helper: GhidraHelper):
        self.helper = helper
        self.flat_api = flat_api

    def setup(self):
        program = self.flat_api.getCurrentProgram()
        memory = program.getMemory()
        romblock = memory.getBlock(self.helper.to_addr(0x0))
        memory.moveBlock(romblock, self.helper.to_addr(0x80000000), self.helper.get_monitor())
