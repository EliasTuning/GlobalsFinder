#!/usr/bin/python
# -*- coding: ascii -*-
# @author Elias
# @category Tuning
# @keybinding
# @menupath
# @toolbar

from ghidra.program.model.address import AddressSet
from ghidra.program.disassemble import Disassembler

start_addr = 0x400000
memory = currentProgram.getMemory()
romblock = memory.getBlock(toAddr(start_addr))
end_addr = romblock.getEnd().getOffset()

for i in range(start_addr, end_addr, 2):
    #print(hex(i))
    addr = toAddr(i)
    data = getDataAt(addr)
    if not data:
        address_set = AddressSet(addr)
        disasm = Disassembler.getDisassembler(currentProgram, False, False, False, monitor, None)
        disasm.disassemble(addr, address_set, False)
