# @author Elias Kotlyar
# @category Tuning
# @keybinding
# @menupath
# @toolbar

memory = currentProgram.getMemory()
romblock = memory.getBlock(toAddr(0x0))
#romblock.setName("rom")
memory.moveBlock(romblock, toAddr(0x400000), monitor)


