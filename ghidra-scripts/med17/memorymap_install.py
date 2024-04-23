# @author Elias Kotlyar
# @category Tuning
# @keybinding
# @menupath
# @toolbar

# Set Registers:
def set_reg_64(regname, regvalue):
    context = currentProgram.getProgramContext()
    #
    regvalue = java.math.BigInteger(regvalue, 16)
    register = context.getRegister(regname)
    start = toAddr(0x80000000)
    end = toAddr(0x8fffffff)
    context.setValue(register, start, end, regvalue)


def set_reg(regname, regvalue):
    context = currentProgram.getProgramContext()
    regvalue = ghidra.util.NumericUtilities.unsignedLongToBigInteger(regvalue)
    register = context.getRegister(regname)
    start = toAddr(0x80000000)
    end = toAddr(0x8fffffff)
    context.setValue(register, start, end, regvalue)


memory = currentProgram.getMemory()
romblock = memory.getBlock(toAddr(0x0))
memory.moveBlock(romblock, toAddr(0x80000000), monitor)

start = 0xD0000000
end = 0xd001fffC
for i in range(start, end, 4):
    createDWord(toAddr(i))

