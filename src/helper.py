import jpype
from ghidra.program.disassemble import Disassembler
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet
from ghidra.app.decompiler import DecompInterface


class GhidraHelper:
    def __init__(self, flat_api):
        self.flat_api = flat_api

    def disasm(self, from_addr, to_addr):
        program = self.flat_api.getCurrentProgram()
        monitor = ConsoleTaskMonitor()
        disasm = Disassembler.getDisassembler(program, monitor, None)
        addr_set = AddressSet()
        addr_set.addRange(from_addr, to_addr)
        instr = disasm.disassemble(from_addr, addr_set)
        #print(instr)

    def get_monitor(self):
        monitor = ConsoleTaskMonitor()
        return monitor

    def to_addr(self, addr: int):
        assert isinstance(addr, int), "Addr must be int!"
        return self.flat_api.toAddr(jpype.JLong(addr))

    def decompile_addr(self, addr):
        TIMEOUT = 1000
        # addr = self.to_addr(addr)
        currentProgram = self.flat_api.getCurrentProgram()
        decomp = DecompInterface()
        decomp.openProgram(currentProgram)
        # functions = list(currentProgram.functionManager.getFunctions(addr, False))
        function = currentProgram.functionManager.getFunctionContaining(addr)
        if not function:
            return ""
        # print(f"Decompiling {function.name}")
        decomp_res = decomp.decompileFunction(function, TIMEOUT, self.get_monitor())
        if decomp_res.isTimedOut():
            # print("Timed out while attempting to decompile '{function.name}'")
            return ""
        elif not decomp_res.decompileCompleted():
            return ""
        return decomp_res.getDecompiledFunction().getC()
