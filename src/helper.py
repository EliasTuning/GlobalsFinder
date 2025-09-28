import jpype
from typing import Any, Optional
from ghidra.program.disassemble import Disassembler
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet
from ghidra.app.decompiler import DecompInterface
from ghidra.util import NumericUtilities

class GhidraHelper:
    def __init__(self, flat_api: Any) -> None:
        assert flat_api is not None, "flat_api must not be None"
        self.flat_api = flat_api

    def disasm(self, from_addr: Any, to_addr: Any) -> None:
        assert from_addr is not None, "from_addr must not be None"
        assert to_addr is not None, "to_addr must not be None"
        program = self.flat_api.getCurrentProgram()
        monitor = ConsoleTaskMonitor()
        disasm = Disassembler.getDisassembler(program, monitor, None)
        addr_set = AddressSet()
        addr_set.addRange(from_addr, to_addr)
        instr = disasm.disassemble(from_addr, addr_set)
        # print(instr)

    def get_monitor(self) -> ConsoleTaskMonitor:
        monitor = ConsoleTaskMonitor()
        return monitor

    def to_addr(self, addr: int) -> Any:
        assert isinstance(addr, int), "Addr must be int!"
        return self.flat_api.toAddr(jpype.JLong(addr))

    def decompile_addr(self, addr: Any) -> str:
        assert addr is not None, "addr must not be None"
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

    def set_reg(self, regname: str, regvalue: int) -> None:
        assert isinstance(regname, str), "regname must be a string"
        assert isinstance(regvalue, int), "regvalue must be an integer"
        currentProgram = self.flat_api.getCurrentProgram()
        context = currentProgram.getProgramContext()
        regvalue = NumericUtilities.unsignedLongToBigInteger(regvalue)
        register = context.getRegister(regname)
        start = self.to_addr(0x8000000)
        end = self.to_addr(0x8fffffff)
        context.setValue(register, start, end, regvalue)
