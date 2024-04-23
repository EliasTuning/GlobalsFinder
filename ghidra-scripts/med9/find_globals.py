#!/usr/bin/python
# -*- coding: ascii -*-
# @author Elias
# @category Tuning
# @keybinding
# @menupath
# @toolbar
import re


def get_opcode_addr_list(instruction_str):
    start_addr = 0x400000
    memory = currentProgram.getMemory()
    romblock = memory.getBlock(toAddr(start_addr))
    end_addr = romblock.getEnd().getOffset()

    ret_arr = []
    for i in range(start_addr, end_addr, 2):
        addr = toAddr(i)
        codeunit = currentProgram.getListing().getCodeUnitAt(addr)
        if codeunit:
            code = str(codeunit)
            if instruction_str in code:
                # print(hex(i))
                # print(codeunit)
                ret_arr.append(i)

    return ret_arr


def decompile_addr(addr):
    TIMEOUT = 1000
    addr = toAddr(addr)
    decomp = ghidra.app.decompiler.DecompInterface()
    decomp.openProgram(currentProgram)
    # functions = list(currentProgram.functionManager.getFunctions(addr, False))
    function = currentProgram.functionManager.getFunctionContaining(addr)
    if not function:
        return ""
    # print(f"Decompiling {function.name}")
    decomp_res = decomp.decompileFunction(function, TIMEOUT, monitor)
    if decomp_res.isTimedOut():
        # print("Timed out while attempting to decompile '{function.name}'")
        return ""
    elif not decomp_res.decompileCompleted():
        return ""
    return decomp_res.getDecompiledFunction().getC()


def match_instruction(text, value):
    pattern = r"" + value + " = (.+?);"
    match = re.search(pattern, text)
    if match:
        match = match.group(1)
        match = match.replace('FUN_', "")
        match = match.replace('&DWORD_', "")
        return match
    else:
        return ""


addr_list = get_opcode_addr_list("lis r2,")
for addr in addr_list:
    print("Found matching instruction on "+hex(addr))
    c_code = decompile_addr(addr)
    r2 = match_instruction(c_code, "r2")
    r13 = match_instruction(c_code, "r13")

    if r2 and r13:
        print("r2:" + r2)
        print("r13:" + r13)
        #break
