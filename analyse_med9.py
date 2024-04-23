from src.ghidra import Ghidra

filename = "8p0907404n.bin"

ghidra = Ghidra()
command = [
    '-import',
    filename,
    '-processor',
    'PowerPC:BE:32:MED9',
    '-cspec',
    'no_globals',
    '-overwrite',
    '-noanalysis',
    '-postScript',
    'med9/memorymap_install.py',
    '-postScript',
    'med9/mark_as_code.py',
    '-postScript',
    'med9/define_undefined_functions.py',
    '-postScript',
    'med9/find_globals.py',
]
ghidra.run_ghidra_headless(command)
