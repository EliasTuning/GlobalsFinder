from src.ghidra import Ghidra

filename = "med17.bin"

ghidra = Ghidra()
command = [
    '-import',
    filename,
    '-processor',
    'tricore:LE:32:tc179x',
    '-overwrite',
    '-noanalysis',
    '-postScript',
    'med17/memorymap_install.py',
    '-postScript',
    'med17/mark_as_code.py',
    '-postScript',
    'med17/define_undefined_functions.py',
    '-postScript',
    'med17/find_globals.py',
]
ghidra.run_ghidra_headless(command)
