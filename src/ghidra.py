import contextlib
import os
import shutil
from pathlib import Path
import pyhidra
from pyhidra.launcher import HeadlessPyhidraLauncher



class Ghidra:
    @contextlib.contextmanager
    def open_program(self, file_name):
        if os.path.isdir('work'):
            shutil.rmtree("work")
        os.environ["GHIDRA_INSTALL_DIR"] = "C:\\Users\\Elias\\Desktop\\Chiptuning-Projects\\Software\\Ghidra"
        ext = Path(file_name).suffix
        if ext == "hex":
            loader = 'ghidra.app.util.opinion.IntelHexLoader'
        elif ext == "elf":
            loader = 'ghidra.app.util.opinion.ElfLoader'
        else:
            loader = 'ghidra.app.util.opinion.BinaryLoader'

        with pyhidra.open_program(
                binary_path=file_name,
                project_location=None,
                project_name="work",
                analyze=False,
                language='tricore:LE:32:med17',
                compiler='default',
                loader=loader
        ) as flat_api:
            if loader == 'ghidra.app.util.opinion.BinaryLoader':
                from src.helper import GhidraHelper
                from src.setup_memorymap import SetupMemoryMap
                helper = GhidraHelper(flat_api)
                memory_map = SetupMemoryMap(flat_api, helper)
                memory_map.setup()

            yield flat_api
