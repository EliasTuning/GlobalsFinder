import contextlib
import os
import shutil
from pathlib import Path
from typing import Any, Generator
import pyhidra
from pyhidra.launcher import HeadlessPyhidraLauncher

from src.path_helper import get_path_helper


class Ghidra:
    """
    A class for managing Ghidra program analysis sessions.
    
    This class provides a context manager for opening and analyzing binary files
    with Ghidra. It handles different file formats (hex, elf, binary) and sets up
    appropriate loaders and memory mappings for MED17 ECU firmware analysis.
    
    The class automatically configures the Ghidra environment and sets up
    memory mappings for binary files to ensure proper analysis of MED17 firmware.
    """
    
    @contextlib.contextmanager
    def open_program(self, file_name: str) -> Generator[Any, None, None]:
        """
        Open a binary file for analysis with Ghidra.
        
        This context manager opens a binary file for analysis, automatically
        determining the appropriate loader based on file extension. For binary
        files, it sets up memory mappings to ensure proper analysis of MED17
        ECU firmware.
        
        Args:
            file_name: The path to the binary file to analyze. Must not be None.
            
        Yields:
            Any: The Ghidra flat API instance for program interaction
            
        Raises:
            AssertionError: If file_name is None
            FileNotFoundError: If the specified file does not exist
        """
        assert file_name is not None, "file_name must not be None"
        base_path = get_path_helper().get_base_path()
        workdir = base_path.joinpath('work')
        if workdir.is_dir():
            shutil.rmtree(workdir)
        env = get_path_helper().get_env()
        ghidra_dir = env.get("GHIDRA_INSTALL_DIR")
        if not ghidra_dir:
            raise ValueError("Ghidra Path not set!")
        #"C:\\Users\\Elias\\Desktop\\Chiptuning-Projects\\Software\\Ghidra"
        #ghidra_dir = "C:\\Users\\Elias\\Desktop\\Chiptuning-Projects\\Software\\Ghidra"
        os.environ["GHIDRA_INSTALL_DIR"] = ghidra_dir
        ext = Path(file_name).suffix
        if ext == ".s19":
            loader = 'ghidra.app.util.opinion.MotorolaHexLoader'
        elif ext == ".hex":
            loader = 'ghidra.app.util.opinion.IntelHexLoader'
        elif ext == ".elf":
            loader = 'ghidra.app.util.opinion.ElfLoader'
        else:
            loader = 'ghidra.app.util.opinion.BinaryLoader'

        with pyhidra.open_program(
                binary_path=file_name,
                project_location=base_path,
                project_name="work",
                analyze=False,
                language='tricore:LE:32:med17',
                compiler='default',
                loader=loader,

        ) as flat_api:
            if loader == 'ghidra.app.util.opinion.BinaryLoader':
                from src.helper import GhidraHelper
                from src.setup_memorymap import SetupMemoryMap
                helper = GhidraHelper(flat_api)
                memory_map = SetupMemoryMap(flat_api, helper)
                memory_map.setup()

            yield flat_api
