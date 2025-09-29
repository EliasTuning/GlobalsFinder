import re
from array import array
import jpype
from typing import Any, Optional

from src.a9_finders.edc17_vag import EDC17_VAG
from src.a9_finders.med17_bmw import MED17_BMW
from src.a9_finders.med17_vag import MED17_VAG
from src.helper import GhidraHelper


class Find_A9:
    """
    A class for finding and analyzing A9 register patterns in Ghidra.
    
    This class provides functionality to locate specific hex patterns in binary code,
    analyze instruction references, and extract A9 register values. It is specifically
    designed to work with MED17 ECU firmware analysis, focusing on finding and
    analyzing A9 register assignments in decompiled code.
    
    Attributes:
        helper: The GhidraHelper instance for common Ghidra operations
        flat_api: The Ghidra flat API instance for program interaction
    """

    def __init__(self, flat_api: Any, helper: GhidraHelper) -> None:
        """
        Initialize the Find_A9 class with Ghidra API instances.
        
        Args:
            flat_api: The Ghidra flat API instance. Must not be None.
            helper: The GhidraHelper instance for common operations. Must not be None.
            
        Raises:
            AssertionError: If flat_api or helper is None.
        """
        assert flat_api is not None, "flat_api must not be None"
        assert helper is not None, "helper must not be None"
        self.helper = helper
        self.flat_api = flat_api

    def find(self) -> int:
        finders = [
            MED17_VAG(
                flat_api=self.flat_api,
                helper=self.helper
            ),
            EDC17_VAG(
                flat_api=self.flat_api,
                helper=self.helper
            ),
            MED17_BMW(
                flat_api=self.flat_api,
                helper=self.helper
            )
        ]
        for finder in finders:
            try:
                a9 = finder.find()
                return a9
            except:
                pass
