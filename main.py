# This is a sample Python script.

# Press Alt+Umschalt+X to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


from src.ghidra import Ghidra
import argparse
import json
from typing import Any, Dict
from pathlib import Path

DEFAULT_FILENAME = "EDC17C50.bin"


def main(filename: str) -> None:
    """
    Execute the globals finding workflow and print results as JSON.

    This function opens the specified program file with Ghidra, runs the
    `Find_A0` and `Find_A9` finders, merges their results, and prints the
    aggregated data as JSON to stdout.

    Args:
        filename: Path to the input binary (e.g., ELF/HEX/BIN) to analyze.

    Returns:
        None: The function prints the JSON result to stdout.

    Raises:
        AssertionError: If `filename` is not a string.
        FileNotFoundError: If the specified `filename` does not exist.
    """
    assert isinstance(filename, str), "filename must be a string"
    file_path = Path(filename)
    if not file_path.exists():
        raise FileNotFoundError(f"Input file does not exist: {file_path}")

    ghidra = Ghidra()
    with ghidra.open_program(filename) as flat_api:
        from src.find_a0 import Find_A0
        from src.find_a9 import Find_A9
        from src.helper import GhidraHelper
        helper = GhidraHelper(flat_api)
        find_a0 = Find_A0(flat_api, helper)
        arr: Dict[str, str] = find_a0.find()
        find_a9 = Find_A9(flat_api, helper)
        a9 = find_a9.find()
        arr["a9"] = a9
        print(json.dumps(arr, ensure_ascii=False, indent=2))


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MED17 Globals Finder CLI')
    parser.add_argument('-f', '--file', default=DEFAULT_FILENAME, help='Path to the input file to process')
    args = parser.parse_args()
    main(args.file)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
