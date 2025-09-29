import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


results: List[Dict[str, str]] = [
    {
        'file': '8K2907115AF.bin',
        'a0': '0xd00095f8',
        'a1': '0x80028058',
        'a8': '0xc0009ce0',
        'a9': '0x801af468'
    },
    {
        'file': '03H907309A.bin',
        'a0': '0xd000aa00',
        'a1': '0x8002dc90',
        'a8': '0xd000aa00',
        'a9': '0x8019150c'
    },
    {
        'file': '75Q2G00B.bin',
        'a0': '0xd0008e00',
        'a1': '0x80038610',
        'a8': '0xafe88000',
        'a9': '0x80113c28'
    },
    {
        'file': '6MC4EE85_00005BA7_014_050_116.elf',
        'a0': '0xd0008400',
        'a1': '0x80038d10',
        'a8': '0xafe88000',
        'a9': '0x80052124'
    }
]


def run_single_file_test(expected: Dict[str, str]) -> bool:
    """
    Run `main.py` for a single input file, parse its JSON output, and compare.

    Args:
        expected: Mapping with keys 'file', 'a0', 'a1', 'a8', 'a9'.

    Returns:
        bool: True if the program output matches expected values; False otherwise.

    Raises:
        AssertionError: If input validation fails.
    """
    assert isinstance(expected, dict), "expected must be a dict"
    assert all(k in expected for k in ('file', 'a0', 'a1', 'a8', 'a9')), "expected must include keys 'file','a0','a1','a8','a9'"

    tests_dir: Path = Path(__file__).parent
    file_path: Path = tests_dir / 'files' / expected['file']

    assert file_path.exists(), f"Input file does not exist: {file_path}"

    cmd: List[str] = [sys.executable, '../main.py', '-f', str(file_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    if proc.returncode != 0:
        print(f"test failed: {expected['file']} (exit {proc.returncode})")
        if proc.stderr:
            print(proc.stderr)
        return False

    try:
        output: Any = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"test failed: {expected['file']} (invalid JSON)")
        return False

    if not isinstance(output, dict):
        print(f"test failed: {expected['file']} (output is not an object)")
        return False

    expected_subset: Dict[str, str] = {k: expected[k] for k in ('a0', 'a1', 'a8', 'a9')}
    actual_subset: Dict[str, str] = {k: str(output.get(k)) for k in ('a0', 'a1', 'a8', 'a9')}

    if actual_subset == expected_subset:
        print(f"test passed: {expected['file']}")
        return True

    print(f"test failed: {expected['file']}")
    return False


def main() -> None:
    """
    Execute all defined tests by invoking `main.py` via subprocess per file.

    This script prefixes files with the `tests/files` directory, runs the CLI
    for each case, decodes the JSON output, compares against expected values,
    and prints a concise pass/fail line for each file.
    """
    all_ok: bool = True
    for case in results:
        ok: bool = run_single_file_test(case)
        if not ok:
            all_ok = False

    # Optional non-zero exit to signal CI failure
    if not all_ok:
        sys.exit(1)


if __name__ == '__main__':
    main()
