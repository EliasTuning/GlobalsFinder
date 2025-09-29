"""Path management utilities for the MED17-GlobalsFinder application.

This module provides a singleton `PathHelper` responsible for resolving the
application base path and loading environment variables from a `.env` file
located at the base path. It currently operates standalone and does not
integrate with other classes.

Responsibilities:
- Provide a canonical application base path via `get_base_path()`
- Parse a `.env` file at the base path, if present; otherwise emit an error

Usage:
    from src.path_helper import get_path_helper
    base_path = get_path_helper().get_base_path()

Notes:
- The base path defaults to the repository/application root by walking up from
  this file's location to find the directory that contains `src/`.
- If a `.env` exists at the base path, it will be parsed on first access.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional


class PathHelper:
    """Singleton for application path management and .env parsing.

    This class centralizes path resolution for the application. It computes the
    base path once and exposes it through `get_base_path()`. It also supports
    parsing a `.env` file from the base path. The parsed environment values are
    stored internally and can be retrieved via `get_env()`.

    Attributes:
        _instance: The singleton instance holder.
        _base_path: Cached base path once resolved.
        _env: Parsed key-value pairs from the `.env` file, if any.
        _env_loaded: Flag indicating whether `.env` parsing was attempted.
    """

    _instance: Optional["PathHelper"] = None

    def __init__(self) -> None:
        """Initialize the PathHelper singleton.

        This constructor is private to enforce the singleton pattern.

        Raises:
            AssertionError: If an instance already exists.
        """
        assert PathHelper._instance is None, "PathHelper is a singleton; use get_instance()"
        self._base_path: Optional[Path] = None
        self._env: Dict[str, str] = {}
        self._env_loaded: bool = False

    @staticmethod
    def get_instance() -> "PathHelper":
        """Return the singleton instance of PathHelper.

        Returns:
            PathHelper: The global PathHelper instance.
        """
        if PathHelper._instance is None:
            PathHelper._instance = PathHelper()
        return PathHelper._instance

    def get_base_path(self) -> Path:
        """Return the canonical base path of the application.

        This method determines the base path by locating the directory that
        contains the `src` folder relative to this file. The result is cached
        after the first computation.

        Returns:
            Path: The application base path directory.
        """
        if self._base_path is not None:
            return self._base_path

        current: Path = Path(__file__).resolve()
        assert isinstance(current, Path), "current must be a pathlib.Path"

        # Walk up until we find a directory that contains `src`.
        search_dir: Path = current.parent
        while True:
            candidate_src = search_dir / "src"
            if candidate_src.exists() and candidate_src.is_dir():
                self._base_path = search_dir
                break
            if search_dir.parent == search_dir:
                # Fallback to the directory one level up from this file
                self._base_path = current.parent
                break
            search_dir = search_dir.parent

        assert isinstance(self._base_path, Path), "_base_path must be a pathlib.Path"
        return self._base_path

    def load_env(self) -> Dict[str, str]:
        """Parse `.env` from the base path and return key-value pairs.

        This method reads a `.env` file located at the application base path. If
        the file does not exist, an error message is logged via `print` and an
        empty mapping is returned. Values are parsed with simple `KEY=VALUE`
        semantics; lines that are empty or start with `#` are ignored.

        Returns:
            Dict[str, str]: Mapping of environment keys to values. Empty if the
                `.env` file is not found.
        """
        if self._env_loaded:
            return dict(self._env)

        base_path: Path = self.get_base_path()
        env_path: Path = base_path / ".env"
        if not env_path.exists() or not env_path.is_file():
            print(f"[PathHelper] Error: .env not found at {env_path}")
            self._env_loaded = True
            return {}

        try:
            for raw_line in env_path.read_text(encoding="utf-8").splitlines():
                line: str = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    # Skip malformed lines silently; could also warn
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key:
                    self._env[key] = value
        finally:
            self._env_loaded = True

        return dict(self._env)

    def get_env(self) -> Dict[str, str]:
        """Get parsed environment key-value pairs, loading if necessary.

        Returns:
            Dict[str, str]: Environment mapping; empty if `.env` missing.
        """
        if not self._env_loaded:
            return self.load_env()
        return dict(self._env)


def get_path_helper() -> PathHelper:
    """Module-level accessor for the PathHelper singleton.

    Returns:
        PathHelper: The global PathHelper instance.
    """
    return PathHelper.get_instance()


