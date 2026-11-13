"""Which files to scan: explicit files always, folders recursively by include/exclude patterns, and globs."""

from __future__ import annotations

import fnmatch
import glob
import os
from dataclasses import dataclass, field

_SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv"}


@dataclass
class Collection:
    files: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)  # inputs that matched nothing


def _key(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def _matches(name: str, patterns: list[str]) -> bool:
    low = name.lower()
    return any(fnmatch.fnmatch(low, p.lower()) for p in patterns)


def collect(inputs: list[str], include: list[str], exclude: list[str], skip_dirs: list[str] | None = None) -> Collection:
    """Files under `inputs`. Folders named in `skip_dirs` (the report folder) are never entered."""
    out = Collection()
    seen: set[str] = set()
    skipped = {_key(d) for d in (skip_dirs or [])}

    def add(path: str) -> None:
        k = _key(path)
        if k not in seen:
            seen.add(k)
            out.files.append(os.path.abspath(path))

    for item in inputs:
        if os.path.isfile(item):
            add(item)
        elif os.path.isdir(item):
            for root, dirs, names in os.walk(item):
                dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and _key(os.path.join(root, d)) not in skipped)
                for name in sorted(names):
                    rel = os.path.relpath(os.path.join(root, name), item)
                    if _matches(name, include) and not (_matches(name, exclude) or _matches(rel, exclude)):
                        add(os.path.join(root, name))
        else:
            matched = [p for p in sorted(glob.glob(item, recursive=True)) if os.path.isfile(p)]
            for p in matched:
                if not _matches(os.path.basename(p), exclude):
                    add(p)
            if not matched:
                out.missing.append(item)
    return out
