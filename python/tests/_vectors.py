"""Robust resolution + loading of the cross-language conformance vectors.

The vectors live at ``<repo>/conformance/vectors/*.json``. This test package is
at ``<repo>/python/tests``. We resolve the path relative to this file and also
honor a ``VCP_VECTORS_DIR`` override, so the suite runs regardless of the
current working directory.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

_THIS = Path(__file__).resolve()


def vectors_dir() -> Path:
    override = os.environ.get("VCP_VECTORS_DIR")
    if override:
        p = Path(override).resolve()
        if (p / "canonical-hash.json").is_file():
            return p
    # tests/ -> python/ -> <repo>/ -> conformance/vectors
    candidates = [
        _THIS.parent.parent.parent / "conformance" / "vectors",
        _THIS.parent.parent / "conformance" / "vectors",
    ]
    # Walk upward as a fallback.
    for ancestor in _THIS.parents:
        candidates.append(ancestor / "conformance" / "vectors")
    for c in candidates:
        if (c / "canonical-hash.json").is_file():
            return c.resolve()
    raise FileNotFoundError(
        "could not locate conformance/vectors; set VCP_VECTORS_DIR. "
        f"searched: {[str(c) for c in candidates]}"
    )


def load(name: str) -> dict:
    path = vectors_dir() / name
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)
