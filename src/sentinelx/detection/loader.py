"""Load Sigma YAML rule files from a directory into compiled records.

Each ``*.yml`` / ``*.yaml`` file is parsed and compiled with
:class:`~sentinelx.detection.sigma.SigmaCompiler`. Files that fail to compile
are skipped with a logged warning so one bad rule cannot take down the whole
rule set; :meth:`~sentinelx.detection.sigma.SigmaCompiler.compile_file` still
raises :class:`ValueError` for callers that want strict behavior.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from sentinelx.detection.sigma import CompiledSigmaRule, SigmaCompiler

logger = logging.getLogger(__name__)

__all__ = ["CompiledSigmaRule", "load_sigma_rules"]


def load_sigma_rules(directory: str | Path) -> list[CompiledSigmaRule]:
    """Compile every Sigma rule file in *directory*.

    Returns a list of :class:`CompiledSigmaRule` records sorted by file name.
    A missing directory yields an empty list (and a warning); individual
    invalid files are skipped with a warning.
    """
    path = Path(directory)
    if not path.is_dir():
        logger.warning("Sigma rules directory %s does not exist; loading none", path)
        return []
    compiler = SigmaCompiler()
    records: list[CompiledSigmaRule] = []
    files = sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml"))
    for file in files:
        try:
            records.append(compiler.compile_record(_load_yaml_dict(file)))
        except ValueError as exc:
            logger.warning("Skipping invalid Sigma rule file %s: %s", file, exc)
    return records


def _load_yaml_dict(file: Path) -> dict:
    """Read a YAML file and ensure it holds a mapping (raises ValueError)."""
    with open(file, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Sigma file {file} must contain a YAML mapping")
    return data
