from __future__ import annotations

from importlib import import_module
from pathlib import Path


_PACKAGE_ROOT = Path(__file__).resolve().parent
_SRC_PACKAGE = _PACKAGE_ROOT.parent / "src" / "aws_cloud_security_misconfiguration_scanner"

__path__ = [str(_SRC_PACKAGE)]

__all__ = ["AwsMisconfigurationScanner", "Finding", "ScanReport"]


def __getattr__(name: str):
	if name in {"Finding", "ScanReport"}:
		module = import_module(f"{__name__}.models")
		return getattr(module, name)
	if name == "AwsMisconfigurationScanner":
		module = import_module(f"{__name__}.scanner")
		return getattr(module, name)
	raise AttributeError(name)
