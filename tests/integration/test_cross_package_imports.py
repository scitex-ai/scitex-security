"""Runtime cross-package import gate (PS-140 §2).

Each peer is optional at runtime (an extra, or a dev tool), so the test
SKIPS when the peer's ROOT package is absent, and HARD-imports the full
dotted path when it is present: a rename inside an installed peer fails
loudly instead of being skipped.
"""

import importlib

import pytest

CROSS_PACKAGE_IMPORTS = [
    "scitex_dev._cli._completion",
    "scitex_logging",
    "scitex_notification",
]


@pytest.mark.parametrize("module_path", CROSS_PACKAGE_IMPORTS)
def test_cross_package_import_module_loads_successfully(module_path: str) -> None:
    # Arrange
    pytest.importorskip(module_path.split(".")[0])
    # Act
    module = importlib.import_module(module_path)
    # Assert
    assert module is not None
