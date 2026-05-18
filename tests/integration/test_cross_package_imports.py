"""Runtime cross-package import gate (PS-140 §2)."""

import pytest

CROSS_PACKAGE_IMPORTS = [
    "scitex_dev._cli._completion",
]


@pytest.mark.parametrize("module_path", CROSS_PACKAGE_IMPORTS)
def test_cross_package_import_module_loads_successfully(module_path: str) -> None:
    # Arrange
    target = module_path
    # Act
    module = pytest.importorskip(target)
    # Assert
    assert module is not None
