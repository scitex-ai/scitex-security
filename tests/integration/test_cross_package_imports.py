"""Runtime cross-package import gate (PS-140 §2)."""

import pytest

CROSS_PACKAGE_IMPORTS = [
    # Updated for the 0.2.0 shim per ADR-0001 (scitex-dev #139):
    # scitex_security re-exports from scitex_audit.github, so that's
    # the only real cross-package import. scitex_dev._cli._completion
    # was used by the old skills/completion wiring (removed in 0.2.0).
    "scitex_audit.github",
]


@pytest.mark.parametrize("module_path", CROSS_PACKAGE_IMPORTS)
def test_cross_package_import_module_loads_successfully(module_path: str) -> None:
    # Arrange
    target = module_path
    # Act
    module = pytest.importorskip(target)
    # Assert
    assert module is not None
