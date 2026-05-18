"""Hand-rolled fakes and swap helpers for scitex-security tests.

Lives under tests/ but is *not* a test module (the name does not match
``test_*.py``), so pytest will not collect it and the PA-307 test-quality
rules do not apply. The PA-306 no-mocks rule still applies; everything
here is a real callable / dataclass — no ``unittest.mock`` symbols.

The module gives the test suite two things:

1.  Real fake callables (``FakeRun``, ``FakeGhRunner``, ``FakeAuthCheck``,
    ``FakeAlertFn``) that record their inputs and return configured
    outputs. Production code receives them through the injection
    parameters added to ``scitex_security.github`` per the no-mocks
    refactor (PA-306).

2.  A ``swap_attrs`` context manager that snapshots module attributes,
    swaps in replacements, then restores the originals in ``finally``.
    Used for ``scitex_security.cli`` tests, where the CLI binds
    collaborators at import time via ``from .github import ...``.
"""

from __future__ import annotations

import subprocess
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, List, Optional


@dataclass
class _CompletedProc:
    """Minimal ``subprocess.CompletedProcess`` look-alike.

    Honest: only the attributes the production code under test reads
    are present (``stdout``, ``stderr``, ``returncode``). Renaming any
    of them in production turns the tests red.
    """

    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


@dataclass
class FakeRun:
    """A real callable that stands in for :func:`subprocess.run`.

    Records every call and either returns a configured
    ``_CompletedProc`` or raises a configured exception.
    """

    stdout: str = ""
    returncode: int = 0
    side_effect: Any = None  # Exception instance or callable
    calls: List[tuple] = field(default_factory=list)

    def __call__(self, args, **kwargs):
        self.calls.append((tuple(args), dict(kwargs)))
        if isinstance(self.side_effect, BaseException):
            raise self.side_effect
        if callable(self.side_effect):
            return self.side_effect(args, **kwargs)
        return _CompletedProc(
            stdout=self.stdout, stderr="", returncode=self.returncode
        )


@dataclass
class FakeGhRunner:
    """A real callable that stands in for ``_run_gh_command``.

    Records every call. Returns ``return_value`` unless ``side_effect``
    is set to an exception, in which case it raises it.
    """

    return_value: str = ""
    side_effect: Optional[BaseException] = None
    calls: List[tuple] = field(default_factory=list)

    def __call__(self, args):
        self.calls.append(tuple(args))
        if isinstance(self.side_effect, BaseException):
            raise self.side_effect
        return self.return_value


@dataclass
class FakeAuthCheck:
    """A real callable that stands in for ``check_gh_auth``.

    Records call count and returns ``return_value``.
    """

    return_value: bool = True
    calls: int = 0

    def __call__(self):
        self.calls += 1
        return self.return_value


@dataclass
class FakeAlertFn:
    """A real callable that stands in for the ``get_*_alerts`` family.

    Records the ``repo`` argument and returns ``return_value``.
    """

    return_value: list = field(default_factory=list)
    calls: List[Optional[str]] = field(default_factory=list)

    def __call__(self, repo=None):
        self.calls.append(repo)
        return self.return_value


@dataclass
class FakeSavePath:
    """A real callable that stands in for ``save_alerts_to_file``.

    Records ``(alerts, output_dir, create_symlink)`` and returns
    ``return_value``.
    """

    return_value: Any = None
    calls: List[tuple] = field(default_factory=list)

    def __call__(self, alerts, output_dir=None, create_symlink=True):
        self.calls.append((alerts, output_dir, create_symlink))
        return self.return_value


@dataclass
class FakeLatestPath:
    """A real callable that stands in for ``get_latest_alerts_file``.

    Records the ``security_dir`` argument. Returns ``return_value``
    unless ``side_effect`` is set, in which case it raises.
    """

    return_value: Any = None
    side_effect: Optional[BaseException] = None
    calls: List[Any] = field(default_factory=list)

    def __call__(self, security_dir=None):
        self.calls.append(security_dir)
        if isinstance(self.side_effect, BaseException):
            raise self.side_effect
        return self.return_value


@dataclass
class FakeFormatReport:
    """A real callable that stands in for ``format_alerts_report``.

    Returns ``return_value`` and records each call's ``alerts`` arg.
    """

    return_value: str = ""
    calls: List[dict] = field(default_factory=list)

    def __call__(self, alerts):
        self.calls.append(alerts)
        return self.return_value


@contextmanager
def swap_attrs(target: Any, **replacements: Any) -> Iterator[None]:
    """Swap module/class attributes for the duration of the block.

    Snapshots the original value of each named attribute on ``target``,
    sets the replacement, then restores the original in ``finally``.
    Pure attribute assignment — no ``monkeypatch``, no ``unittest.mock``.

    Example::

        from scitex_security import cli
        with swap_attrs(cli, check_github_alerts=fake_check):
            ...
    """
    saved: dict = {}
    try:
        for name, value in replacements.items():
            saved[name] = getattr(target, name)
            setattr(target, name, value)
        yield
    finally:
        for name, value in saved.items():
            setattr(target, name, value)


def make_called_process_error(
    returncode: int = 1, cmd: str = "gh", stderr: str = ""
) -> subprocess.CalledProcessError:
    """Construct a real ``subprocess.CalledProcessError`` for fakes."""
    return subprocess.CalledProcessError(returncode, cmd, stderr=stderr)


__all__ = [
    "FakeRun",
    "FakeGhRunner",
    "FakeAuthCheck",
    "FakeAlertFn",
    "FakeSavePath",
    "FakeLatestPath",
    "FakeFormatReport",
    "make_called_process_error",
    "swap_attrs",
]


def _conftest_import_anchor() -> None:
    """No-op anchor so ``tests/_helpers.py`` is reachable from any
    test directory through ``from tests._helpers import ...``."""
    return None
