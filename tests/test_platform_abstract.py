"""
Regression test for #8.

A ``Platform`` subclass that leaves an abstract method unimplemented cannot
be instantiated, which crashed ``pwncat-vl -m windows`` at session creation
with::

    TypeError: Can't instantiate abstract class Windows without an
    implementation for abstract method 'context_changed'

``context_changed`` had been added as an abstract method on the base
``Platform`` and implemented on ``Linux`` but not on ``Windows``. These
tests guard every concrete platform, so a newly added abstract method must
be implemented on all of them before it can regress a platform again.
"""

import pytest

from pwncat.platform.linux import Linux
from pwncat.platform.windows import Windows


@pytest.mark.parametrize("platform", [Linux, Windows], ids=["linux", "windows"])
def test_platform_has_no_unimplemented_abstract_methods(platform):
    missing = sorted(platform.__abstractmethods__)
    assert missing == [], f"{platform.__name__} is missing: {missing}"


def test_windows_implements_context_changed():
    assert "context_changed" not in Windows.__abstractmethods__
    assert callable(Windows.context_changed)
