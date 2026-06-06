"""
Regression test for ``Config.copy`` independence.

The original implementation did a shallow ``copy.copy`` of
``self.values`` (a ``dict[str, dict]``) so mutating a value on the
copy leaked into the original because the inner dicts were shared.
"""

import io

import pytest

import pwncat.manager


@pytest.fixture
def manager():
    with pwncat.manager.Manager(config=io.StringIO('set -g db "memory://"\n')) as m:
        yield m


class TestConfigCopyIsolation:
    def test_set_on_copy_does_not_leak_into_original(self, manager):
        c1 = manager.config
        c2 = c1.copy()

        original = c1["backdoor_user"]
        c2.set("backdoor_user", "EVIL", glob=True)

        assert c1["backdoor_user"] == original
        assert c2["backdoor_user"] == "EVIL"

    def test_locals_isolated(self, manager):
        c1 = manager.config
        c1.locals["some_local"] = "before"

        c2 = c1.copy()
        c2.locals["some_local"] = "after"

        assert c1.locals["some_local"] == "before"
        assert c2.locals["some_local"] == "after"
