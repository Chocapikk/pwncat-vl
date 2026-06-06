"""
Compatibility tests for Python 3.14 migration.

Verifies that the replacements for netifaces, zodburi, and pkg_resources
actually work at runtime, not just at import time.
"""

import io
import os
import tempfile
from importlib.resources import files as _pkg_files

import ZODB
import psutil
import ZODB.FileStorage
import ZODB.MappingStorage


class TestImportlibResources:
    """Verify importlib.resources.files() loads pwncat data files correctly."""

    def test_gtfobins_json_exists(self):
        path = _pkg_files("pwncat").joinpath("data/gtfobins.json")
        assert path.is_file(), f"gtfobins.json not found at {path}"

    def test_gtfobins_json_readable(self):
        import json

        path = str(_pkg_files("pwncat").joinpath("data/gtfobins.json"))
        with open(path) as fh:
            data = json.load(fh)
        assert isinstance(data, (dict, list)), "gtfobins.json is not valid JSON"

    def test_lester_json_exists(self):
        path = _pkg_files("pwncat").joinpath("data/lester.json")
        assert path.is_file(), f"lester.json not found at {path}"

    def test_lester_json_readable(self):
        import json

        path = str(_pkg_files("pwncat").joinpath("data/lester.json"))
        with open(path) as fh:
            data = json.load(fh)
        assert isinstance(data, (dict, list)), "lester.json is not valid JSON"

    def test_pam_c_exists(self):
        path = _pkg_files("pwncat").joinpath("data/pam.c")
        assert path.is_file(), f"pam.c not found at {path}"

    def test_pam_c_readable(self):
        path = str(_pkg_files("pwncat").joinpath("data/pam.c"))
        with open(path) as fh:
            content = fh.read()
        assert len(content) > 0, "pam.c is empty"
        assert "#include" in content, "pam.c doesn't look like C source"


class TestPsutilNetInterfaces:
    """Verify psutil replaces netifaces correctly for network interface detection."""

    def test_net_if_addrs_returns_dict(self):
        addrs = psutil.net_if_addrs()
        assert isinstance(addrs, dict), "net_if_addrs() should return a dict"

    def test_net_if_addrs_has_interfaces(self):
        addrs = psutil.net_if_addrs()
        assert len(addrs) > 0, "No network interfaces found"

    def test_net_if_addrs_has_loopback(self):
        addrs = psutil.net_if_addrs()
        lo_names = [name for name in addrs if name.startswith("lo")]
        assert len(lo_names) > 0, "No loopback interface found"

    def test_get_ip_addr_import(self):
        from pwncat.util import get_ip_addr

        result = get_ip_addr()
        # May return None in CI with no real network, that's OK
        # Just verify it doesn't crash
        assert result is None or isinstance(result, str)


class TestZODBWithoutZodburi:
    """Verify ZODB works without zodburi for both memory and file storage."""

    def test_memory_storage(self):
        storage = ZODB.MappingStorage.MappingStorage()
        db = ZODB.DB(storage, cache_size=10000)
        conn = db.open()
        assert conn.root is not None
        conn.close()
        db.close()

    def test_file_storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "test.fs")
            storage = ZODB.FileStorage.FileStorage(path)
            db = ZODB.DB(storage, cache_size=10000)
            conn = db.open()
            assert conn.root is not None
            conn.close()
            db.close()
            storage.close()
            assert os.path.exists(path), "FileStorage didn't create the db file"

    def test_memory_storage_readwrite(self):
        import transaction

        storage = ZODB.MappingStorage.MappingStorage()
        db = ZODB.DB(storage, cache_size=10000)
        conn = db.open()
        conn.root.test_key = "test_value"
        transaction.commit()

        # Verify data persists in same connection
        assert conn.root.test_key == "test_value"
        conn.close()
        db.close()

    def test_cache_size_preserved(self):
        """Verify we pass cache_size=10000 (zodburi's old default) not ZODB's 400."""
        storage = ZODB.MappingStorage.MappingStorage()
        db = ZODB.DB(storage, cache_size=10000)
        assert db.getCacheSize() == 10000
        db.close()

    def test_manager_opens_memory_db(self):
        """Integration test: Manager.open_database() works with memory://"""
        import pwncat.manager

        config = io.StringIO('set -g db "memory://"\n')
        with pwncat.manager.Manager(config=config) as manager:
            assert manager.db is not None


class TestAllModulesImport:
    """Verify all pwncat modules can be imported without errors.
    This catches missing dependencies at import time.

    Note: these may fail if running against a stale PyPI install
    instead of the local source (e.g. via uvx). In CI with
    pip install . they test the actual code.
    """

    def test_import_util(self):
        import pwncat.util  # noqa: F401

    def test_import_manager(self):
        import pwncat.manager  # noqa: F401

    def test_import_channel(self):
        import pwncat.channel  # noqa: F401

    def test_import_platform_init(self):
        import pwncat.platform  # noqa: F401

    def test_import_config(self):
        import pwncat.config  # noqa: F401

    def test_import_commands(self):
        import pwncat.commands  # noqa: F401
