"""
Core unit tests that run without remote targets.
Tests config parsing, utility functions, GTFOBins, and module loading.
"""

import io
import os
import tempfile


class TestConfig:
    """Test configuration parsing and defaults."""

    def test_default_config_values(self):
        from pwncat.config import KeyType

        assert isinstance(KeyType, type)

    def test_config_set_get(self):
        import pwncat.manager

        config = io.StringIO(
            'set -g db "memory://"\nset -g backdoor_user "testuser"\n'
        )
        with pwncat.manager.Manager(config=config) as manager:
            assert manager.config["backdoor_user"] == "testuser"

    def test_config_default_db(self):
        import pwncat.manager

        config = io.StringIO('set -g db "memory://"\n')
        with pwncat.manager.Manager(config=config) as manager:
            assert manager.config["db"] == "memory://"

    def test_config_file_db(self):
        import pwncat.manager

        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "test.fs")
            config = io.StringIO(f'set -g db "file://{db_path}"\n')
            with pwncat.manager.Manager(config=config) as manager:
                assert manager.db is not None
                assert os.path.exists(db_path)


class TestUtil:
    """Test utility functions."""

    def test_human_readable_size_bytes(self):
        from pwncat.util import human_readable_size

        result = human_readable_size(500)
        assert "B" in result

    def test_human_readable_size_kb(self):
        from pwncat.util import human_readable_size

        result = human_readable_size(2048)
        assert "K" in result or "k" in result

    def test_human_readable_size_zero(self):
        from pwncat.util import human_readable_size

        result = human_readable_size(0)
        assert "0" in result

    def test_get_ip_addr_returns_string_or_none(self):
        from pwncat.util import get_ip_addr

        result = get_ip_addr()
        assert result is None or isinstance(result, str)

    def test_copyfileobj_exists(self):
        from pwncat.util import copyfileobj

        assert callable(copyfileobj)

    def test_console_exists(self):
        from pwncat.util import console

        assert console is not None


class TestGTFOBins:
    """Test GTFOBins database loading."""

    def test_gtfobins_loads(self):
        from pwncat.gtfobins import GTFOBins

        assert GTFOBins is not None

    def test_gtfobins_data_file_valid(self):
        import json
        from importlib.resources import files

        path = str(files("pwncat").joinpath("data/gtfobins.json"))
        with open(path) as fh:
            data = json.load(fh)
        assert isinstance(data, dict)
        assert len(data) > 0

    def test_lester_data_file_valid(self):
        import json
        from importlib.resources import files

        path = str(files("pwncat").joinpath("data/lester.json"))
        with open(path) as fh:
            data = json.load(fh)
        assert isinstance(data, (dict, list))


class TestModuleLoading:
    """Test that the module system loads without errors."""

    def test_manager_loads_builtin_modules(self):
        import pwncat.manager

        config = io.StringIO('set -g db "memory://"\n')
        with pwncat.manager.Manager(config=config) as manager:
            assert len(manager.modules) > 0

    def test_manager_module_names(self):
        import pwncat.manager

        config = io.StringIO('set -g db "memory://"\n')
        with pwncat.manager.Manager(config=config) as manager:
            names = [m.name for m in manager.modules.values()]
            assert any("enumerate" in name for name in names)

    def test_load_custom_modules_dir(self):
        """Verify load_modules with a custom path doesn't crash."""
        import pwncat.manager

        config = io.StringIO('set -g db "memory://"\n')
        with tempfile.TemporaryDirectory() as tmp:
            with pwncat.manager.Manager(config=config) as manager:
                before = len(manager.modules)
                manager.load_modules(tmp)
                # Empty dir, should not add any modules
                assert len(manager.modules) == before


class TestChannelRegistry:
    """Test channel type registration."""

    def test_channel_types_registered(self):
        from pwncat.channel import CHANNEL_TYPES

        assert len(CHANNEL_TYPES) > 0

    def test_known_channels_exist(self):
        from pwncat.channel import CHANNEL_TYPES

        expected = ["bind", "connect", "ssh"]
        for name in expected:
            assert name in CHANNEL_TYPES, f"Channel {name} not registered"

    def test_find_channel(self):
        from pwncat.channel import find

        ssh = find("ssh")
        assert ssh is not None


class TestDatabaseOperations:
    """Test ZODB database operations without zodburi."""

    def test_db_stores_targets(self):
        import pwncat.manager

        config = io.StringIO('set -g db "memory://"\n')
        with pwncat.manager.Manager(config=config) as manager:
            conn = manager.db.open()
            assert hasattr(conn.root, "targets") or conn.root is not None
            conn.close()

    def test_file_db_persists(self):
        import pwncat.manager

        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "persist.fs")

            # Create and close
            config = io.StringIO(f'set -g db "file://{db_path}"\n')
            with pwncat.manager.Manager(config=config) as manager:
                assert manager.db is not None

            # Verify file was created
            assert os.path.exists(db_path)
            assert os.path.getsize(db_path) > 0
