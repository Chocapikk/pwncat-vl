#!/usr/bin/env python3
import re

import rich.markup

from pwncat.db import Fact
from pwncat.subprocess import CalledProcessError
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class PkexecVersion(Fact):
    """
    Version of the installed pkexec binary may be useful for exploitation
    """

    def __init__(self, source, version, output, vulnerable):
        super().__init__(source=source, types=["software.pkexec.version"])

        self.version: str = version
        self.output: str = output
        self.vulnerable: bool = vulnerable

    def title(self, session):
        result = f"[yellow]pkexec[/yellow] version [cyan]{rich.markup.escape(self.version)}[/cyan]"
        if self.vulnerable:
            result += " (may be [red]vulnerable[/red])"
        return result

    def description(self, session):
        result = self.output
        if self.vulnerable:
            result = result.rstrip("\n") + "\n\n"
            result += "This version is likely vulnerable to [red]CVE-2021-4034[/red] (PwnKit)."
        return result


class Module(EnumerateModule):
    """
    Retrieve the version of pkexec on the remote host
    """

    PROVIDES = ["software.pkexec.version"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session):
        """
        Enumerate the currently running version of pkexec
        """

        try:
            result = session.platform.run(
                ["pkexec", "--version"], capture_output=True, check=True,
            )
        except CalledProcessError:
            return

        output = result.stdout.decode("utf-8")
        match = re.search(r"pkexec version\s+([0-9]+\.[0-9]+)", output)

        vulnerable = False
        version_str = "unknown"

        if match:
            version_str = match.group(1)
            # PwnKit vuln: all versions strictly < 0.106
            if version_str.startswith("0.1") and version_str < "0.106":
                vulnerable = True

        yield PkexecVersion(self.name, version_str, output, vulnerable)
