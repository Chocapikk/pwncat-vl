#!/usr/bin/env python3
import shlex

from pwncat.db import Fact
from pwncat.subprocess import CalledProcessError
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class ProcessData(Fact):
    """A single process from the `ps` output"""

    def __init__(self, source, uid, username, pid, ppid, argv):
        super().__init__(source=source, types=["system.process"])

        self.uid: int = uid
        self.username: str = username
        self.pid: int = pid
        self.ppid: int = ppid
        self.argv: list[str] = argv

    def title(self, session):
        if self.uid == 0:
            color = "red"
        elif self.uid < 1000:
            color = "blue"
        else:
            color = "magenta"

        # Color our current user differently
        if self.uid == session.platform.getuid():
            color = "lightblue"

        result = f"[{color}]{self.username:>10s}[/{color}] "
        result += f"[magenta]{self.pid:<7d}[/magenta] "
        result += f"[lightblue]{self.ppid:<7d}[/lightblue] "
        result += f"[cyan]{shlex.join(self.argv)}[/cyan]"

        return result


class Module(EnumerateModule):
    """
    Extract the currently running processes. This will parse the
    process information and give you access to the user, parent
    process, command line, etc as with the `ps` command.

    This is only run once unless manually cleared.
    """

    PROVIDES = ["system.process"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session):

        # Try GNU ps first, fall back to POSIX ps for busybox environments
        commands = [
            "ps -eo pid,ppid,uid,user,command --no-header -ww",
            "ps -eo pid,ppid,uid,user,args",
        ]

        proc = None
        for cmd in commands:
            try:
                proc = session.platform.run(
                    cmd, capture_output=True, text=True, check=True,
                )
                if proc.stdout:
                    break
            except (CalledProcessError, FileNotFoundError, PermissionError):
                continue

        if proc is None or not proc.stdout:
            return

        for line in proc.stdout.split("\n"):
            if not line or not line.strip():
                continue

            line = line.strip()

            # Skip header lines that slipped through (POSIX ps fallback)
            if line.startswith("PID") or line.startswith("  PID"):
                continue

            entities = line.split()

            try:
                pid, ppid, uid, username, *argv = entities
            except ValueError:
                continue

            command = " ".join(argv)
            # Kernel threads aren't helpful for us
            if command.startswith("[") and command.endswith("]"):
                continue

            try:
                uid = int(uid)
                pid = int(pid)
                ppid = int(ppid)
            except ValueError:
                continue

            yield ProcessData(self.name, uid, username, pid, ppid, argv)
