#!/usr/bin/env python3
"""Enumerate Windows services on the target system."""

import csv
import io

import rich.markup

import pwncat
from pwncat.db import Fact
from pwncat.platform.windows import Windows
from pwncat.modules.enumerate import EnumerateModule


class ServicesData(Fact):
    def __init__(
        self,
        source,
        name: str,
        pid: int,
        start_mode: str,
        status: str,
    ):
        super().__init__(source=source, types=["system.services"])

        self.name: str = name

        self.pid: int = pid

        self.start_mode: str = start_mode

        self.status: str = status

    def title(self, session):
        out = f"[cyan]{rich.markup.escape(self.name)}[/cyan] (PID [blue]{self.pid}[/blue]) currently "
        if self.status == "Running":
            out += f"[bold green]{self.status}[/bold green] "
        else:
            out += f"[red]{self.status}[/red] "
        if self.start_mode == "Auto":
            out += f"([bold yellow]{self.start_mode}[/bold yellow] start)"
        else:
            out += f"([magenta]{self.start_mode}[/magenta] start)"
        return out


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.services"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        proc = session.platform.Popen(
            [
                "wmic.exe",
                "service",
                "get",
                "Caption,ProcessId,State,StartMode",
                "/format:csv",
            ],
            stderr=pwncat.subprocess.DEVNULL,
            stdout=pwncat.subprocess.PIPE,
            text=True,
        )

        # Process the standard output from the command using csv reader
        with proc.stdout as stream:
            # Skip empty lines and read CSV content
            content = stream.read()
            # Filter out empty lines before parsing
            lines = [line for line in content.splitlines() if line.strip()]
            if not lines:
                proc.wait()
                return

            reader = csv.DictReader(io.StringIO("\n".join(lines)))
            for row in reader:
                try:
                    name = row.get("Caption", "").strip()
                    pid = int(row.get("ProcessId", 0))
                    start_mode = row.get("StartMode", "").strip()
                    status = row.get("State", "").strip()

                    if name:  # Only yield if we have a valid service name
                        yield ServicesData(self.name, name, pid, start_mode, status)
                except (ValueError, KeyError):
                    # Skip malformed rows
                    continue

        proc.wait()
