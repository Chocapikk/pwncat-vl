#!/usr/bin/env python3
"""Enumerate Windows hotfixes installed on the target system."""

import csv
import io

import rich.markup

import pwncat
from pwncat.db import Fact
from pwncat.platform.windows import Windows
from pwncat.modules.enumerate import EnumerateModule


class HotfixData(Fact):
    def __init__(
        self, source, caption: str, hotfixid: str, tag: str, installed_on: str
    ):
        super().__init__(source=source, types=["system.hotfixes"])

        self.hotfixid: str = hotfixid

        self.tag: str = tag

        self.caption: str = caption

        self.installed_on: str = installed_on

    def title(self, session):
        return f"[cyan]{rich.markup.escape(self.hotfixid)}[/cyan] {rich.markup.escape(self.tag)} installed on [blue]{rich.markup.escape(self.installed_on)}[/blue] ([blue]{rich.markup.escape(self.caption)}[/blue])"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.hotfixes"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        proc = session.platform.Popen(
            [
                "wmic",
                "qfe",
                "get",
                "Caption,HotFixID,Description,InstalledOn",
                "/format:csv",
            ],
            stderr=pwncat.subprocess.DEVNULL,
            stdout=pwncat.subprocess.PIPE,
            text=True,
        )

        # Process the standard output from the command using csv reader
        with proc.stdout as stream:
            content = stream.read()
            # Filter out empty lines before parsing
            lines = [line for line in content.splitlines() if line.strip()]
            if not lines:
                proc.wait()
                return

            reader = csv.DictReader(io.StringIO("\n".join(lines)))
            for row in reader:
                try:
                    caption = row.get("Caption", "").strip()
                    hotfixid = row.get("HotFixID", "").strip()
                    tag = row.get("Description", "").strip()
                    installed_on = row.get("InstalledOn", "").strip()

                    if hotfixid:  # Only yield if we have a valid hotfix ID
                        yield HotfixData(self.name, caption, hotfixid, tag, installed_on)
                except (ValueError, KeyError):
                    # Skip malformed rows
                    continue

        proc.wait()
