#!/usr/bin/env python3
"""Enumerate mounted drives on the target Windows system."""

import csv
import io

import rich.markup

import pwncat
from pwncat.db import Fact
from pwncat.platform.windows import Windows
from pwncat.modules.enumerate import EnumerateModule


class MountedDrive(Fact):
    def __init__(
        self, source, drive_letter: str, tag: str, drive_name: str, system_name: str
    ):
        super().__init__(source=source, types=["system.drives"])

        self.drive_letter: str = drive_letter
        self.tag: str = tag
        self.drive_name: str = drive_name
        self.system_name: str = system_name

    def title(self, session):
        return f"{rich.markup.escape(self.drive_letter)}:\\ '{rich.markup.escape(self.drive_name)}' mounted from [cyan]{rich.markup.escape(self.system_name)}[/cyan] ([blue]{rich.markup.escape(self.tag)}[/blue])"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.drives"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        proc = session.platform.Popen(
            [
                "wmic",
                "logicaldisk",
                "get",
                "caption,description,volumename,systemname",
                "/format:csv",
            ],
            stderr=pwncat.subprocess.DEVNULL,
            stdout=pwncat.subprocess.PIPE,
            text=True,
        )

        # Process the standard output from the command using csv reader
        with proc.stdout as stream:
            content = stream.read()
            lines = [line for line in content.splitlines() if line.strip()]
            if not lines:
                proc.wait()
                return

            reader = csv.DictReader(io.StringIO("\n".join(lines)))
            for row in reader:
                try:
                    caption = row.get("Caption", "").strip()
                    drive_letter = caption[0] if caption else ""
                    tag = row.get("Description", "").strip()
                    system_name = row.get("SystemName", "").strip()
                    drive_name = row.get("VolumeName", "").strip()

                    if drive_letter:
                        yield MountedDrive(
                            self.name, drive_letter, tag, drive_name, system_name
                        )
                except (ValueError, KeyError, IndexError):
                    continue

        proc.wait()
