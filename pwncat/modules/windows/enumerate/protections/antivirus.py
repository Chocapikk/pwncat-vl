#!/usr/bin/env python3
"""Enumerate antivirus products installed on the target Windows system."""

import csv
import io

import rich.markup

import pwncat
from pwncat.db import Fact
from pwncat.platform.windows import Windows
from pwncat.modules.enumerate import EnumerateModule


class AntivirusProduct(Fact):
    def __init__(self, source, av_name: str, exe_path: str):
        super().__init__(source=source, types=["protection.antivirus"])

        self.av_name: str = av_name
        self.exe_path: str = exe_path

    def title(self, session):
        return f"Antivirus [red]{rich.markup.escape(self.av_name)}[/red] running from [yellow]{rich.markup.escape(self.exe_path)}[/yellow]"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["protection.antivirus"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        proc = session.platform.Popen(
            [
                "wmic.exe",
                "/Node:localhost",
                "/Namespace:\\\\root\\SecurityCenter2",
                "Path",
                "AntiVirusProduct",
                "Get",
                "displayName,pathToSignedReportingExe",
                "/Format:csv",
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
                    av_name = row.get("displayName", "").strip()
                    exe_path = row.get("pathToSignedReportingExe", "").strip()

                    if av_name:
                        yield AntivirusProduct(self.name, av_name, exe_path)
                except (ValueError, KeyError):
                    continue

        proc.wait()
