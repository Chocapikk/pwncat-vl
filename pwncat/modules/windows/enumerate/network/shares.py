#!/usr/bin/env python3
"""
Enumerate network shares on the target Windows system.

Note: We could parse the share `type` to determine access to non-default network shares.
See: https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/getaccessmask-method-in-class-win32-share
"""

import csv
import io

import rich.markup

import pwncat
from pwncat.db import Fact
from pwncat.platform.windows import Windows
from pwncat.modules.enumerate import EnumerateModule


class NetworkShare(Fact):
    def __init__(
        self,
        source,
        name: str,
        caption: str,
        tag: str,
        install_date: str,
        path: str,
        status: str,
        share_type: str,
    ):
        super().__init__(source=source, types=["network.shares"])

        self.name: str = name
        self.install_date: str = install_date
        self.tag: str = tag
        self.share_type: str = share_type
        self.path: str = path
        self.status: str = status
        self.caption: str = caption

    def title(self, session):
        out = f"[dim][cyan]{rich.markup.escape(self.name)}[/cyan] {rich.markup.escape(self.tag)}"
        if self.path:
            out += f" at [blue]{rich.markup.escape(self.path)} [/blue][/dim]"
        else:
            out += "[/dim]"
        if self.tag.lower() not in ["remote admin", "default share", "remote ipc"]:
            out = (
                out.replace("[dim]", "[bold]")
                .replace("[/dim]", "[/bold]")
                .replace("[cyan]", "[green]")
                .replace("[/cyan]", "[/green]")
            )
        return out


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["network.shares"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        proc = session.platform.Popen(
            [
                "wmic.exe",
                "share",
                "get",
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
                    caption = row.get("Caption", "").strip()
                    tag = row.get("Description", "").strip()
                    install_date = row.get("InstallDate", "").strip()
                    name = row.get("Name", "").strip()
                    path = row.get("Path", "").strip()
                    status = row.get("Status", "").strip()
                    share_type = row.get("Type", "").strip()

                    if name:
                        yield NetworkShare(
                            self.name,
                            caption=caption,
                            tag=tag,
                            install_date=install_date,
                            name=name,
                            path=path,
                            status=status,
                            share_type=share_type,
                        )
                except (ValueError, KeyError):
                    continue

        proc.wait()
