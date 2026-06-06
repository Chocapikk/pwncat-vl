#!/usr/bin/env python3
import os
import time

from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    SpinnerColumn,
    TimeRemainingColumn,
)

import pwncat
from pwncat import util
from pwncat.util import console
from pwncat.commands import Complete, Parameter, CommandDefinition


def download_file_base(remote_path, local_path):
    """
    Download a file from remote_path to local_path.
    Returns a tuple (elapsed, error) where elapsed is the time taken (in seconds)
    if successful, and error is a complete error message (or None if successful).
    """
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    start_time = time.time()
    try:
        with open(local_path, "wb") as lf, remote_path.open("rb") as rf:
            lf.writelines(iter(lambda: rf.read(4096), b""))
        elapsed = time.time() - start_time
        return elapsed, None
    except Exception as e:
        return None, f"{remote_path}: {e}"


def download_file_recursive(
    remote_path, local_path, task_id, progress, download_errors,
):
    """
    Download a file in recursive mode.
    Always advances the progress bar (advance=1) regardless of outcome.
    Records any error (with full error message) in download_errors.
    """
    _, error = download_file_base(remote_path, local_path)
    progress.update(task_id, advance=1)
    if error:
        download_errors.append(error)
    return error


def download_file_single(remote_path, local_path):
    """
    Download a single file.
    If successful, prints the file's name, its size, and download time.
    """
    elapsed, error = download_file_base(remote_path, local_path)
    if error:
        console.log(f"[red]Error downloading {remote_path}: {error}[/red]")
    else:
        size = util.human_readable_size(remote_path.stat().st_size)
        console.log(
            f"Downloaded {remote_path} ({size}) in [green]{util.human_readable_delta(elapsed)}[/green] \u2192 {local_path}",
        )
    return error


def get_all_entries(start_dir):
    """
    Walk the directory tree in a single pass using a stack.
    Collect all directories and, from each, the files that are downloadable.

    :param start_dir: A pwncat Path object representing the remote start directory.
    :return: A tuple (directories, files)
    """
    directories = []
    files = []
    download_errors = []
    stack = [start_dir]
    visited = set()
    while stack:
        current = stack.pop()
        rstr = str(current)
        if rstr in visited:
            continue
        visited.add(rstr)
        try:
            entries = list(current.iterdir())
        except Exception as e:
            console.log(f"[red]Error listing directory {current}: {e}[/red]")
            continue

        directories.append(current)
        for entry in entries:
            child_name = os.path.basename(str(entry))
            if child_name in {".", ".."}:
                continue
            try:
                if entry.is_dir():
                    stack.append(entry)
                else:
                    entry.stat()  # verify file accessibility
                    files.append(entry)
            except Exception as e:
                download_errors.append(f"{entry}: {e}")
    return directories, files, download_errors


class Command(CommandDefinition):
    """
    Download a file from the remote host to the local host.
    If --recursive is specified and the source is a directory,
    recursively download its contents into the local destination,
    preserving the remote subdirectory structure.

    In recursive mode, a global progress bar (based on the total number of files)
    is updated for every file processed. At the end, a summary is printed indicating
    the number of files successfully downloaded and the number skipped due to errors,
    followed by the full error messages.
    For a single file download, the file's name, size, and download time are displayed.
    """

    PROG = "download"
    ARGS = {
        "source": Parameter(Complete.REMOTE_FILE),
        "destination": Parameter(Complete.LOCAL_FILE, nargs="?"),
        "--recursive": Parameter(
            Complete.NONE, action="store_true", help="Recursively download directories",
        ),
    }

    def run(self, manager: "pwncat.manager.Manager", args):
        """
        Execute the download command.

        - For a single file: download it and display its name, size, and download time.
        - For directories: first display a spinner while performing a single-pass
          listing of the directory tree, then download each file while preserving
          the directory structure. A global progress bar is updated for every file,
          and a final summary is printed.
        """
        download_errors = []

        try:
            remote = manager.target.platform.Path(args.source)
            if remote.is_dir():
                if not args.recursive:
                    self.parser.error(
                        "Source is a directory. Use --recursive to download it recursively.",
                    )
                if not args.destination:
                    args.destination = os.path.basename(args.source)
                os.makedirs(args.destination, exist_ok=True)

                # Display a spinner progress bar for directory listing.
                console.log(f"Starting single-pass listing for: {remote}")
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[bold cyan]{task.description}"),
                    transient=True,
                ) as listing_progress:
                    listing_progress.add_task(
                        "Listing directories...", total=None,
                    )
                    directories, file_list, errors = get_all_entries(remote)
                    for err in errors:
                        console.log(f"[red]Skipped: {err}[/red]")
                    listing_progress.stop()
                total_files = len(file_list)
                console.log(
                    f"Ready to download: {len(directories)} directories and {total_files} downloadable files.",
                )

                downloaded_count = 0
                skipped_count = 0

                with Progress(
                    TextColumn("[bold cyan]{task.fields[status]}", justify="right"),
                    BarColumn(bar_width=None),
                    "[progress.percentage]{task.percentage:>3.1f}%",
                    "\u2022",
                    TimeRemainingColumn(),
                ) as progress:
                    task_id = progress.add_task(
                        "download",
                        status="Downloading files",
                        total=total_files,
                        start=True,
                    )
                    for file_entry in file_list:
                        relative_path = os.path.relpath(str(file_entry), str(remote))
                        local_path = os.path.join(args.destination, relative_path)
                        error = download_file_recursive(
                            file_entry, local_path, task_id, progress, download_errors,
                        )
                        if error is None:
                            downloaded_count += 1
                        else:
                            skipped_count += 1

                console.log(
                    f"Finished downloading {downloaded_count} files, skipped {skipped_count} files.",
                )
                if download_errors:
                    console.log("The following errors occurred during download:")
                    for err in download_errors:
                        console.log(f"    {err}")
            else:
                if not args.destination:
                    args.destination = os.path.basename(args.source)
                elif os.path.isdir(args.destination):
                    args.destination = os.path.join(
                        args.destination, os.path.basename(args.source),
                    )
                download_file_single(remote, args.destination)
        except (FileNotFoundError, PermissionError, IsADirectoryError) as exc:
            self.parser.error(str(exc))
