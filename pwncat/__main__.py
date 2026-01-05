#!/usr/bin/env python3
"""
pwncat entry point module.

This module provides the main entry point for pwncat, handling command-line
argument parsing and session management.
"""
import sys
import logging
import argparse
import importlib.metadata
from typing import Any, Dict, Optional

from rich import box
from rich.table import Table
from rich.progress import Progress, SpinnerColumn

import pwncat.manager
from pwncat.util import console
from pwncat.channel import ChannelError
from pwncat.modules import ModuleFailed
from pwncat.commands import connect
from pwncat.platform import PlatformError


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser for pwncat."""
    parser = argparse.ArgumentParser(
        description=(
            "Start interactive pwncat session and optionally connect to existing "
            "victim via a known platform and channel type. This entrypoint can also "
            "be used to list known implants on previous targets."
        )
    )
    parser.add_argument(
        "--version", "-v", action="store_true", help="Show version number and exit"
    )
    parser.add_argument(
        "--download-plugins",
        action="store_true",
        help="Pre-download all Windows builtin plugins and exit immediately",
    )
    parser.add_argument(
        "--config",
        "-c",
        type=argparse.FileType("r"),
        default=None,
        help="Custom configuration file (default: ./pwncatrc)",
    )
    parser.add_argument(
        "--ssl", action="store_true", help="Connect or listen with SSL"
    )
    parser.add_argument(
        "--ssl-cert",
        default=None,
        help="Certificate for SSL-encrypted listeners (PEM)",
    )
    parser.add_argument(
        "--ssl-key",
        default=None,
        help="Key for SSL-encrypted listeners (PEM)",
    )
    parser.add_argument(
        "--identity",
        "-i",
        type=argparse.FileType("r"),
        default=None,
        help="Private key for SSH authentication",
    )
    parser.add_argument(
        "--listen",
        "-l",
        action="store_true",
        help="Enable the `bind` protocol (supports netcat-style syntax)",
    )
    parser.add_argument(
        "--platform",
        "-m",
        help="Name of the platform to use (default: linux)",
        default="linux",
    )
    parser.add_argument(
        "--port",
        "-p",
        help="Alternative way to specify port to support netcat-style syntax",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List installed implants with remote connection capability",
    )
    parser.add_argument(
        "connection_string",
        metavar="[protocol://][user[:password]@][host][:port]",
        help="Connection string describing victim",
        nargs="?",
    )
    parser.add_argument(
        "pos_port",
        nargs="?",
        metavar="port",
        help="Alternative port number to support netcat-style syntax",
    )
    parser.add_argument(
        "--verbose",
        "-V",
        action="store_true",
        help="Enable verbose output for the remote commands executed by `pwncat`",
    )
    return parser


def download_plugins(manager: "pwncat.manager.Manager") -> None:
    """Pre-download all Windows builtin plugins."""
    import pwncat.platform

    for plugin_info in pwncat.platform.Windows.PLUGIN_INFO:
        with pwncat.platform.Windows.open_plugin(manager, plugin_info.provides[0]):
            pass


def list_implants(manager: "pwncat.manager.Manager") -> None:
    """List all installed implants with remote connection capability."""
    db = manager.db.open()

    table = Table(
        "ID",
        "Address",
        "Platform",
        "Implant",
        "User",
        box=box.MINIMAL_DOUBLE_HEAD,
    )

    for target in db.root.targets:
        # Collect users
        users = {fact.id: fact for fact in target.facts if "user" in fact.types}

        # Collect implants and add to table
        for fact in target.facts:
            if "implant.remote" in fact.types:
                table.add_row(
                    target.guid,
                    target.public_address[0],
                    target.platform,
                    fact.source,
                    users[fact.uid].name,
                )

    if not table.rows:
        console.log("[red]error[/red]: no remote implants found")
    else:
        console.print(table)


def parse_connection_string(
    connection_string: str, args: argparse.Namespace
) -> Dict[str, Any]:
    """Parse the connection string and return query arguments."""
    query_args: Dict[str, Any] = {
        "protocol": None,
        "user": None,
        "password": None,
        "host": None,
        "port": None,
        "platform": args.platform,
        "identity": args.identity,
        "certfile": args.ssl_cert,
        "keyfile": args.ssl_key,
        "ssl": args.ssl,
    }
    querystring = None

    if connection_string:
        m = connect.Command.CONNECTION_PATTERN.match(connection_string)
        query_args["protocol"] = m.group("protocol")
        query_args["user"] = m.group("user")
        query_args["password"] = m.group("password")
        query_args["host"] = m.group("host")
        query_args["port"] = m.group("port")
        querystring = m.group("querystring")

        if query_args["protocol"] is not None:
            query_args["protocol"] = query_args["protocol"].removesuffix("://")

        if query_args["password"] is not None:
            query_args["password"] = query_args["password"].removeprefix(":")

    # Parse querystring parameters
    if querystring is not None:
        for arg in querystring.split("&"):
            if "=" not in arg:
                continue

            key, *value = arg.split("=")

            if key in query_args and query_args[key] is not None:
                console.log(f"[red]error[/red]: multiple values for {key}")
                return None

            query_args[key] = "=".join(value)

    return query_args


def validate_connection_args(
    query_args: Dict[str, Any], args: argparse.Namespace
) -> Optional[str]:
    """
    Validate connection arguments and return error message if invalid.

    Returns None if validation passes, or an error message string if it fails.
    """
    # Normalize empty host
    if query_args["host"] == "":
        query_args["host"] = None

    # Check listen flag compatibility
    if query_args["protocol"] is not None and args.listen:
        return "--listen is not compatible with an explicit connection string"
    elif args.listen:
        query_args["protocol"] = "bind"

    # Check SSL cert/key pair
    if (query_args["certfile"] is None) != (query_args["keyfile"] is None):
        return "both a ssl certificate and key file are required"

    if query_args["certfile"] is not None or query_args["keyfile"] is not None:
        query_args["ssl"] = True

    # Check SSL protocol compatibility
    if query_args["protocol"] not in (None, "bind", "connect") and query_args.get(
        "ssl"
    ):
        return f"--ssl is incompatible with an [yellow]{query_args['protocol']}[/yellow] protocol"
    elif query_args["protocol"] is not None and query_args.get("ssl"):
        query_args["protocol"] = "ssl-" + query_args["protocol"]

    # Check for multiple port specifications
    port_count = sum(
        [
            query_args["port"] is not None,
            args.port is not None,
            args.pos_port is not None,
        ]
    )
    if port_count > 1:
        return "multiple ports specified"

    # Set port from alternative sources
    if args.port is not None:
        query_args["port"] = args.port
    if args.pos_port is not None:
        query_args["port"] = args.pos_port

    # Validate and parse port number
    if query_args["port"] is not None:
        try:
            query_args["port"] = int(query_args["port"].lstrip(":"))
        except ValueError:
            return f"{query_args['port'].lstrip(':')}: invalid port number"

    return None


def try_reconnect_via_implants(
    manager: "pwncat.manager.Manager", query_args: Dict[str, Any]
) -> Optional[Any]:
    """
    Attempt to reconnect to a target via installed implants.

    Returns the used implant if successful, None otherwise.
    """
    db = manager.db.open()
    implants = []

    # Locate all installed implants for matching target
    for target in db.root.targets:
        if (
            target.guid != query_args["host"]
            and target.public_address[0] != query_args["host"]
        ):
            continue

        # Collect users
        users = {fact.id: fact for fact in target.facts if "user" in fact.types}

        # Collect implants
        for fact in target.facts:
            if "implant.remote" in fact.types:
                implants.append((target, users[fact.uid], fact))

    # Try each implant
    for target, implant_user, implant in implants:
        # Check user match
        if query_args["user"] is not None and implant_user.name != query_args["user"]:
            continue
        # Check platform match
        if (
            query_args["platform"] is not None
            and target.platform != query_args["platform"]
        ):
            continue

        manager.log(f"trigger implant: [cyan]{implant.source}[/cyan]")

        try:
            session = implant.trigger(manager, target)
            manager.target = session
            return implant
        except ModuleFailed:
            db.transaction_manager.commit()
            continue

    return None


def handle_connection(
    manager: "pwncat.manager.Manager", args: argparse.Namespace
) -> None:
    """Handle the connection logic based on parsed arguments."""
    query_args = parse_connection_string(args.connection_string, args)
    if query_args is None:
        return

    error = validate_connection_args(query_args, args)
    if error:
        console.log(f"[red]error[/red]: {error}")
        return

    used_implant = None

    # Attempt to reconnect via installed implants
    if (
        query_args["protocol"] is None
        and query_args["password"] is None
        and query_args["port"] is None
        and args.identity is None
    ):
        used_implant = try_reconnect_via_implants(manager, query_args)

    if manager.target is not None:
        manager.target.log(f"connected via {used_implant.title(manager.target)}")
    else:
        try:
            manager.create_session(**query_args)
        except (ChannelError, PlatformError) as exc:
            manager.log(f"connection failed: {exc}")
        except KeyboardInterrupt:
            sys.stdout.write("\b\b\r")
            manager.log("[yellow]warning[/yellow]: cancelled by user")


def close_sessions(manager: "pwncat.manager.Manager") -> None:
    """Close all active sessions with progress indication."""
    if not manager.sessions:
        return

    with Progress(
        SpinnerColumn(),
        "closing sessions",
        "•",
        "{task.fields[status]}",
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("task", status="...")

        session_ids = list(manager.sessions.keys())

        for session_id in session_ids:
            progress.update(task, status=str(manager.sessions[session_id].platform))
            manager.sessions[session_id].close()

        progress.update(task, status="done!", completed=100)


def should_handle_connection(args: argparse.Namespace) -> bool:
    """Check if connection handling should be performed based on arguments."""
    return (
        args.connection_string is not None
        or args.pos_port is not None
        or args.port is not None
        or args.listen
        or args.identity is not None
    )


def main() -> None:
    """Main entry point for pwncat."""
    logging.getLogger().setLevel(logging.INFO)

    parser = create_argument_parser()
    args = parser.parse_args()

    # Print the version number and exit
    if args.version:
        print(importlib.metadata.version("pwncat-vl"))
        return

    # Create the session manager
    with pwncat.manager.Manager(args.config) as manager:
        if args.verbose:
            manager.config.set("verbose", True, True)

        if args.download_plugins:
            download_plugins(manager)
            return

        if args.list:
            list_implants(manager)
            return

        console.log("Welcome to [red]pwncat[/red] 🐈!")

        if should_handle_connection(args):
            handle_connection(manager, args)

        manager.interactive()
        close_sessions(manager)


if __name__ == "__main__":
    main()
    sys.exit(0)
