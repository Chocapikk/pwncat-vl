# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **ssh.py**: Properly block in `send` to prevent a `TimeoutError` instantly appearing when the size of the upload file exceeds the SSH window size

## [0.6.2] - 2026-04-01

### Added
- **linux.py**: PTY support for busybox/Alpine environments via embedded static `pty_helper` binary. When no standard PTY method (script, python) is available, pwncat auto-detects the remote architecture, uploads a minimal forkpty helper (~30KB) over the existing connection, and execs it to allocate a real PTY. Supports x86_64, aarch64, i686, and armv7l.
- **linux.py**: Busybox environment detection via `busybox --list`
- **linux.py**: `ash` shell prompt support in `PROMPTS` dict
- **linux.py**: `_find_writable_exec_dir()` - prefers `/dev/shm` (RAM) over `/tmp`, with exec permission check to handle `noexec` mounts
- **linux.py**: Graceful fallback when no PTY method works at all (no more crash on minimal systems)
- **pty_helper/**: Static musl-linked C helper and cross-compilation build script for 4 architectures

### Fixed
- **linux.py**: `os.get_terminal_size()` crash when pwncat runs without a local terminal (piped/backgrounded)
- **linux.py**: Setup command echo leak on PTY shells where echo was active before `stty sane` - now sends `stty -echo` before the setup command

## [0.6.1] - 2026-03-24

### Fixed
- **linux.py**: Added `0x0D` (CR) to `CONTROL_CODES` in `LinuxWriter` to prevent binary file corruption on PTY connections, especially with JSP reverse shells ([upstream #155](https://github.com/calebstewart/pwncat/issues/155))
- **linux.py**: Drain channel startup output (e.g. "no job control") before sending commands during shell initialization, fixing hangs and timeouts on connection ([upstream #244](https://github.com/calebstewart/pwncat/issues/244), [#278](https://github.com/calebstewart/pwncat/issues/278), [#299](https://github.com/calebstewart/pwncat/issues/299))
- **sudo/rules.py**: Handle spaces in sudoers runas spec like `(ALL : ALL)` which previously caused the regex to fail, silently dropping all escalation paths ([upstream #253](https://github.com/calebstewart/pwncat/issues/253))
- **connect.py**: Allow `@` in SSH passwords without escaping by using greedy regex backtracking to the last `@` separator ([upstream #281](https://github.com/calebstewart/pwncat/issues/281))
- **manager.py**: Load user config from `$XDG_CONFIG_HOME/pwncat/pwncatrc` with fallback to `$XDG_DATA_HOME` ([upstream #239](https://github.com/calebstewart/pwncat/issues/239))
- **process.py**: Fall back to POSIX `ps` flags when GNU `ps` fails on busybox/constrained environments ([upstream #234](https://github.com/calebstewart/pwncat/issues/234))
- **network.py**: Remove `check=True` from `ip addr` so non-zero exit codes in Docker containers don't suppress network enumeration ([upstream #264](https://github.com/calebstewart/pwncat/issues/264))
- **authorized_key.py**: Enforce `chmod 700` and correct ownership on `.ssh` directory when installing key implants ([upstream #260](https://github.com/calebstewart/pwncat/issues/260))
- **cve_2017_5618.py**: Fixed missing f-prefix on error message string
- **container.py**: Replaced slow `find /` with simple `/.dockerenv` existence check for Docker detection
- **pam.py**: Aligned `CalledProcessError` import to use `pwncat.subprocess` for consistency

### Changed
- **Dockerfile**: Migrated from Alpine to Debian slim for more reliable compilation
- **run-tests.sh**: Fixed typo in Ubuntu container log message

## [0.6.0] - 2026-03-24

### Added
- Python **3.14** support (tested in CI across 3.9 to 3.14)
- 46+ unit tests running without remote targets (compat, core, config, modules, channels, database)
- CI triggers on push/PR to main (was manual-only)
- CI badge and Python version badge in README
- `enable all` / `disable all` commands for check management
- Markdown export support in report generation

### Changed
- Replaced `netifaces` with `psutil` for network interface detection (fixes Python 3.14 C extension build failure) (PR #3 by @raltheo)
- Replaced `zodburi` with direct ZODB storage instantiation (removes `pkg_resources` dependency) (PR #3 by @raltheo)
- Replaced all `pkg_resources.resource_filename()` with `importlib.resources.files()` (standard library, 3.9+) (PR #3 by @raltheo)
- Preserved `cache_size=10000` (zodburi's old default) instead of falling to ZODB's default of 400
- Modernized syntax to Python 3.9+ via pyupgrade (`Type[X]` -> `type[X]`, `socket.error` -> `OSError`)
- Updated CI actions (checkout v2->v4, setup-python v2->v5)
- Fixed Dockerfile entrypoint from `pwncat-cs` to `pwncat-vl`
- Updated README with correct Python versions, badges, dependency changes, and entrypoint name

### Fixed
- **linux.py**: `self.stdout_raw.close` missing parentheses - resource leak on every `detach()`
- **linux.py**: `poll()` never restored `blocking` flag to `True` in finally block - broke all subsequent polls
- **linux.py**: `mkdir` ignored `parents` flag - always passed `-p` regardless
- **linux.py**: Shell injection via unsanitized `name` in `_do_custom_which` - now uses `shlex.quote()`
- **linux.py**: Shell injection via unquoted `cwd` in `Popen` - now uses `shlex.quote()`
- **windows.py**: `in exc` TypeError - `PowershellError` is not a string, fixed to `in str(exc)`
- **windows.py**: `elif "directory":` always True - missing `in msg`, made else branch unreachable
- **channel/__init__.py**: `peek()` crash when `count` is None - `TypeError` on `count -= len(new_data)`
- **manager.py**: Bare `except:` catching `SystemExit`/`KeyboardInterrupt` - changed to `except Exception:`
- **manager.py**: Duplicate `output_thread.join()` call removed
- **manager.py**: Duplicate `COUNTRY_NAME` in x509 certificate subject removed
- **manager.py**: `datetime.utcnow()` deprecated in 3.12 - replaced with `datetime.now(timezone.utc)`
- **ssl_bind.py**: Same `datetime.utcnow()` deprecation fix
- **manager.py**: `open_database()` error message suggested only absolute paths but default config uses relative
- **download.py**: `download_errors` referenced but never defined - now properly collected and reported
- **download.py**: Unused `task` variable from progress bar
- **remember.py**: Undefined `pwncat` in string type hint
- **remember.py**: Unused `json` import in `do_export()`
- **manager.py**: `load_modules` couldn't load custom modules from external paths (PR #2 by @credibleforce)

## [0.5.9] - 2025-07-06

### Added

- New privilege‑escalation module leveraging **CVE‑2025‑32463** (sudo *‑R* NSS‑preload). Detects vulnerable sudo ≥ 1.9.14 < 1.9.17 and drops a root shell via the original *sudo‑chwoot* technique.

## [0.5.8] - 2025-04-06  
### Fixed  
- Silently ignored unsafe `flush of closed file` errors caused by `BufferedWriter`, improving stability during privilege escalation and enumeration modules.  
- Prevented crash when popping non-callable items from session cleanup layers (e.g., `None`).  

### Added  
- New privilege escalation module leveraging **CVE-2021-4034 (PwnKit)** for Linux targets with vulnerable `pkexec`. Automatically detects and exploits the vulnerability if possible.

## [0.5.7] - 2025-04-06
### Added
- New `remember` command to store and retrieve arbitrary key-value pairs during the session (e.g., passwords, tokens, paths). Includes actions: set, get, list, clear, and export.

## [0.5.6] - 2025-04-06
### Fixed
- Fixed recursive downloads showing one progress bar per file. Now a single global progress bar tracks the entire operation.

### Improved
- Recursive downloads now scale better for large directory trees, with clearer output and no redundant logs.

## [0.5.5] - 2025-04-06
### Added
- Added support for recursive directory downloads in the `download` command. Now, the contents
  (and subdirectories) of a remote directory are downloaded into the specified destination
  without duplicating the base directory.
- Prevented infinite recursion by skipping `.` and `..` entries and using a visited set.
- Marked the initial release of the hard fork, introducing these new features and improvements.

### Changed
- Applied code formatting improvements using isort and Black.
- Minor refactoring for improved readability.

## [0.5.4] - 2022-01-27
Bug fix for the `load` command.

### Changed
- Fixed `Manger.load_modules` call in `pwncat/commands/load.py`.

## [0.5.3] - 2022-01-09
Fix for argument parsing bug introduced in `0.5.2` which caused bind/connect
protocols to be automatically interpreted as SSL even when `--ssl` was not
provided.

### Changed
- Fixed parsing of `--ssl` argument ([#231](https://github.com/calebstewart/pwncat/issues/231)).

## [0.5.2] - 2021-12-31
Bug fixes for argument parsing and improved SSH key support thanks to
`paramiko-ng`. Moved to a prettier theme for ReadTheDocs documentation.

### Changed
- Fixed parsing of `--ssl` argument in main entrypoint ([#225](https://github.com/calebstewart/pwncat/issues/225))
- Replaced `paramiko` with `paramiko-ng`
- Utilized Paramiko SSHClient which will also utilize the SSHAgent if available by default and supports key types aside from RSA ([#91](https://github.com/calebstewart/pwncat/issues/91))
- Added implant module `list` command to match documentation ([#224](https://github.com/calebstewart/pwncat/issues/224)).
- Update documentation to clarify implant reconnection
- Fixed `--ssl` argument parsing for bind channels.
- Moved documentation theme to [furo](https://github.com/pradyunsg/furo).
- Added Extras group for documentation depenedencies and removed `docs/requirements.txt`.

## [0.5.1] - 2021-12-07
Minor bug fixes. Mainly typos from changing the package name.

### Changed
- Fixed `--version` switch.
- Fixed readme typos.
### Added
- Read the Docs Configuration File

## [0.5.0] - 2021-11-28
This is a major release mainly due to the name change, and PyPI package addition.
The package has been renamed to `pwncat-cs` and the default entrypoint has also
been renamed to `pwncat-cs`. These changes were made in an effort to deconflict
with [Cytopia pwncat](https://pwncat.org/). Beyond that, some new features were
added as seen in the release notes below.

I've tried to update all references to the old `pwncat` entrypoint, but may have
missed some throughout the documentation or code. Please open an issue if you
notice any old references to the previous name.

It's worth noting that the internal module name is still `pwncat`, as Cytopia
does not implement an importable package (only a command line entrypoint). I may
change this name in the future, but for now it doesn't cause any issues and would
require a major refactor so I'm going to leave it.

### Changed
- Moved dependency management and building to [Poetry](https://python-poetry.org).
- Changed package name to `pwncat-cs` in order to not conflict w/ cytopia/pwncat.
### Added
- Added `ssl-bind` and `ssl-connect` channel protocols for encrypted shells
- Added `ncat`-style ssl arguments to entrypoint and `connect` command
- Added query-string arguments to connection strings for both the entrypoint
  and the `connect` command.
- Added Enumeration States to allow session-bound enumerations
- Added PyPi publishing to GitHub `publish` workflow.
- Added licensing for pwncat (MIT)
- Added background listener API and commands ([#43](https://github.com/calebstewart/pwncat/issues/43))
- Added Windows privilege escalation via BadPotato plugin ([#106](https://github.com/calebstewart/pwncat/issues/106))
### Removed
- Removed `setup.py` and `requirements.txt`

## [0.4.4] - 2021-11-28

### Fixed
- Possible exception due to _pre-registering_ of `session` with `manager`
- Covered edge case in sudo rule parsing for wildcards ([#183](https://github.com/calebstewart/pwncat/issue/183))
- Added fallthrough cases for PTY methods in case of misbehaving binaries (looking at you: `screen`)
- Fixed handling of `socket.getpeername` when `Socket` channel uses IPv6 ([#159](https://github.com/calebstewart/pwncat/issues/159)).
- Fixed verbose logging handler to be __unique__ for every `channel`
- Fixed docstrings in `Command` modules
- Changed docker base image to `python3.9-alpine` to fix python version issues.
- Added logic for calling correct paramiko method when reloading an encrypted SSH privat ekey ([#185](https://github.com/calebstewart/pwncat/issues/185)).
- Forced `Stream.RAW` for all GTFOBins interaction ([#195](https://github.com/calebstewart/pwncat/issues/195)).
- Added custom `which` implementation for linux when `which` is not available ([#193](https://github.com/calebstewart/pwncat/issues/193)).
- Correctly handle `--listen` argument ([#201](https://github.com/calebstewart/pwncat/issues/201))
- Added handler for `OSError` when attempting to detect the running shell ([#179](https://github.com/calebstewart/pwncat/issues/179))
- Added additional check for stat time of file birth field (#208)
- Removed shell compare with ["nologin", "false", "sync", "git-shell"] (#210)
- Added shell compare with not in ["bash", "zsh", "ksh", "fish"] (#210)
### Added
- Added alternatives to `bash` to be used during _shell upgrade_ for a _better shell_
- Added a warning message when a `KeyboardInterrupt` is caught
- Added `--verbose/-V` for argument parser
- Added `OSError` for `bind` protocol to show appropriate error messages
- Contributing guidelines for GitHub maintainers
- Installation instructions for BlackArch
- Added `lpwd` and `lcd` commands to interact with the local working directory ([#218](https://github.com/calebstewart/pwncat/issues/218))
### Changed
- Removed handling of `shell` argument to `Popen` to prevent `euid` problems ([#179](https://github.com/calebstewart/pwncat/issues/179))
- Changed some 'red' warning message color to 'yellow'
- Leak private keys for all users w/ file-read ability as UID=0 ([#181](https://github.com/calebstewart/pwncat/issues/181))
- Raise `PermissionError` when underlying processes terminate unsuccessfully for `LinuxReader` and `LinuxWriter`
- Removed `busybox` and `bruteforce` commands from documentation.

## [0.4.3] - 2021-06-18
Patch fix release. Major fixes are the correction of file IO for LinuxWriters and
improved stability with better exception handling.

### Fixed
- Pinned container base image to alpine 3.13.5 and installed to virtualenv ([#134](https://github.com/calebstewart/pwncat/issues/134))
- Fixed syntax for f-strings in escalation command
- Re-added `readline` import for windows platform after being accidentally removed
- Corrected processing of password in connection string
### Changed
- Changed session tracking so session IDs aren't reused
- Changed zsh prompt to match CWD of other shell prompts
- Improved exception handling throughout framework ([#133](https://github.com/calebstewart/pwncat/issues/133))
- Added explicit permission checks when opening files
- Changed LinuxWriter close routine again to account for needed EOF signals ([#140](https://github.com/calebstewart/pwncat/issues/140))
### Added
- Added better file io test cases

## [0.4.2] - 2021-06-15
Quick patch release due to corrected bug in `ChannelFile` which caused command
output to be empty in some situations.

### Fixed
- Fixed `linux.enumerate.system.network` to work with old and new style `ip`.
- Fixed `ChannelFile.recvinto` which will no longer raise `BlockingIOError` ([#126](https://github.com/calebstewart/pwncat/issues/126), [#131](https://github.com/calebstewart/pwncat/issues/131))
- Fixed sessions command with invalid session ID ([#130](https://github.com/calebstewart/pwncat/issues/130))
- Fixed zsh shell prompt color syntax ([#130](https://github.com/calebstewart/pwncat/issues/130))
### Added
- Added Pull Request template
- Added CONTRIBUTING.md
- Added `--version` option to entrypoint to retrieve pwncat version
- Added `latest` tag to documented install command to prevent dev installs

## [0.4.1] - 2021-06-14
### Added
- Differentiate prompt syntax for standard bash, zsh and sh ([#126](https://github.com/calebstewart/pwncat/issues/126))
- Added `-c=never` to `ip` command in `linux.enumerate.system.network`
  ([#126](https://github.com/calebstewart/pwncat/issues/126))
- Updated Dockerfile to properly build post-v0.4.0 releases ([#125](https://github.com/calebstewart/pwncat/issues/125))
- Added check for `nologin` shell to stop pwncat from accidentally
  closing the session ([#116](https://github.com/calebstewart/pwncat/issues/116))
- Resolved all flake8 errors ([#123](https://github.com/calebstewart/pwncat/issues/123))
- Improved EOF handling for Linux file-writes ([#117](https://github.com/calebstewart/pwncat/issues/117))
