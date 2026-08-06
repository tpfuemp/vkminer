#!/usr/bin/env python3
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Drives stratum_server.py against a real miner process and asserts on what the
# miner did about being disconnected.
#
# The three ways a pool connection ends, each of which reaches the reconnect
# path by a different route:
#
#   drop      the socket breaks mid-batch. stratum_recv_line fails.
#   silent    the socket stays open and nothing arrives. Only the read timeout
#             can notice, and a miner that waits on a dead pool forever mines
#             nothing while looking healthy.
#   redirect  the pool sends client.reconnect and the miner has to end up
#             somewhere else. This is the only form of failover the miner has --
#             there is no pool list.
#
# Run standalone for a real device:
#   python3 reconnect_test.py --miner ./vkminer --backend vulkan
#
# Exit 0 pass, 1 fail, 77 skip (which ctest reads as a skip).

import argparse
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "stratum_server.py")

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Fail(Exception):
    pass


def run_case(name, opts, server_args, miner_args, seconds, second_server=None):
    """Starts the server(s), runs the miner to its own time limit, returns the
    two logs. The miner is given --time-limit rather than being killed, so that
    a case which ends by hanging fails as a hang instead of being papered over
    by the harness that shot it.

    The servers log to files, not to pipes. Nothing reads a pipe until the miner
    has exited, so a server that outlogs the pipe buffer blocks inside its own
    print, mid-request, and stops answering -- the harness stalls the pool and
    then reports the miner for not reconnecting. That is what a 1.4 GH/s GPU
    did to this test, and what a 5 MH/s rasterizer could never have shown."""
    procs = []
    files = []
    logs = []
    for args in filter(None, [server_args, second_server]):
        f = tempfile.TemporaryFile(mode="w+")
        p = subprocess.Popen([sys.executable, SERVER] + args,
                             stdout=f, stderr=subprocess.STDOUT, text=True)
        procs.append(p)
        files.append(f)
    time.sleep(0.6)

    pin = ["--devices", opts.devices] if opts.devices else []
    miner = subprocess.run(
        [opts.miner, "-a", "sha256d", "--backend", opts.backend,
         "-u", "tester", "-p", "x", "--retry-pause", "2",
         "--time-limit", str(seconds)] + pin + miner_args,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        timeout=seconds + 90)

    for p in procs:
        p.terminate()
    for p, f in zip(procs, files):
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
        f.seek(0)
        logs.append(f.read())
        f.close()

    return ANSI.sub("", miner.stdout), logs, miner.returncode


def check(name, miner_log, rc, wants, min_established):
    """Every case wants the same three things -- a clean exit, no giving up on
    the pool, and the connection back -- so they are asserted in one place."""
    if rc != 0:
        raise Fail(f"{name}: miner exited {rc}, not 0")
    if "terminating workio thread" in miner_log:
        raise Fail(f"{name}: the miner gave up on the pool")

    established = miner_log.count("Stratum connection established")
    if established < min_established:
        raise Fail(f"{name}: {established} connection(s) established, "
                   f"wanted at least {min_established} -- it did not reconnect")

    for want in wants:
        if want not in miner_log:
            raise Fail(f"{name}: expected {want!r} in the miner's log")

    return established


def case_drop(opts):
    port = free_port()
    url = f"stratum+tcp://127.0.0.1:{port}"
    miner_log, (srv,), rc = run_case(
        "drop", opts,
        ["--port", str(port), "--diff", "0.001", "--drop-after", "4",
         "--drops", "2", "--job-interval", "3"],
        ["-o", url], 22)

    n = check("drop", miner_log, rc,
              ["stratum_recv_line failed", "Stratum connection reset"], 3)
    dropped = srv.count("dropped")
    if dropped < 2:
        raise Fail(f"drop: the server only dropped {dropped} time(s)")
    print(f"  drop      {dropped} drops, {n} connections established")
    return miner_log


def case_silent(opts):
    port = free_port()
    url = f"stratum+tcp://127.0.0.1:{port}"
    # -T 5 is the read timeout under test. The server holds the socket open for
    # longer than that and says nothing, so the only thing that can notice is
    # the timeout; with the default 300 s the case would just look slow.
    miner_log, (srv,), rc = run_case(
        "silent", opts,
        # job-interval stays short so the session after the reconnect is a
        # normal one. With nothing arriving there either, the miner would keep
        # timing out and the case would pass on a loop rather than on a
        # recovery.
        ["--port", str(port), "--diff", "0.001", "--drop-after", "4",
         "--drops", "1", "--silent", "12", "--job-interval", "3"],
        ["-o", url, "-T", "5"], 22)

    n = check("silent", miner_log, rc, ["Stratum connection timeout"], 2)
    # And then stopped. A miner that reconnects on a loop also satisfies "it
    # reconnected", so the case is only interesting if the second connection
    # was the last one it needed.
    if n > 3:
        raise Fail(f"silent: {n} connections established -- it reconnected "
                   f"repeatedly rather than recovering")
    print(f"  silent    timed out and reconnected, {n} connections established")
    return miner_log


def case_redirect(opts):
    first, second = free_port(), free_port()
    url = f"stratum+tcp://127.0.0.1:{first}"
    miner_log, (a, b), rc = run_case(
        "redirect", opts,
        ["--port", str(first), "--diff", "0.001", "--drop-after", "4",
         "--drops", "1", "--redirect", str(second)],
        ["-o", url], 18,
        second_server=["--port", str(second), "--diff", "0.001",
                       "--drops", "0", "--job-interval", "3"])

    n = check("redirect", miner_log, rc,
              ["Server requested reconnection to", f":{second}"], 2)
    if "connect #1" not in b:
        raise Fail("redirect: the miner never reached the second server")
    print(f"  redirect  followed client.reconnect to port {second}, "
          f"{n} connections established")
    return miner_log


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--miner", default="./vkminer")
    p.add_argument("--backend", default="null",
                   help="null needs no GPU, so the default runs anywhere")
    p.add_argument("--devices", default="",
                   help="passed through to --devices; a box that enumerates a "
                        "software rasterizer alongside its GPU wants 0")
    p.add_argument("--case", default="all",
                   choices=["all", "drop", "silent", "redirect"])
    opts = p.parse_args()

    if not os.path.exists(opts.miner):
        print(f"SKIP no miner at {opts.miner}")
        return 77

    cases = {"drop": case_drop, "silent": case_silent,
             "redirect": case_redirect}
    todo = cases if opts.case == "all" else {opts.case: cases[opts.case]}

    print(f"reconnect: {len(todo)} case(s) on the {opts.backend} backend")
    logs = {}
    try:
        for name, fn in todo.items():
            logs[name] = fn(opts)
    except Fail as e:
        print(f"FAIL {e}")
        return 1
    except subprocess.TimeoutExpired:
        print("FAIL the miner had to be killed -- it never reached its "
              "own time limit")
        return 1

    # Shares only happen on a backend that computes something. Where they do,
    # the interesting one is a share accepted after the last reconnect: mining
    # resumed, rather than the connection merely coming back up.
    if "drop" in logs:
        after = logs["drop"].rsplit("Stratum connection established", 1)[-1]
        accepted = after.count("Accepted")
        if accepted:
            print(f"  shares    {accepted} accepted after the last reconnect")

    print("ok   reconnect")
    return 0


if __name__ == "__main__":
    sys.exit(main())
