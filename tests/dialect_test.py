#!/usr/bin/env python3
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Drives stratum_server.py in its ProgPoW mode against a real miner process, and
# asserts on what the miner made of a dialect nothing else in this tree speaks.
#
# stratum_kawpow_kat.cpp already proves the parsing, field by field, without a
# socket. What it cannot prove is that the miner reaches that code at all: the
# dialect is chosen from the algorithm before the first packet, the subscribe
# reply has a different shape, the target arrives by a different method, and a
# job carries a height instead of a coinbase. Any of those can be right in
# isolation and unreachable in a running miner.
#
#  progpow       a KawPoW pool, served the way one runs: mining.set_target
#                first, then jobs that state no target of their own.
#  job_target    the other arrangement -- every job states its target -- with
#                the height moving three per job, which on a real device is a
#                new ProgPoW program to compile for each one.
#  set_target    the trap, sprung on the dialect that has no use for the
#                method: a Bitcoin miner is sent a mining.set_target and then
#                an ordinary Bitcoin job, which it must still read as one.
#
# The last case is the one this file exists for. A parser that reads
# mining.set_target as evidence of which dialect the pool speaks is right
# against every pool that never sends the method, so it fails late and rarely.
# Here it is sent to a miner mining sha256d, and the job after it has to become
# work exactly as it would have anyway.
#
# Run standalone for a real device, where shares are reachable too:
#  python3 dialect_test.py --miner ./vkminer --backend vulkan --require-shares
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
SESSION = re.compile(r"SERVER session #\d+ took (\d+) share\(s\)")
# The height as the job lines carry it: "New Block 102, Tx 0, ...". Both the
# comma and the Tx are load-bearing. Without the comma this also matches the
# time-to-find line, where "Block 4s" is four seconds rather than block four.
# Without the Tx it matches the result line a share prints, which states the
# height of the share rather than of a job -- and states zero whenever that
# share's pending entry was overwritten before the pool's reply arrived, which
# a fast device does in bursts. Neither is the pool moving the height.
BLOCK = re.compile(r"Block (\d+), Tx")

# The prefix stratum_server.py hands out in this dialect, and the height its
# first job is at. Duplicated here rather than imported, so that a server that
# starts serving something else is caught rather than followed.
PREFIX = "8007"
HEIGHT = 99


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Fail(Exception):
    pass


# The logs of the case running now, for save_logs() to write out if it fails.
LAST = {}


def save_logs(opts):
    """Writes the failing case's two logs where they can be read afterwards.

    Otherwise they are gone by the time the message is printed -- the pool's is
    a temporary file and the miner's is a pipe -- and the only way to see what
    the miner actually said is to run the whole case again, on a card that is
    not always free to run it."""
    if not LAST:
        return
    for which in ("miner", "pool"):
        path = os.path.join(opts.log_dir, f"dialect-{LAST['name']}-{which}.log")
        try:
            with open(path, "w") as fh:
                fh.write(LAST[which])
        except OSError as ex:
            print(f"     (could not write {path}: {ex})")
            continue
        print(f"     {which} log: {path}")


def run_case(name, opts, server_args, algo, miner_args, seconds):
    """Starts the pool, runs the miner to its own time limit, returns both logs.

    The server logs to a file rather than a pipe for the reason reconnect_test.py
    gives: nothing reads a pipe until the miner has exited, and a pool blocked
    inside its own print has stopped answering the miner it is being used to
    test."""
    # Cleared before the case rather than after it, so that a case killed at the
    # timeout below leaves nothing behind to be read as its own.
    LAST.clear()
    f = tempfile.TemporaryFile(mode="w+")
    srv = subprocess.Popen([sys.executable, SERVER] + server_args,
                           stdout=f, stderr=subprocess.STDOUT, text=True)
    time.sleep(0.6)

    pin = ["--devices", opts.devices] if opts.devices else []
    try:
        miner = subprocess.run(
            [opts.miner, "-a", algo, "--backend", opts.backend,
             "-u", "tester", "-p", "x", "--retry-pause", "2",
             "--time-limit", str(seconds)] + pin + miner_args,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=seconds + 120)
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=10)
        except subprocess.TimeoutExpired:
            srv.kill()
            srv.wait()

    f.seek(0)
    server_log = f.read()
    f.close()
    miner_log = ANSI.sub("", miner.stdout)
    LAST.update(name=name, miner=miner_log, pool=server_log)
    return miner_log, server_log, miner.returncode


def check(name, miner_log, server_log, rc, wants, unwanted):
    if rc != 0:
        raise Fail(f"{name}: miner exited {rc}, not 0")
    if "terminating workio thread" in miner_log:
        raise Fail(f"{name}: the miner gave up on the pool")
    for want in wants:
        if want not in miner_log:
            raise Fail(f"{name}: expected {want!r} in the miner's log")
    for bad in unwanted:
        if bad in miner_log:
            raise Fail(f"{name}: {bad!r} in the miner's log")

    # A malformed share is refused by the pool and counted there, because the
    # miner has no way of knowing it sent one.
    if "badshare" in server_log:
        line = [l for l in server_log.splitlines() if "badshare" in l][0]
        raise Fail(f"{name}: the pool refused a share -- {line}")

    shares = sum(int(n) for n in SESSION.findall(server_log))
    if server_log.count("SERVER notify") < 2:
        raise Fail(f"{name}: the pool sent fewer than two jobs, so the miner "
                   f"was never mining steadily")
    return shares


def case_progpow(opts):
    """A KawPoW pool as one actually runs: the target is pushed once, up front,
    and the jobs after it state none of their own."""
    port = free_port()
    miner_log, server_log, rc = run_case(
        "progpow", opts,
        ["--port", str(port), "--dialect", "progpow", "--drops", "0",
         "--job-interval", "4", "--share-target", str(opts.share_target)],
        "kawpow", ["-o", f"stratum+tcp://127.0.0.1:{port}"], opts.seconds)

    shares = check(
        "progpow", miner_log, server_log, rc,
        ["speaks the ProgPoW stratum",
         f"Stratum nonce prefix 0x{PREFIX}",
         "Pool set target",
         # The height, which arrived as a JSON number in the job and has to
         # reach the work: it is the only thing that says which epoch and which
         # program this is mined with.
         f"Block {HEIGHT}"],
        ["Stratum notify: invalid ProgPoW parameters",
         "Stratum notify: no block height",
         "Stratum subscribe: pool assigned",
         "has no mix hash"])

    print(f"  progpow      job at height {HEIGHT} mined at a pushed target, "
          f"{shares} share(s)")
    return shares


def case_job_target(opts):
    """The other arrangement, and a moving height. Every job states its own
    target, and each is three blocks past the last -- which is a ProgPoW period,
    and on a device a different program to compile for every job."""
    port = free_port()
    miner_log, server_log, rc = run_case(
        "job_target", opts,
        ["--port", str(port), "--dialect", "progpow", "--drops", "0",
         "--job-interval", "4", "--target-in-job", "--height-step", "3",
         "--share-target", str(opts.share_target)],
        "kawpow", ["-o", f"stratum+tcp://127.0.0.1:{port}"], opts.seconds)

    shares = check("job_target", miner_log, server_log, rc,
                   [f"Block {HEIGHT}"],
                   ["Stratum notify: invalid ProgPoW parameters",
                    "Stratum notify: no block height"])

    # Two heights, not one: a miner that took the first job's height for every
    # job after it would mine every later job with the wrong program, and its
    # log would look exactly like this one but for these numbers.
    heights = sorted({int(h) for h in BLOCK.findall(miner_log)})
    if len(heights) < 2:
        raise Fail(f"job_target: the miner only ever saw height "
                   f"{heights or '[none]'} -- the pool moved it every job")
    if heights[0] != HEIGHT:
        raise Fail(f"job_target: mining started at height {heights[0]}, "
                   f"and the pool's first job was at {HEIGHT}")

    print(f"  job_target   heights {heights[0]}..{heights[-1]} through the "
          f"wire, {shares} share(s)")
    return shares


def case_set_target(opts):
    """A mining.set_target sent to a Bitcoin miner, followed by a Bitcoin job.
    The method is not a dialect, and the job after it is read the way the
    algorithm said it would be."""
    port = free_port()
    miner_log, server_log, rc = run_case(
        "set_target", opts,
        ["--port", str(port), "--set-target-first", "--drops", "0",
         "--diff", "0.001", "--job-interval", "4"],
        "sha256d", ["-o", f"stratum+tcp://127.0.0.1:{port}"], 14)

    check("set_target", miner_log, server_log, rc,
          # The target was taken, as a difficulty, because that is what it means
          # in this dialect ...
          ["Pool set target",
           # ... and the job that followed it still became work.
           "Job job0001"],
          # Not read as the other dialect's job, which is what a parser rewired
          # by the method above would have done -- and which fails loudly,
          # because a coinbase is not a 64-character seed hash.
          ["Stratum notify: invalid ProgPoW parameters",
           "speaks the ProgPoW stratum",
           "Stratum notify: no block height"])

    print("  set_target   a target before the job did not change how the job "
          "was read")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--miner", default="./vkminer")
    p.add_argument("--backend", default="null",
                   help="null needs no GPU, so the default runs anywhere -- "
                        "and finds no shares, which is what --require-shares "
                        "is for")
    p.add_argument("--devices", default="",
                   help="passed through to --devices; a box that enumerates a "
                        "software rasterizer alongside its GPU wants 0")
    p.add_argument("--seconds", type=int, default=20,
                   help="how long each KawPoW case mines; a device building a "
                        "dataset for the first time wants more")
    p.add_argument("--share-target", type=float, default=5.0,
                   help="shares per second the pool holds the miner to by "
                        "tightening the target, as a pool's vardiff would")
    p.add_argument("--require-shares", action="store_true",
                   help="fail if no share was submitted; for a run on a device, "
                        "where the submit path is reachable")
    p.add_argument("--log-dir", default=tempfile.gettempdir(),
                   help="where the failing case's miner and pool logs are "
                        "written; a passing run writes nothing")
    p.add_argument("--case", default="all",
                   choices=["all", "progpow", "job_target", "set_target"])
    opts = p.parse_args()

    if not os.path.exists(opts.miner):
        print(f"SKIP no miner at {opts.miner}")
        return 77

    cases = {"progpow": case_progpow, "job_target": case_job_target,
             "set_target": case_set_target}
    todo = cases if opts.case == "all" else {opts.case: cases[opts.case]}

    print(f"dialect: {len(todo)} case(s) on the {opts.backend} backend")
    shares = 0
    try:
        for fn in todo.values():
            shares += fn(opts) or 0
    except Fail as e:
        print(f"FAIL {e}")
        save_logs(opts)
        return 1
    except subprocess.TimeoutExpired:
        print("FAIL the miner had to be killed -- it never reached its "
              "own time limit")
        save_logs(opts)
        return 1

    if opts.require_shares and not shares:
        print("FAIL no share was submitted, and --require-shares says the "
              "submit path was supposed to be reachable")
        return 1

    print("ok   dialect")
    return 0


if __name__ == "__main__":
    sys.exit(main())
