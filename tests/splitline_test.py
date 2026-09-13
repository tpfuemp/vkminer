#!/usr/bin/env python3
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Does one stratum line split by more than a second cost the miner its pool?
#
# stratum_recv_line gives the tail of a partial line exactly one second to
# arrive (stratum.c: CURLE_AGAIN, then socket_full(sock, 1)); when it does not,
# the miner declares the connection failed and reconnects. Nothing is wrong
# with the socket in that case, and the cost is not only the reconnect: shares
# found before it are submitted onto the new session, where the pool has never
# issued their job ids.
#
# This asserts the behaviour a working miner has -- the connection survives --
# so it fails while the defect is present and passes once it is not.
#
# Needs no device: the read path is what is under test, so --backend null is
# enough and no share ever has to be found.
#
# Exit 0 pass, 1 fail.

import argparse
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
POOL = os.path.join(HERE, "split_pool.py")

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def save_logs(miner_log, pool_log):
    """Writes both logs where they can be read after a failure.

    The pool's is a temporary file and the miner's is a pipe, so neither
    survives the run that failed, and the only other way to see what the miner
    said is to run the whole case again. The directory is outside the tree."""
    out = tempfile.mkdtemp(prefix="splitline-")
    for name, text in (("miner.log", miner_log), ("pool.log", pool_log)):
        with open(os.path.join(out, name), "w") as fh:
            fh.write(text)
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--miner", required=True)
    p.add_argument("--backend", default="null")
    p.add_argument("--seconds", type=int, default=25)
    # Longer than the one second the tail is given, so a miner that holds the
    # connection held it through an unambiguous gap rather than a marginal one.
    p.add_argument("--gap", default="2.5")
    # Late enough that the session is established and mining, so the split
    # lands on a job and not on the subscribe handshake.
    p.add_argument("--nth", default="5")
    opts = p.parse_args()

    port = free_port()
    f = tempfile.TemporaryFile(mode="w+")
    srv = subprocess.Popen(
        [sys.executable, POOL, opts.gap, opts.nth, "--port", str(port),
         "--drops", "0", "--diff", "0.001", "--job-interval", "4"],
        stdout=f, stderr=subprocess.STDOUT, text=True)
    time.sleep(0.6)

    try:
        miner = subprocess.run(
            [opts.miner, "-a", "sha256d", "--backend", opts.backend,
             "-o", "stratum+tcp://127.0.0.1:%d" % port, "-u", "tester",
             "-p", "x", "--retry-pause", "2",
             "--time-limit", str(opts.seconds)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=opts.seconds + 90)
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=10)
        except subprocess.TimeoutExpired:
            srv.kill()
            srv.wait()

    f.seek(0)
    pool_log = f.read()
    f.close()
    miner_log = ANSI.sub("", miner.stdout)

    # Both of these say the experiment did not happen, which is not a verdict
    # on the miner and must not be reported as one.
    if "SERVER split" not in pool_log:
        print("FAIL the pool never split a message -- there were fewer than "
              "%s of them" % opts.nth)
        print("     logs in " + save_logs(miner_log, pool_log))
        return 1
    if "completed" not in pool_log:
        print("FAIL the pool never finished the split message, so the miner "
              "was never given the chance to read it whole")
        print("     logs in " + save_logs(miner_log, pool_log))
        return 1

    print("     the pool cut message %s and waited %ss" % (opts.nth, opts.gap))
    connects = pool_log.count("SERVER connect #")
    failed = miner_log.count("stratum_recv_line failed")
    resets = miner_log.count("Stratum connection reset")

    if failed or resets:
        print("FAIL the miner dropped a healthy connection over a split line: "
              "%d recv failure(s), %d reset(s), and the pool saw %d "
              "connection(s) where one was enough"
              % (failed, resets, connects))
        print("     logs in " + save_logs(miner_log, pool_log))
        return 1

    print("     %d connection(s), no recv failure, no reset" % connects)
    print("ok   a split line did not cost the connection")
    return 0


if __name__ == "__main__":
    sys.exit(main())
