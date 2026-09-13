#!/usr/bin/env python3
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Does the miner say so when a pool's seed hash is the wrong epoch?
#
# A ProgPoW notify carries the seed hash and the height as separate fields, and
# a pool that disagrees with itself about which epoch it is on has told the
# miner to build a dataset no share will ever be checked against. stratum.c
# calls that "the first thing anybody would need to see", and gates the line on
# a per-seed dedupe so a disagreement costs one line an epoch, not one a job.
#
# The trap is in the dedupe, and it is why the zero arm is here. All-zeros is
# not a spare value -- it is epoch 0's real seed hash, and exactly what a pool
# sends when it has not filled the field in -- so a dedupe whose sentinel is a
# zeroed buffer goes silent on the single most likely real pool bug. Both arms
# below are a genuine disagreement; only the zero arm collides with that
# sentinel.
#
# The nonzero arm is the control: several notifies, still exactly one line, so
# the dedupe was not traded away to make the zero arm talk.
#
# Needs no device: the check runs in the stratum thread as a notify is parsed,
# so --backend null reaches it and no dataset is ever built.
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
POOL = os.path.join(HERE, "seed_pool.py")

ANSI = re.compile(r"\x1b\[[0-9;]*m")

# Epoch 6 for a 7500-block fork, so neither arm's seed belongs to this height
# and both are a real disagreement rather than a coincidence of epoch 0.
HEIGHT = 46237

# Not the zero seed and not epoch 6's own: the arm has to disagree for the same
# reason the zero arm does, while missing the sentinel it collides with.
NONZERO = "11" * 32


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def save_logs(tag, miner_log, pool_log):
    """Writes both logs where they can be read after a failure.

    The pool's is a temporary file and the miner's is a pipe, so neither
    survives the run that failed. The directory is outside the tree."""
    out = tempfile.mkdtemp(prefix="seed-mismatch-")
    for name, text in ((tag + "-miner.log", miner_log),
                       (tag + "-pool.log", pool_log)):
        with open(os.path.join(out, name), "w") as fh:
            fh.write(text)
    return out


def arm(opts, seed):
    """One pool, one miner, one seed. Returns (complaints, notifies, logs)."""
    port = free_port()
    f = tempfile.TemporaryFile(mode="w+")
    srv = subprocess.Popen(
        [sys.executable, POOL, seed, "--port", str(port),
         "--dialect", "progpow", "--base-height", str(HEIGHT),
         "--drops", "0", "--diff", "1", "--job-interval", "2"],
        stdout=f, stderr=subprocess.STDOUT, text=True)
    time.sleep(0.6)

    try:
        miner = subprocess.run(
            [opts.miner, "-a", "kawpow", "--backend", opts.backend,
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

    return (miner_log.count("wrong dataset"),
            pool_log.count("notify"),
            miner_log, pool_log)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--miner", required=True)
    p.add_argument("--backend", default="null")
    p.add_argument("--seconds", type=int, default=14)
    opts = p.parse_args()

    rc = 0
    for tag, seed in (("zeros", "default"), ("nonzero", NONZERO)):
        shown = "all zeros" if seed == "default" else "0x11.."
        complaints, notifies, miner_log, pool_log = arm(opts, seed)

        # Fewer than two notifies is not a verdict on the miner: the dedupe
        # cannot be shown to hold over a single job, and one complaint would
        # then prove nothing about the case this test exists for.
        if notifies < 2:
            print("FAIL %-8s the pool served %d notify(s), too few to say "
                  "anything about a once-per-epoch line" % (tag, notifies))
            print("     logs in " + save_logs(tag, miner_log, pool_log))
            rc = 1
            continue

        if complaints != 1:
            if complaints == 0:
                why = ("silent -- the seed disagrees with the height and "
                       "nothing said so")
            else:
                why = ("repeating -- the once-per-epoch dedupe is not "
                       "holding")
            print("FAIL %-8s seed %s over %d notify(s): %d complaint(s), %s"
                  % (tag, shown, notifies, complaints, why))
            print("     logs in " + save_logs(tag, miner_log, pool_log))
            rc = 1
            continue

        print("     %-8s seed %-9s %d notify(s), exactly 1 complaint"
              % (tag, shown, notifies))

    if rc == 0:
        print("ok   a seed that is the wrong epoch is reported once, whether "
              "or not it is epoch 0's")
    return rc


if __name__ == "__main__":
    sys.exit(main())
