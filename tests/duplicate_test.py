#!/usr/bin/env python3
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# A job id is not unique, and a miner that assumes it is submits the same share
# twice.
#
# Pools that switch between coins re-send a job id they have already sent. If
# the miner answers every notify by restarting its nonce range *and* its
# extranonce2 counter, then the second copy of a job rebuilds the same coinbase
# over the same range: it re-finds the nonce it already found and submits it
# again, and the pool rejects it as a duplicate. Nothing else in the tree can
# see this -- the share is valid, it verifies, it is not stale, and the only
# symptom is a reject line from a pool that has to be misbehaving in this
# particular way at the time somebody is watching.
#
# So this pool misbehaves on purpose: job A, then B, then A again with
# byte-identical parameters. It accepts everything, records what it was sent,
# and fails if the miner ever submits the same (job, extranonce2, ntime, nonce)
# twice -- which is exactly the tuple a real pool dedupes on.
#
#   python3 duplicate_test.py --miner ./vkminer --backend vulkan --devices 0
#
# Exit 0 pass, 1 fail, 77 skip (which ctest reads as a skip).

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from stratum_server import (COINB1, COINB2, EXTRANONCE1, EXTRANONCE2_SIZE,
                            MERKLE_BRANCH, NBITS, NTIME, PREVHASH, VERSION)

# Low enough that a device produces shares faster than the phases go by, and it
# has to be: a phase that ends before the miner has submitted anything proves
# nothing, and reads as a pass. The pass criterion below therefore also requires
# that shares actually arrived.
DIFFICULTY = 0.002

# One job id, sent twice, with a second job in between so the miner genuinely
# leaves it and comes back. NTIME is pinned across both copies -- a pool
# re-sending a job sends the job, and a differing ntime would make it a
# different header and hide the thing under test.
JOB_A = "aaaa1111"
JOB_B = "bbbb2222"


class Pool:
    """Accepts every share and remembers all of them."""

    def __init__(self, conn):
        self.conn = conn
        self.buf = b""
        self.submits = []          # (job, xnonce2, ntime, nonce)
        self.lock = threading.Lock()
        self.stop = False

    def send(self, obj):
        self.conn.sendall((json.dumps(obj) + "\n").encode())

    def notify(self, job_id, clean):
        self.send({"id": None, "method": "mining.notify",
                   "params": [job_id, PREVHASH, COINB1, COINB2,
                              MERKLE_BRANCH, VERSION, NBITS, NTIME, clean]})
        print(f"SERVER notify {job_id} clean={clean}", flush=True)

    def serve(self):
        """Reads and answers until told to stop. Runs on its own thread so the
        phase schedule below is wall-clock and not driven by share arrival."""
        while not self.stop:
            self.conn.settimeout(0.2)
            try:
                chunk = self.conn.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            if not chunk:
                return
            self.buf += chunk
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                if line.strip():
                    try:
                        self.handle(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    def handle(self, msg):
        method = msg.get("method")
        mid = msg.get("id")

        if method == "mining.subscribe":
            self.send({"id": mid, "error": None, "result": [
                [["mining.set_difficulty", "1"], ["mining.notify", "1"]],
                EXTRANONCE1, EXTRANONCE2_SIZE]})
        elif method == "mining.authorize":
            self.send({"id": mid, "error": None, "result": True})
            self.send({"id": None, "method": "mining.set_difficulty",
                       "params": [DIFFICULTY]})
        elif method == "mining.submit":
            p = msg.get("params", [""] * 5)
            with self.lock:
                self.submits.append(tuple(p[1:5]))
            self.send({"id": mid, "error": None, "result": True})
        elif mid is not None:
            self.send({"id": mid, "error": None, "result": True})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--miner", required=True)
    ap.add_argument("--backend", default="vulkan")
    ap.add_argument("--devices", default="")
    ap.add_argument("--phase", type=float, default=6.,
                    help="seconds spent on each of the three jobs")
    opts = ap.parse_args()

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)

    seconds = int(opts.phase * 3) + 6
    pin = ["--devices", opts.devices] if opts.devices else []
    log = tempfile.TemporaryFile(mode="w+")
    miner = subprocess.Popen(
        [opts.miner, "-a", "sha256d", "--backend", opts.backend,
         "-o", f"stratum+tcp://127.0.0.1:{port}", "-u", "tester", "-p", "x",
         "--time-limit", str(seconds)] + pin,
        stdout=log, stderr=subprocess.STDOUT, text=True)

    srv.settimeout(30)
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        miner.kill()
        # Almost always no device: this is the only test here that needs one and
        # a pool both. Printed rather than swallowed, because a miner that fails
        # to start for some other reason lands here too.
        log.seek(0)
        print("SKIP: the miner never connected\n" + log.read()[-1500:])
        return 77

    pool = Pool(conn)
    thread = threading.Thread(target=pool.serve, daemon=True)
    thread.start()

    # The three phases. B exists only so that the second A is a job the miner
    # has left and returned to, which is the case that breaks.
    def phase(job_id, clean):
        pool.notify(job_id, clean)
        time.sleep(opts.phase)
        with pool.lock:
            return len(pool.submits)

    time.sleep(1.)                      # let the handshake finish
    first = phase(JOB_A, True)
    phase(JOB_B, True)
    total = phase(JOB_A, True)

    pool.stop = True
    thread.join(timeout=5)
    try:
        miner.wait(timeout=seconds + 60)
    except subprocess.TimeoutExpired:
        miner.kill()
    conn.close()
    srv.close()

    with pool.lock:
        submits = list(pool.submits)

    log.seek(0)
    miner_log = log.read()
    log.close()

    # A device that found nothing cannot have found the same thing twice, so
    # silence here is an inconclusive run and not a pass.
    if first == 0 or total == first:
        print(f"SKIP: too few shares to conclude ({first} in the first phase, "
              f"{total - first} after the job was re-sent). Raise --phase or "
              f"lower the difficulty.")
        print(miner_log[-1500:])
        return 77

    seen, dupes = set(), []
    for s in submits:
        if s in seen:
            dupes.append(s)
        seen.add(s)

    print(f"submitted {len(submits)} share(s), {len(seen)} distinct, "
          f"{total - first} of them after the job id was re-sent")

    if dupes:
        print(f"FAIL: {len(dupes)} duplicate submission(s); the pool would "
              f"reject every one. First: job={dupes[0][0]} "
              f"xnonce2={dupes[0][1]} ntime={dupes[0][2]} nonce={dupes[0][3]}")
        return 1

    print("PASS: no share was submitted twice across a re-sent job id")
    return 0


if __name__ == "__main__":
    sys.exit(main())
