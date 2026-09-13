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
# Three things below are load-bearing:
#
#   The sends are guarded. An unguarded sendall takes the whole process down
#   when the miner resets the connection, and ctest reads Python's own exit 1
#   as a verdict -- so a run that judged nothing is recorded as a failure.
#
#   It accepts in a loop and pools the submissions across connections. One
#   accept() under listen(1) leaves every redial completing its handshake into
#   the kernel backlog, read by nobody. A reconnect is also the sharpest form
#   of the case under test: a pool dedupes on the tuple, not on the connection
#   it arrived over.
#
#   The difficulty is an opening bid, not a setting: loose enough for the CPU
#   backend to submit, and vardiff tightens from there. A fixed difficulty that
#   gives lavapipe a share every few seconds gives a fast card hundreds a
#   second, and those are not the same test.
#
#   python3 duplicate_test.py --miner ./vkminer --backend vulkan --devices 0
#   python3 duplicate_test.py --miner ./vkminer --backend cpu
#
# Exit 0 pass, 1 fail, 77 skip (which ctest reads as a skip).

import argparse
import json
import math
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

# What a connection opens at, not what it runs at. Low enough that the CPU
# backend submits inside the first phase -- a phase that ends before the miner
# has submitted anything proves nothing and reads as a pass, which the criterion
# below guards against -- and raised from here by vardiff.
DIFFICULTY = 0.00002

# Shares per second vardiff holds a connection near: enough that the submit path
# is continuously exercised, few enough that a fast card does not spend the run
# flooding. A phase is seconds long, so this is also what decides whether the
# three phases are distinguishable at all.
SHARE_TARGET = 20.

# One job id, sent twice, with a second job in between so the miner genuinely
# leaves it and comes back. NTIME is pinned across both copies -- a pool
# re-sending a job sends the job, and a differing ntime would make it a
# different header and hide the thing under test.
JOB_A = "aaaa1111"
JOB_B = "bbbb2222"


class Session:
    """Every connection the miner opens, and every share sent over any of them.

    The submissions are pooled rather than kept per connection because that is
    how a pool sees them: the same (job, extranonce2, ntime, nonce) arriving on
    a second socket is the same duplicate share, and splitting the record by
    connection would hide exactly the case a redial creates.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.submits = []
        self.conns = []
        # The job the phase schedule is currently on, so a miner that redials
        # mid-phase is put back on the job it left rather than left idle until
        # the next one. That is also the case most likely to produce a repeat.
        self.job_id = None

    def record(self, tup):
        with self.lock:
            self.submits.append(tup)

    def count(self):
        with self.lock:
            return len(self.submits)

    def add(self, pool):
        with self.lock:
            self.conns.append(pool)

    def live(self):
        with self.lock:
            return [c for c in self.conns if not c.gone]

    def all(self):
        with self.lock:
            return list(self.conns)


class Pool:
    """One miner connection. Accepts every share and remembers all of them."""

    # How long a difficulty is given to reach the miner before the rate it
    # produces is believed. A new one applies only to work started after it, so
    # for a moment shares keep arriving at the old rate; measuring inside that
    # window multiplies each raise on top of one that has not taken effect.
    SETTLE = 1.0

    def __init__(self, conn, session, index, share_target):
        self.conn = conn
        self.session = session
        self.index = index
        self.share_target = share_target
        self.buf = b""
        self.diff = DIFFICULTY
        self.shares = 0
        self.stop = False
        self.gone = False
        self.window_start = time.time()
        self.window_shares = 0
        self.settle_until = 0.

    def send(self, obj):
        """Guarded: the phase thread writes here while the miner may already
        have hung up on the read thread. This raising is what used to kill the
        process before it reached a verdict."""
        try:
            self.conn.sendall((json.dumps(obj) + "\n").encode())
        except OSError:
            self.gone = True

    def notify(self, job_id, clean):
        self.send({"id": None, "method": "mining.notify",
                   "params": [job_id, PREVHASH, COINB1, COINB2,
                              MERKLE_BRANCH, VERSION, NBITS, NTIME, clean]})
        print(f"SERVER notify {job_id} clean={clean} conn={self.index}",
              flush=True)

    def set_difficulty(self, diff):
        self.diff = diff
        self.settle_until = time.time() + self.SETTLE
        self.send({"id": None, "method": "mining.set_difficulty",
                   "params": [diff]})
        print(f"SERVER difficulty {diff:g} conn={self.index}", flush=True)

    def retarget(self):
        """Vardiff, so the run is the same test on a software rasterizer and on
        a card two orders of magnitude faster."""
        if not self.share_target:
            return

        now = time.time()
        if now < self.settle_until:
            self.window_start, self.window_shares = now, self.shares
            return
        if self.shares - self.window_shares < 20:
            return

        rate = (self.shares - self.window_shares) / max(now - self.window_start,
                                                        1e-6)
        self.window_start, self.window_shares = now, self.shares
        if rate <= self.share_target:
            return

        # In powers of two, the way a pool difficulty moves, rounded up so an
        # overshoot costs one step rather than a slow climb behind a card that
        # is already flooding.
        step = 2. ** math.ceil(math.log2(rate / self.share_target))
        self.set_difficulty(self.diff * step)
        # A difficulty is read at the next job, and the phases here are seconds
        # apart. Re-send the job already running so it applies now -- clean is
        # false on purpose, because a clean re-send would restart the miner's
        # range and manufacture the very transition the phase schedule exists to
        # control.
        if self.session.job_id:
            self.notify(self.session.job_id, False)

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
                break
            if not chunk:
                break
            self.buf += chunk
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                if line.strip():
                    try:
                        self.handle(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        self.gone = True

    def handle(self, msg):
        method = msg.get("method")
        mid = msg.get("id")

        if method == "mining.subscribe":
            self.send({"id": mid, "error": None, "result": [
                [["mining.set_difficulty", "1"], ["mining.notify", "1"]],
                EXTRANONCE1, EXTRANONCE2_SIZE]})
        elif method == "mining.authorize":
            self.send({"id": mid, "error": None, "result": True})
            self.set_difficulty(DIFFICULTY)
            # A connection that opened mid-run joins the job in progress.
            if self.session.job_id:
                self.notify(self.session.job_id, True)
        elif method == "mining.submit":
            p = msg.get("params", [""] * 5)
            self.session.record(tuple(p[1:5]))
            self.shares += 1
            self.send({"id": mid, "error": None, "result": True})
            self.retarget()
        elif mid is not None:
            self.send({"id": mid, "error": None, "result": True})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--miner", required=True)
    ap.add_argument("--backend", default="vulkan")
    ap.add_argument("--devices", default="")
    ap.add_argument("--phase", type=float, default=6.,
                    help="seconds spent on each of the three jobs")
    ap.add_argument("--share-target", type=float, default=SHARE_TARGET,
                    help="shares per second vardiff aims to hold; 0 disables")
    opts = ap.parse_args()

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    # A backlog and a loop below, so a redial is answered rather than left to
    # complete its handshake in the kernel and be counted as a silent miner.
    srv.listen(8)

    seconds = int(opts.phase * 3) + 6
    pin = ["--devices", opts.devices] if opts.devices else []
    log = tempfile.TemporaryFile(mode="w+")
    miner = subprocess.Popen(
        [opts.miner, "-a", "sha256d", "--backend", opts.backend,
         "-o", f"stratum+tcp://127.0.0.1:{port}", "-u", "tester", "-p", "x",
         "--time-limit", str(seconds)] + pin,
        stdout=log, stderr=subprocess.STDOUT, text=True)

    session = Session()
    first_conn = threading.Event()
    accepting = threading.Event()
    accepting.set()

    def accept_loop():
        srv.settimeout(0.5)
        while accepting.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            pool = Pool(conn, session, len(session.all()) + 1,
                        opts.share_target)
            session.add(pool)
            threading.Thread(target=pool.serve, daemon=True).start()
            print(f"SERVER connection {pool.index}", flush=True)
            first_conn.set()

    accepter = threading.Thread(target=accept_loop, daemon=True)
    accepter.start()

    if not first_conn.wait(30):
        accepting.clear()
        miner.kill()
        # Almost always no device: the null backend produces no shares at all.
        # Printed rather than swallowed, because a miner that fails to start for
        # some other reason lands here too.
        log.seek(0)
        print("SKIP: the miner never connected\n" + log.read()[-1500:])
        srv.close()
        return 77

    # The three phases. B exists only so that the second A is a job the miner
    # has left and returned to, which is the case that breaks.
    def phase(job_id, clean):
        session.job_id = job_id
        for pool in session.live():
            pool.notify(job_id, clean)
        time.sleep(opts.phase)
        return session.count()

    time.sleep(1.)                      # let the handshake finish
    first = phase(JOB_A, True)
    phase(JOB_B, True)
    total = phase(JOB_A, True)

    accepting.clear()
    for pool in session.all():
        pool.stop = True
    try:
        miner.wait(timeout=seconds + 60)
    except subprocess.TimeoutExpired:
        miner.kill()
    for pool in session.all():
        try:
            pool.conn.close()
        except OSError:
            pass
    srv.close()

    submits = list(session.submits)
    conns = session.all()

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
          f"{total - first} of them after the job id was re-sent, over "
          f"{len(conns)} connection(s)")
    if len(conns) > 1:
        # Not a failure here -- this file judges duplicates, and reconnect_test
        # owns the question of why a connection dropped. It is reported because
        # it widens what a pass covers: the shares either side of a redial were
        # compared against each other.
        print(f"NOTE: the miner reconnected {len(conns) - 1} time(s); the "
              f"submissions above are pooled across all of them")

    if dupes:
        print(f"FAIL: {len(dupes)} duplicate submission(s); the pool would "
              f"reject every one. First: job={dupes[0][0]} "
              f"xnonce2={dupes[0][1]} ntime={dupes[0][2]} nonce={dupes[0][3]}")
        return 1

    print("PASS: no share was submitted twice across a re-sent job id")
    return 0


if __name__ == "__main__":
    sys.exit(main())
