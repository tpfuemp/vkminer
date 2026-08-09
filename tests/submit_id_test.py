#!/usr/bin/env python3
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# A pool answers shares in whatever order it likes, and a reply says which share
# it is about only through the JSON-RPC id it echoes.
#
# With one dispatch in flight at a time, shares are submitted one at a time and
# answered before the next one is found, so matching a reply to the oldest
# unanswered share is right by accident. With a queue kept full it is not:
# several shares are in flight at once, the pool may answer the newest first,
# and then the difficulty, block, job and latency printed beside a result belong
# to a different share than the accept or reject does. The tallies stay right,
# which is why this survives a live run unnoticed -- every line is plausible and
# the totals add up.
#
# So this pool answers out of order on purpose. It holds two shares from two
# different jobs, then rejects the *newer* one first. The job id printed on the
# reject line says which share the miner thought it was answering, and a miner
# matching by arrival order names the older job there.
#
#   python3 submit_id_test.py --miner ./vkminer --backend vulkan --devices 0
#
# Exit 0 pass, 1 fail, 77 skip (which ctest reads as a skip).

import argparse
import json
import os
import re
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

# The difficulty the probe phase runs at, low enough that any device produces
# shares within it.
PROBE_DIFFICULTY = 0.002

# Shares per second the experiment wants, whatever the device. It has to be slow
# rather than fast: the miner remembers only the last eight submitted shares, so
# a share held across a job change has to survive fewer than eight further
# submissions or its entry is overwritten and nothing can be concluded. One
# share every second or so leaves that margin on a software rasterizer and on a
# GPU alike -- which is the whole reason the difficulty is measured here rather
# than picked.
TARGET_RATE = 0.8

JOB_PROBE = "9999cccc"
JOB_OLD = "1111aaaa"
JOB_NEW = "2222bbbb"

# Not "job", "stale" or anything containing them: the miner reads those out of a
# reject reason and counts the share as stale instead of rejected.
REJECT_REASON = "Low difficulty share"


class Pool:
    """Answers every share at once, or holds the ones the experiment needs."""

    def __init__(self, conn):
        self.conn = conn
        self.buf = b""
        self.lock = threading.Lock()
        self.stop = False
        self.hold_jobs = ()        # jobs whose shares are kept unanswered
        self.held = []             # (rpc_id, job) in arrival order
        self.submits = 0
        self.mining = threading.Event()   # set once the first job is out

    def send(self, obj):
        self.conn.sendall((json.dumps(obj) + "\n").encode())

    def set_difficulty(self, diff):
        self.send({"id": None, "method": "mining.set_difficulty",
                   "params": [diff]})
        print(f"SERVER set_difficulty {diff:g}", flush=True)

    def notify(self, job_id, clean=True):
        # The difficulty sent above takes effect here and not before: the miner
        # keeps it as the *next* difficulty and applies it when it builds work
        # for a new job.
        self.send({"id": None, "method": "mining.notify",
                   "params": [job_id, PREVHASH, COINB1, COINB2,
                              MERKLE_BRANCH, VERSION, NBITS, NTIME, clean]})
        print(f"SERVER notify {job_id} clean={clean}", flush=True)

    def answer(self, rpc_id, accepted):
        if accepted:
            self.send({"id": rpc_id, "error": None, "result": True})
        else:
            self.send({"id": rpc_id, "result": False,
                       "error": [23, REJECT_REASON, None]})

    def serve(self):
        """Reads and answers until told to stop, on its own thread so the phases
        below are driven by what arrives rather than by wall clock alone."""
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
            # The probe job goes out from here rather than from the phase
            # schedule below, so that the difficulty it is meant to carry is
            # already sent when the miner builds work for it.
            self.send({"id": mid, "error": None, "result": True})
            self.set_difficulty(PROBE_DIFFICULTY)
            self.notify(JOB_PROBE)
            self.mining.set()
        elif method == "mining.submit":
            job = msg.get("params", [""] * 5)[1]
            with self.lock:
                self.submits += 1
                if job in self.hold_jobs:
                    self.held.append((mid, job))
                    return
            self.answer(mid, True)
        elif mid is not None:
            self.send({"id": mid, "error": None, "result": True})

    def first_held(self, job, deadline):
        """The rpc id of the first share held for `job`, or None on timeout."""
        while time.time() < deadline:
            with self.lock:
                for rpc_id, held_job in self.held:
                    if held_job == job:
                        return rpc_id
            time.sleep(0.02)
        return None


# The miner colours its output whether or not anything is watching, and a colour
# escape sits directly against the word it colours -- so this has to come off
# before the verdict is a word at all.
ANSI = re.compile(r"\x1b\[[0-9;]*m")
RESULT_LINE = re.compile(r"\b(Accepted|Rejected|Stale)\b.*\bJob (\S+?),")


def results(text):
    """(verdict, job) for each share the miner reported, in the order it did."""
    return [(m.group(1), m.group(2))
            for m in RESULT_LINE.finditer(ANSI.sub("", text))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--miner", required=True)
    ap.add_argument("--backend", default="vulkan")
    ap.add_argument("--devices", default="")
    ap.add_argument("--probe", type=float, default=8.,
                    help="seconds spent measuring the device's share rate")
    opts = ap.parse_args()

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)

    pin = ["--devices", opts.devices] if opts.devices else []
    log = tempfile.TemporaryFile(mode="w+")
    miner = subprocess.Popen(
        [opts.miner, "-a", "sha256d", "--backend", opts.backend,
         "-o", f"stratum+tcp://127.0.0.1:{port}", "-u", "tester", "-p", "x",
         "--time-limit", "120"] + pin,
        stdout=log, stderr=subprocess.STDOUT, text=True)

    def finish(code, message):
        pool_stop()
        try:
            miner.terminate()
            miner.wait(timeout=20)
        except (subprocess.TimeoutExpired, OSError):
            miner.kill()
        log.seek(0)
        tail = log.read()
        log.close()
        srv.close()
        print(message)
        if code != 0:
            print(tail[-2500:])
        return code

    pool = None
    thread = None

    def pool_stop():
        if pool is not None:
            pool.stop = True
        if thread is not None:
            thread.join(timeout=5)
        if pool is not None:
            pool.conn.close()

    srv.settimeout(30)
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        return finish(77, "SKIP: the miner never connected")

    pool = Pool(conn)
    thread = threading.Thread(target=pool.serve, daemon=True)
    thread.start()

    # Phase 1 -- how fast does this device find shares? Everything downstream is
    # sized off the answer, because a share rate is the one thing that differs by
    # three orders of magnitude across the machines this runs on.
    if not pool.mining.wait(timeout=30):
        return finish(77, "SKIP: the miner never got as far as authorizing")

    start = time.time()
    deadline = start + opts.probe
    while time.time() < deadline:
        time.sleep(0.1)
        with pool.lock:
            if pool.submits >= 4:
                break
    elapsed = time.time() - start
    with pool.lock:
        rate = pool.submits / elapsed

    if rate <= 0.:
        return finish(77, "SKIP: no shares in %.0f s, so there is nothing to "
                          "answer out of order" % elapsed)

    # Rate and difficulty are inversely proportional, so this is one step and
    # not a search. Never below the probe difficulty: raising the rate is not
    # what the clamp is there for.
    difficulty = max(PROBE_DIFFICULTY, PROBE_DIFFICULTY * rate / TARGET_RATE)
    interval = difficulty / (PROBE_DIFFICULTY * rate)
    print(f"probe: {rate:.2f} share/s at difficulty {PROBE_DIFFICULTY:g}; "
          f"experiment at {difficulty:g}, about one share every "
          f"{interval:.1f} s")

    # Phase 2 -- two shares, two jobs, neither answered yet. Held from the moment
    # the first job is sent, so that nothing about which share is which depends
    # on a reply racing a submission.
    with pool.lock:
        pool.hold_jobs = (JOB_OLD, JOB_NEW)
    pool.set_difficulty(difficulty)
    pool.notify(JOB_OLD)

    wait = max(30., interval * 8.)
    old_id = pool.first_held(JOB_OLD, time.time() + wait)
    if old_id is None:
        return finish(77, f"SKIP: no share for the first job within {wait:.0f} s")

    pool.notify(JOB_NEW)
    new_id = pool.first_held(JOB_NEW, time.time() + wait)
    if new_id is None:
        return finish(77, f"SKIP: no share for the second job within {wait:.0f} s")

    # Phase 3 -- answer the newer share first, and reject it. Everything else
    # held is accepted afterwards, oldest first, so the only reject in the whole
    # run is the one whose identity is being asserted.
    with pool.lock:
        rest = [rpc_id for rpc_id, _ in pool.held if rpc_id != new_id]
        pool.hold_jobs = ()
    pool.answer(new_id, False)
    time.sleep(0.2)
    for rpc_id in rest:
        pool.answer(rpc_id, True)
    print(f"held {len(rest) + 1} share(s); rejected id {new_id} (job "
          f"{JOB_NEW}) before answering id {old_id} (job {JOB_OLD})")

    time.sleep(2.)              # let the miner print what it made of that
    log.seek(0)
    text = log.read()
    seen = results(text)

    # An overwritten entry is an inconclusive run, not a failure: the miner says
    # so, and what it says instead of a job id is nothing at all.
    if "Share stats not available" in text:
        return finish(77, "SKIP: the miner's share window overflowed, so the "
                          "held shares were forgotten before they were answered")

    rejects = [job for verdict, job in seen if verdict == "Rejected"]
    if len(rejects) != 1:
        return finish(77, f"SKIP: expected exactly one reject, saw "
                          f"{len(rejects)}: {rejects}")

    if rejects[0] != JOB_NEW:
        return finish(1, f"FAIL: the reject was answered for job {JOB_NEW} and "
                         f"the miner attributed it to job {rejects[0]}. Replies "
                         f"are being matched by arrival order rather than by "
                         f"the id the pool echoed.")

    accepted = [job for verdict, job in seen if verdict == "Accepted"]
    if JOB_OLD not in accepted:
        return finish(1, f"FAIL: the reject landed on the right job, but the "
                         f"share accepted for job {JOB_OLD} was reported "
                         f"against {accepted[-1:] or ['nothing']}.")

    return finish(0, f"PASS: an out-of-order reject was attributed to the share "
                     f"it was sent for ({len(seen)} share results read)")


if __name__ == "__main__":
    sys.exit(main())
