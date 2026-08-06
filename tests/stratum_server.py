#!/usr/bin/env python3
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# A Stratum v1 server that exists to misbehave.
#
# The reconnect path only runs when something has gone wrong, which is exactly
# what a real pool will not help test: it drops the connection when it feels
# like it, not when a test is watching. This serves a real job to a real miner
# and then does the thing under test -- closes the socket mid-batch, goes
# silent, or redirects the client elsewhere -- at a chosen moment.
#
# The job it serves is the captured one from stratum_header_kat.cpp, which this
# miner is already proven to assemble into the right eighty bytes. Any parse
# failure here is therefore the server's fault, not the miner's.
#
#   python3 stratum_server.py --port 3333 --drop-after 8 --drops 2
#
# Every event goes to stdout as `SERVER <event> <detail>` so a driver can assert
# on the sequence rather than on timing. Shares are sampled, with a total per
# session, because their number depends on the device and a log whose length
# does is a log nobody can be required to read.

import argparse
import json
import math
import socket
import struct
import sys
import time

# The mining.subscribe reply that fixed extranonce1 for the captured job. The
# size matters more than the value: it is the room the miner has to roll a
# coinbase, and a miner given none has one nonce range per job.
EXTRANONCE1 = "8007e1bb"
EXTRANONCE2_SIZE = 4

# mining.notify, job 3a409, exactly as the pool sent it. The 0x4e in coinb1
# declares a 78-byte scriptSig of which ten bytes are here; the rest is the two
# extranonces and the head of coinb2.
PREVHASH = "25e64461aaf2fade90d786b7810348084d8bb835011a56d0689c29f55e9240a7"
COINB1 = ("01000000010000000000000000000000000000000000000000000000000000000000"
          "000000ffffffff4e03622842044358726a08")
COINB2 = ("2f7a706f6f6c2e63612f1cd1999b2f00fabe6d6de7a6e06406823582fab852d1c437"
          "df174638dc7345e1fdf8916e12e7cb7074f38000000000000000000000000180"
          "6e8774010000001976a9146c05352933d58f6ba2ff6223d0f276aa35a0f26688ac"
          "00000000")
MERKLE_BRANCH = []
VERSION = "00000000"
NBITS = "1a008a57"
NTIME = "6a725843"


def log(event, detail=""):
    print(f"SERVER {event} {detail}".rstrip(), flush=True)


class Client:
    """One miner connection, for as long as it is allowed to last."""

    def __init__(self, conn, addr, opts):
        self.conn = conn
        self.addr = addr
        self.opts = opts
        self.buf = b""
        self.jobs = 0
        self.shares = 0
        self.authorized = False
        self.diff = opts.diff
        # The window the share rate is measured over, restarted at every
        # retarget so that a difficulty already raised is not re-raised on the
        # strength of the shares that provoked it.
        self.window_start = time.time()
        self.window_shares = 0
        self.settle_until = 0.

    def send(self, obj):
        self.conn.sendall((json.dumps(obj) + "\n").encode())

    # How long a difficulty is given to take effect before the rate it produces
    # is believed. A new one reaches the miner with the next job and applies
    # only to work started after it, so for a moment shares keep arriving at the
    # old rate. Generous: waiting too long costs a few hundred extra shares,
    # not waiting compounds the raise.
    SETTLE = 1.0

    def set_difficulty(self, diff):
        self.diff = diff
        self.settle_until = time.time() + self.SETTLE
        self.send({"id": None, "method": "mining.set_difficulty",
                   "params": [diff]})
        log("difficulty", f"{diff:g}")

    def retarget(self):
        """Vardiff, for the reason real pools have it. A difficulty that gives a
        software rasterizer a share every few seconds gives a 1.4 GH/s GPU three
        hundred a second, and a reconnect test whose share rate varies by 300x
        with the device is not running the same test on both. Holding the rate
        roughly fixed keeps the submit path present -- shares in flight across a
        drop are the point -- without letting it become the whole run."""
        if not self.opts.share_target:
            return

        now = time.time()
        if now < self.settle_until:
            # Still arriving under the old difficulty. Measuring here is what
            # ramped this 0.001 -> 0.032 -> 4 -> 262 -> 33554 in four steps on
            # a 1.4 GH/s card: each window saw a rate the last raise had not
            # taken effect on yet, and multiplied on top of it.
            self.window_start, self.window_shares = now, self.shares
            return
        if self.shares - self.window_shares < 20:
            return

        rate = (self.shares - self.window_shares) / max(now - self.window_start,
                                                        1e-6)
        self.window_start, self.window_shares = now, self.shares
        if rate <= self.opts.share_target:
            return

        # In powers of two, which is how pool difficulty moves, and rounded up
        # so an overshoot costs one step rather than a slow climb behind a card
        # that is already flooding.
        step = 2. ** math.ceil(math.log2(rate / self.opts.share_target))
        self.set_difficulty(self.diff * step)
        # The miner picks up a difficulty at the next job, so one goes out now.
        # Without it the new value sits unused until the job interval elapses,
        # which at these rates is thousands more shares.
        self.notify(clean=False)

    def notify(self, clean=True):
        """A fresh job. Only ntime moves, which is enough to make it a new job
        and keeps every other field the captured, known-good one."""
        self.jobs += 1
        ntime = format(int(NTIME, 16) + self.jobs, "08x")
        self.send({
            "id": None,
            "method": "mining.notify",
            "params": [f"job{self.jobs:04x}", PREVHASH, COINB1, COINB2,
                       MERKLE_BRANCH, VERSION, NBITS, ntime, clean],
        })
        log("notify", f"job{self.jobs:04x}")

    def handle(self, msg):
        method = msg.get("method")
        mid = msg.get("id")

        if method == "mining.subscribe":
            log("subscribe")
            self.send({"id": mid, "error": None, "result": [
                [["mining.set_difficulty", "1"], ["mining.notify", "1"]],
                EXTRANONCE1, EXTRANONCE2_SIZE]})
        elif method == "mining.authorize":
            log("authorize", str(msg.get("params", [""])[0]))
            self.authorized = True
            self.send({"id": mid, "error": None, "result": True})
        elif method == "mining.submit":
            self.shares += 1
            # Not one line per share. A fast device submits thousands in a
            # twenty-second case, and a driver that collects this output has to
            # read all of it or block the server inside this very print.
            if self.shares == 1 or self.shares % 100 == 0:
                log("share",
                    f"#{self.shares} nonce={msg.get('params', ['']*5)[4]}")
            self.send({"id": mid, "error": None, "result": True})
            self.retarget()
        elif method in ("mining.extranonce.subscribe",
                        "mining.suggest_difficulty"):
            # Answered rather than ignored: an unanswered id leaves the miner
            # waiting, and a test that hangs says nothing about reconnecting.
            self.send({"id": mid, "error": None, "result": True})
        elif mid is not None:
            self.send({"id": mid, "error": None, "result": True})

    def pump(self, deadline, until=None):
        """Reads and answers until `deadline`, or until `until()` goes true.
        False means the miner hung up.

        The predicate is not a nicety: without it the handshake would sit here
        for the whole deadline before the first job went out, and a fixed delay
        between authorize and notify is indistinguishable in the miner's log
        from the miner being slow to start mining."""
        while time.time() < deadline and not (until and until()):
            self.conn.settimeout(max(0.05, min(0.5, deadline - time.time())))
            try:
                chunk = self.conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return False
            if not chunk:
                return False
            self.buf += chunk
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                if line.strip():
                    try:
                        self.handle(json.loads(line))
                    except json.JSONDecodeError:
                        log("badjson", line[:60].decode(errors="replace"))
        return True

    def kill(self):
        """An abortive close: RST rather than FIN, so the miner sees the
        connection break rather than being told about it. That is the harsher
        of the two and the one a dropped route or a killed pool process looks
        like from here."""
        try:
            self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                 struct.pack("ii", 1, 0))
            self.conn.close()
        except OSError:
            pass


def serve_one(conn, addr, opts, session):
    c = Client(conn, addr, opts)
    log("connect", f"#{session} from {addr[0]}")
    try:
        serve_session(c, opts, session)
    finally:
        log("session", f"#{session} took {c.shares} share(s) at difficulty "
                       f"{c.diff:g}")


def serve_session(c, opts, session):
    # Subscribe and authorize first, then the difficulty and the first job. The
    # miner will not mine before all four.
    if not c.pump(time.time() + 10, until=lambda: c.authorized):
        log("gone", "before authorize")
        return
    if not c.authorized:
        log("gone", "never authorized")
        return
    c.set_difficulty(opts.diff)
    c.notify()
    # The rate window starts at the first job, not at accept: handshake seconds
    # produced no shares and would drag the first measured rate below target.
    # Nor does this difficulty need settling -- it went out ahead of the first
    # job, so it is in force on everything the miner has ever hashed.
    c.window_start, c.settle_until = time.time(), 0.

    if opts.redirect and session <= opts.drops:
        # The pool telling the miner to go somewhere else, which is the only
        # form of failover the miner implements -- there is no pool list.
        time.sleep(opts.drop_after)
        log("redirect", f"port {opts.redirect}")
        c.send({"id": None, "method": "client.reconnect",
                "params": ["127.0.0.1", opts.redirect, 0]})
        c.pump(time.time() + 2)
        c.kill()
        return

    end = time.time() + (opts.drop_after if session <= opts.drops else 1e9)
    next_job = time.time() + opts.job_interval
    while time.time() < end:
        if not c.pump(min(end, next_job)):
            log("gone", "miner closed")
            return
        if time.time() >= next_job:
            c.notify(clean=False)
            next_job = time.time() + opts.job_interval

    if opts.silent:
        # Still connected, saying nothing. This is the other way a pool fails,
        # and it exercises a different branch: the socket never breaks, so only
        # the read timeout can notice.
        log("silent", "holding the socket open, sending nothing")
        time.sleep(opts.silent)
        c.kill()
        log("dropped", f"session #{session} after going silent")
    else:
        c.kill()
        log("dropped", f"session #{session} mid-batch")


def main():
    p = argparse.ArgumentParser(description="a Stratum server that misbehaves")
    p.add_argument("--port", type=int, default=3333)
    p.add_argument("--diff", type=float, default=0.01,
                   help="starting stratum difficulty; low so shares arrive "
                        "quickly on a slow device")
    p.add_argument("--share-target", type=float, default=5.0,
                   help="shares per second to hold the client to by raising "
                        "difficulty, as a pool's vardiff would; 0 disables it "
                        "and lets a fast device submit as fast as it can")
    p.add_argument("--drop-after", type=float, default=8.0,
                   help="seconds of mining before the connection is dropped")
    p.add_argument("--drops", type=int, default=1,
                   help="how many sessions to drop before serving normally")
    p.add_argument("--job-interval", type=float, default=5.0)
    p.add_argument("--silent", type=float, default=0.0,
                   help="instead of dropping, go quiet for N seconds")
    p.add_argument("--redirect", type=int, default=0,
                   help="send client.reconnect to this port instead")
    p.add_argument("--sessions", type=int, default=0,
                   help="exit after N sessions; 0 means never")
    opts = p.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", opts.port))
    srv.listen(4)
    log("listening", f"127.0.0.1:{opts.port}")

    session = 0
    try:
        while True:
            conn, addr = srv.accept()
            session += 1
            serve_one(conn, addr, opts, session)
            if opts.sessions and session >= opts.sessions:
                log("done", f"{session} session(s)")
                return
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


if __name__ == "__main__":
    sys.exit(main())
