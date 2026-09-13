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
#  python3 stratum_server.py --port 3333 --drop-after 8 --drops 2
#
# It speaks either dialect. --dialect progpow serves the job from
# stratum_kawpow_kat.cpp instead: a header the pool has already hashed, a block
# height, a 256-bit target pushed with mining.set_target, and a five-field
# submit with a mix hash in it. That job is served the way the dialect's own
# trap is set -- the target arrives before the first notify, which is the order
# that gets a job read as some other dialect's.
#
# Every event goes to stdout as `[hh:mm:ss.mmm] SERVER <event> <detail>` so a
# driver can assert on the sequence rather than on timing. Shares are sampled,
# with a total per session, because their number depends on the device and a log
# whose length does is a log nobody can be required to read.

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

# ---------------------------------------------------------- the other dialect
#
# ProgPoW 0.9.4's published block 99, which is the job stratum_kawpow_kat.cpp
# proves this miner assembles and hashes correctly. Serving a vector rather than
# an invented job means a miner that mines it can be checked against a number
# somebody else computed, here and in that test.
#
# The prefix is two bytes because a KawPoW nonce is 64 bits of which the miner
# walks 48. A pool that keeps a different number of them is refused by the
# miner, which is a case worth having and not the default one.
PROGPOW_PREFIX = "8007"
PROGPOW_HEADER = \
    "de37e1824c86d35d154cf65a88de6d9286aec4f7f10c3fc9f0fa1bcc2687188d"
PROGPOW_SEED = "00" * 32       # epoch 0, which is what height 99 is in
PROGPOW_HEIGHT = 99
PROGPOW_NBITS = "1d00ffff"

# Loose enough that a GPU submits within a few seconds of starting; vardiff
# tightens it from there, the same way it does with a difficulty.
PROGPOW_TARGET = "0000ffff" + "0" * 56


def log(event, detail=""):
    # The time in front, because the miner's log has one and without it the two
    # cannot be laid side by side. A job the miner reads seconds after it was
    # sent and a job the pool sent seconds late produce the same miner log, and
    # only these timestamps tell them apart. Every driver matches on the SERVER
    # word or later, so nothing reads the line from its start.
    now = time.time()
    stamp = time.strftime("%H:%M:%S", time.localtime(now))
    print(f"[{stamp}.{int(now % 1 * 1000):03d}] SERVER {event} {detail}".rstrip(),
          flush=True)


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
        self.progpow = opts.dialect == "progpow"
        # The 256-bit target this dialect states outright, as a number so that
        # vardiff can move it. There is no difficulty in it to move instead.
        self.target = int(opts.target, 16)
        # Which job ids were actually sent. A share for a job the pool never
        # issued is a miner mining something it made up, and looks like nothing
        # else in the log.
        self.job_ids = set()
        self.bad = 0
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

    def set_target(self, target):
        """The other dialect's way of saying the same thing, and the method this
        whole file exists to send at an awkward moment: all 256 bits of the
        share target, in one string, with no difficulty anywhere near it."""
        self.target = max(target, 1)
        self.settle_until = time.time() + self.SETTLE
        self.send({"id": None, "method": "mining.set_target",
                   "params": [f"{self.target:064x}"]})
        log("target", f"{self.target:064x}")

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
        if self.progpow:
            # Harder means smaller here, because what is being moved is the
            # target itself rather than a difficulty to divide one out of.
            self.set_target(int(self.target / step))
        else:
            self.set_difficulty(self.diff * step)
        # The miner picks up a difficulty at the next job, so one goes out now.
        # Without it the new value sits unused until the job interval elapses,
        # which at these rates is thousands more shares.
        self.notify(clean=False)

    def notify(self, clean=True):
        """A fresh job. Only ntime moves, which is enough to make it a new job
        and keeps every other field the captured, known-good one."""
        self.jobs += 1
        job_id = f"job{self.jobs:04x}"
        self.job_ids.add(job_id)

        if self.progpow:
            # Seven parameters, none of them a coinbase, and the height among
            # them: it is the only thing in the job that says which epoch and
            # which program to mine it with.
            #
            # The target field is left empty unless asked for, so that the job
            # is mined at whatever the last mining.set_target said. That is the
            # arrangement the dialect gets wrong most easily and the one a pool
            # which pushes a target actually runs.
            # The seed stays the vector's whatever the height says, so a
            # --base-height large enough to move the epoch serves a job the
            # miner complains about the seed of before it ever weighs the
            # dataset. That complaint is expected, not the thing under test.
            height = (self.opts.base_height
                      + (self.jobs - 1) * self.opts.height_step)
            target = f"{self.target:064x}" if self.opts.target_in_job else ""
            self.send({
                "id": None,
                "method": "mining.notify",
                "params": [job_id, PROGPOW_HEADER, PROGPOW_SEED, target, clean,
                           height, PROGPOW_NBITS],
            })
            log("notify", f"{job_id} height={height}")
            return

        ntime = format(int(NTIME, 16) + self.jobs, "08x")
        self.send({
            "id": None,
            "method": "mining.notify",
            "params": [job_id, PREVHASH, COINB1, COINB2,
                       MERKLE_BRANCH, VERSION, NBITS, ntime, clean],
        })
        log("notify", job_id)

    def bad_share(self, params):
        """Why this submission is not a share, or None if it is one.

        Only the ProgPoW dialect is checked this closely, because only it has
        fields a pool would silently reject: a nonce whose top bytes are not the
        ones this pool handed out, a header hash belonging to no job it sent, or
        a mix hash left at zero. Each of those is a session of rejects with a
        perfectly correct kernel underneath, and each is invisible from the
        miner's own log."""
        if not self.progpow:
            return None

        if len(params) != 5:
            return f"{len(params)} parameters, and a ProgPoW share has five"

        _, job_id, nonce, header, mix = params
        for name, field, digits in (("nonce", nonce, 16),
                                    ("header hash", header, 64),
                                    ("mix hash", mix, 64)):
            if not isinstance(field, str) or not field.startswith("0x"):
                return f"the {name} is not an 0x-prefixed string: {field!r}"
            body = field[2:]
            if len(body) != digits:
                return (f"the {name} is {len(body)} hex digits, "
                        f"and it is {digits}")
            try:
                int(body, 16)
            except ValueError:
                return f"the {name} is not hex: {field!r}"

        if job_id not in self.job_ids:
            return f"job {job_id!r}, which this pool never sent"
        if nonce[2:6] != PROGPOW_PREFIX:
            # Two faults arrive here and the prefix is what is checked first, so
            # say which one it was. A nonce partitioning that did not survive a
            # switch walks the wrong range of a job this pool did send; a share
            # found under another profile and sent after the dialect moved
            # carries a header this pool has never issued.
            whose = ("" if header[2:] == PROGPOW_HEADER
                     else ", and on a header hash it never sent")
            return (f"nonce {nonce} is outside the prefix "
                    f"0x{PROGPOW_PREFIX} this pool assigned{whose}")
        if header[2:] != PROGPOW_HEADER:
            return f"header hash {header} belongs to no job this pool sent"
        if int(mix[2:], 16) == 0:
            return "the mix hash is zero, so the pool cannot re-check the share"
        return None

    def handle(self, msg):
        method = msg.get("method")
        mid = msg.get("id")

        if method == "mining.subscribe":
            log("subscribe")
            if self.progpow:
                # Two elements, and the second is the whole of what the miner
                # gets: the top of the nonce. No extranonce2 size, because there
                # is no coinbase for one to roll.
                self.send({"id": mid, "error": None,
                           "result": [None, PROGPOW_PREFIX]})
                return
            self.send({"id": mid, "error": None, "result": [
                [["mining.set_difficulty", "1"], ["mining.notify", "1"]],
                EXTRANONCE1, EXTRANONCE2_SIZE]})
        elif method == "mining.authorize":
            log("authorize", str(msg.get("params", [""])[0]))
            self.authorized = True
            self.send({"id": mid, "error": None, "result": True})
        elif method == "mining.submit":
            params = msg.get("params", [])
            reason = self.bad_share(params)
            if reason:
                # Refused and counted, not tolerated. A pool that accepts a
                # malformed share is how a miner ships one for a whole session
                # without anybody noticing.
                self.bad += 1
                log("badshare", reason)
                self.send({"id": mid, "error": [23, reason, None],
                           "result": False})
                return

            self.shares += 1
            # Not one line per share. A fast device submits thousands in a
            # twenty-second case, and a driver that collects this output has to
            # read all of it or block the server inside this very print.
            if self.shares == 1 or self.shares % 100 == 0:
                nonce = params[2] if self.progpow else params[4]
                log("share", f"#{self.shares} nonce={nonce}")
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
    except OSError as ex:
        # A miner hanging up while the pool is still answering it. Every send in
        # here can raise that, and unguarded it walks out of the accept loop and
        # ends the process -- so one abrupt disconnect leaves nothing listening
        # and every later connection fails against a pool that is not there.
        # From the miner's own log that is indistinguishable from a miner that
        # never came back, which is the wrong half of the test to be reading.
        log("gone", f"{ex.__class__.__name__} while answering")
    finally:
        at = (f"target {c.target:064x}" if c.progpow
              else f"difficulty {c.diff:g}")
        log("session", f"#{session} took {c.shares} share(s) at {at}, "
                       f"{c.bad} refused")


def serve_session(c, opts, session):
    # Subscribe and authorize first, then the difficulty and the first job. The
    # miner will not mine before all four.
    if not c.pump(time.time() + 10, until=lambda: c.authorized):
        log("gone", "before authorize")
        return
    if not c.authorized:
        log("gone", "never authorized")
        return
    # The target goes out before the first job, on purpose. This is the
    # order that broke a sibling port: it read the arrival of mining.set_target
    # as evidence about which dialect the pool spoke and rewired its notify
    # parser, so every job after one of these was parsed as something else.
    # Serving it this way round means a miner with that bug fails here rather
    # than against the first pool that pushes targets.
    if opts.dialect == "progpow":
        c.set_target(c.target)
    elif opts.set_target_first:
        # The same trap sprung on the dialect that has no use for the method:
        # a Bitcoin job following a set_target must still be read as a Bitcoin
        # job. The difficulty that follows is what the miner actually mines at.
        c.send({"id": None, "method": "mining.set_target",
                "params": [f"{int(opts.target, 16):064x}"]})
        log("target", opts.target)
    if opts.dialect != "progpow":
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
    p.add_argument("--dialect", default="bitcoin",
                   choices=["bitcoin", "progpow"],
                   help="which job this pool serves: a coinbase to build a "
                        "header from, or a header it has already hashed")
    p.add_argument("--target", default=PROGPOW_TARGET,
                   help="the 256-bit share target for the ProgPoW dialect, as "
                        "64 hex digits; also what --set-target-first pushes")
    p.add_argument("--target-in-job", action="store_true",
                   help="state the target in every notify rather than leaving "
                        "the job to be mined at the standing one")
    p.add_argument("--height-step", type=int, default=0,
                   help="how far the block height moves per job; 3 crosses a "
                        "ProgPoW period, which is a new program to compile")
    p.add_argument("--base-height", type=int, default=PROGPOW_HEIGHT,
                   help="the block height of the first ProgPoW job; the "
                        "default is the published vector's own. Raising it "
                        "moves the epoch, which is how a job needing a "
                        "dataset larger than the device is served. The seed "
                        "is not recomputed, so the miner also logs that the "
                        "seed and the height disagree")
    p.add_argument("--set-target-first", action="store_true",
                   help="push a mining.set_target before the first Bitcoin "
                        "job, which must not change how that job is read")
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
