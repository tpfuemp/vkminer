#!/usr/bin/env python3
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Drives the control API over HTTP against a running miner, and asserts on what
# the miner made of a profile it was never going to accept.
#
# control_test.cpp proves the barrier itself, but calls the request functions
# directly. Every check the handler makes *before* the barrier -- the bodies it
# refuses, the profile it declines to half-apply -- is therefore executed by
# nothing else in the tree, and those are the checks a manager app meets first.
#
#  bodies     the refusals that never reach the barrier. The witness is the
#             epoch: it is spent when a change commits, so a refusal that left
#             it alone touched nothing.
#  refused    a profile naming an algorithm this build does not have. It goes
#             through the barrier -- the switch hook is what answers that -- so
#             it is the cheapest injected failure that exercises rollback.
#  retarget   a pool change that lands, followed immediately by one the
#             anti-flap interval refuses, with the profile read either side.
#  park       the same switch under a park timeout too short to make: whatever
#             wins the race, the profile must be wholly moved or wholly not.
#  disabled   without --api-control the route answers 403 and is still there.
#
# A half-switched miner must never be an outcome, so every case reads the whole
# profile -- algorithm, both pool credentials, run state and epoch -- and
# compares it as one value.
#
# Runs on the null backend: nothing here is about hashes, so it needs no GPU.
#
# Exit 0 pass, 1 fail, 77 skip (which ctest reads as a skip).

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "stratum_server.py")

# The algorithm the miner starts on, and a name no registry will ever resolve.
ALGO = "sha256d"
NO_SUCH_ALGO = "nosuchalgo"


class Fail(Exception):
    pass


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ------------------------------------------------------------------ the client


def api(port, path, body=None, timeout=30):
    """Returns (status, parsed body). A refusal is a result here, not an
    exception: every interesting case in this file is a non-2xx answer."""
    url = "http://127.0.0.1:%d/api/v1%s" % (port, path)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, method="POST" if data is not None else "GET")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as ex:
        raw = ex.read().decode()
        try:
            return ex.code, json.loads(raw)
        except ValueError:
            return ex.code, None


def message(body):
    """The complaint out of an error body, or "" if it carried none."""
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        return body["error"].get("message") or ""
    return ""


def control(port):
    status, body = api(port, "/control/state")
    if status != 200:
        raise Fail("GET /control/state answered %d, not 200" % status)
    return body["control"]


def profile_of(c):
    """Everything a switch moves, as one value. Compared whole on purpose: a
    miner that moved its pool but not its algorithm is the failure this file is
    looking for, and reading the fields one at a time is how that gets missed."""
    return (c["state"], c["algo"], c["pool"]["url"], c["pool"]["user"],
            c["epoch"])


# ----------------------------------------------------------------- the fixture


def start_pool(port, extra=()):
    """The fake pool, logging to a file rather than a pipe -- for the reason
    reconnect_test.py gives: nothing reads a pipe until the process exits, and a
    pool blocked inside its own print has stopped answering."""
    f = tempfile.TemporaryFile(mode="w+")
    proc = subprocess.Popen(
        [sys.executable, SERVER, "--port", str(port), "--drops", "0",
         "--diff", "0.001", "--job-interval", "4"] + list(extra),
        stdout=f, stderr=subprocess.STDOUT, text=True)
    return proc, f


def start_miner(opts, pool_port, api_port, extra=(), seconds=120):
    f = tempfile.TemporaryFile(mode="w+")
    pin = ["--devices", opts.devices] if opts.devices else []
    # --api-remote on every arm, --api-control only where a case asks for it.
    # The control privilege is write plus that flag, so a miner given neither
    # answers 403 for the missing privilege and never reaches the control gate
    # at all -- two different refusals that look identical from the status line.
    cmd = ([opts.miner, "-a", ALGO, "--backend", opts.backend,
            "-o", "stratum+tcp://127.0.0.1:%d" % pool_port,
            "-u", "tester", "-p", "x", "--retry-pause", "2",
            "--time-limit", str(seconds),
            "-b", "127.0.0.1:%d" % api_port,
            "--api-remote"] + list(extra) + pin)
    proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)
    return proc, f


def tail(log_file, lines=6):
    """The end of a process's log. A miner that died before it opened its API
    said why on the way out, and without this the harness reports only that it
    is gone -- which is true of a refused option and of a crash alike."""
    log_file.seek(0)
    got = [l.rstrip() for l in log_file.read().splitlines() if l.strip()]
    return " | ".join(got[-lines:]) if got else "(nothing logged)"


def wait_for_api(port, proc, log_file, seconds=40):
    end = time.time() + seconds
    while time.time() < end:
        if proc.poll() is not None:
            raise Fail("the miner exited %d before its API answered -- %s"
                       % (proc.returncode, tail(log_file)))
        try:
            # The index, not /control/state: that route answers 403 without
            # --api-control, which one case here starts a miner without on
            # purpose. The index is served by every build and every flag
            # combination, so readiness means the same thing on all of them.
            status, body = api(port, "/", timeout=5)
            if status == 200:
                return body
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.25)
    raise Fail("the miner's API never answered on port %d" % port)


def wait_for_pool(port, proc, seconds=30):
    """Mining, not merely listening. A profile applied to a miner that has not
    reached its first pool yet would be answered by a different code path."""
    end = time.time() + seconds
    while time.time() < end:
        if proc.poll() is not None:
            raise Fail("the miner exited %d before it reached the pool"
                       % proc.returncode)
        if control(port).get("pool_connected"):
            return
        time.sleep(0.25)
    raise Fail("the miner never connected to the fake pool")


def stop(procs, files):
    for p in procs:
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
    out = []
    for f in files:
        f.seek(0)
        out.append(f.read())
        f.close()
    return out


def still_mining(name, proc, log_file):
    """The property every refusal in this file shares: the miner went on being a
    miner. A process that died is the loudest possible half-switch."""
    if proc.poll() is not None:
        raise Fail("%s: the miner exited %d -- a refused profile must leave it "
                   "running" % (name, proc.returncode))
    log_file.seek(0)
    if "terminating workio thread" in log_file.read():
        raise Fail("%s: the miner gave up on its pool" % name)


# ----------------------------------------------------------------------- cases


# Every one of these is refused by h_control_profile before the barrier is
# touched, so every one of them must leave the epoch alone. The message is
# asserted too: a 400 that does not name what was wrong with the body is a
# refusal a client cannot act on.
BAD_BODIES = [
    ("algo without pool", {"algo": "kawpow"}, "algo requires pool"),
    ("a params key", {"params": {"intensity": 20}},
     "unknown parameter 'intensity'"),
    ("an empty body", {}, "must carry at least one"),
    ("an unknown field", {"nonsense": 1}, "unknown field 'nonsense'"),
    ("a wrong type", {"algo": 7, "pool": {"url": "stratum+tcp://127.0.0.1:1"}},
     "algo is a string"),
    ("a pool with no url", {"pool": {"user": "x"}}, "pool.url is required"),
    ("an unknown pool field",
     {"pool": {"url": "stratum+tcp://127.0.0.1:1", "bogus": 1}},
     "unknown field 'pool.bogus'"),
]


def case_bodies(opts):
    """The two 400s the gate names, and the rest of the route's refusals with
    them. All on one miner: none of them is supposed to change anything, so they
    cannot interfere with each other, and running them together is itself the
    assertion that none did."""
    pool_port, api_port = free_port(), free_port()
    pool, pool_log = start_pool(pool_port)
    miner, miner_log = start_miner(opts, pool_port, api_port,
                                   ["--api-control"])
    try:
        wait_for_api(api_port, miner, miner_log)
        wait_for_pool(api_port, miner)
        before = profile_of(control(api_port))

        for name, body, want in BAD_BODIES:
            status, got = api(api_port, "/control/profile", body)
            if status != 400:
                raise Fail("%s: answered %d, not 400" % (name, status))
            if want not in message(got):
                raise Fail("%s: the complaint was %r, which does not mention "
                           "%r" % (name, message(got), want))

        # An empty params object is the documented no-op, and the one body here
        # that is not an error: it names no parameter, so there is nothing to
        # refuse, and it asks for no change either.
        status, _ = api(api_port, "/control/profile", {"params": {}})
        if status != 200:
            raise Fail("an empty params object answered %d, not 200" % status)

        after = profile_of(control(api_port))
        if before != after:
            raise Fail("a refused body moved the profile: %r -> %r"
                       % (before, after))
        still_mining("bodies", miner, miner_log)
    finally:
        stop([miner, pool], [miner_log, pool_log])

    print("  bodies       %d refusals named their cause, none spent an epoch"
          % len(BAD_BODIES))


def case_refused(opts):
    """A profile the route cannot fault and the miner cannot honour. The name
    resolves nowhere, which only the switch hook knows, so this is a failure
    injected on the far side of the park -- and the whole profile has to come
    back."""
    pool_port, api_port = free_port(), free_port()
    second = free_port()
    pool, pool_log = start_pool(pool_port)
    miner, miner_log = start_miner(opts, pool_port, api_port,
                                   ["--api-control"])
    try:
        wait_for_api(api_port, miner, miner_log)
        wait_for_pool(api_port, miner)
        before = profile_of(control(api_port))

        status, got = api(api_port, "/control/profile", {
            "algo": NO_SUCH_ALGO,
            "pool": {"url": "stratum+tcp://127.0.0.1:%d" % second,
                     "user": "other", "pass": "x"},
        }, timeout=90)

        if status < 400:
            raise Fail("a switch to %r answered %d -- this build has no such "
                       "algorithm" % (NO_SUCH_ALGO, status))
        if NO_SUCH_ALGO not in message(got):
            raise Fail("the refusal was %r, which does not name the algorithm "
                       "it refused" % message(got))

        after = profile_of(control(api_port))
        if before != after:
            raise Fail("a refused switch moved the profile: %r -> %r"
                       % (before, after))
        still_mining("refused", miner, miner_log)
    finally:
        stop([miner, pool], [miner_log, pool_log])

    print("  refused      a switch the hook declined left algo, pool, state "
          "and epoch put")


def case_retarget(opts):
    """A pool change that lands, then one the anti-flap interval refuses. The
    first proves the route reaches the barrier at all -- without it the refusals
    above could all be passing for the wrong reason -- and the second proves a
    refusal after a success still leaves the profile whole."""
    first, second, api_port = free_port(), free_port(), free_port()
    pool_a, log_a = start_pool(first)
    pool_b, log_b = start_pool(second)
    miner, miner_log = start_miner(opts, first, api_port, ["--api-control"])
    try:
        wait_for_api(api_port, miner, miner_log)
        wait_for_pool(api_port, miner)
        before = control(api_port)

        url_b = "stratum+tcp://127.0.0.1:%d" % second
        status, _ = api(api_port, "/control/profile",
                        {"pool": {"url": url_b, "user": "second", "pass": "x"}},
                        timeout=90)
        if status not in (200, 202):
            raise Fail("a pool re-target answered %d, not 200 or 202" % status)

        # 202 is the contract's polling shape, so honour it rather than assume
        # the change had landed by the time the answer was written.
        deadline = time.time() + 60
        while time.time() < deadline:
            now = control(api_port)
            if now["pool"]["url"] == url_b:
                break
            time.sleep(0.25)
        after = control(api_port)

        if after["pool"]["url"] != url_b:
            raise Fail("the pool did not move: still %r" % after["pool"]["url"])
        if after["pool"]["user"] != "second":
            raise Fail("the pool url moved but the user did not: %r"
                       % after["pool"]["user"])
        if after["algo"] != before["algo"]:
            raise Fail("a pool change moved the algorithm: %r -> %r"
                       % (before["algo"], after["algo"]))
        if after["epoch"] != before["epoch"] + 1:
            raise Fail("a pool change spent %d epochs, not exactly one"
                       % (after["epoch"] - before["epoch"]))

        # Straight back again, inside the interval it was just changed in.
        status, got = api(api_port, "/control/profile",
                          {"pool": {"url": "stratum+tcp://127.0.0.1:%d" % first,
                                    "user": "tester", "pass": "x"}})
        if status != 429:
            raise Fail("a second re-target inside the anti-flap interval "
                       "answered %d, not 429" % status)
        # A client is told to branch on `code` and never on the prose, so the
        # delay has to be a field: reading it out of `message` is the one route
        # the contract forbids. A bool is an int in Python, which is why the
        # type is checked the long way round.
        err = got.get("error") if isinstance(got, dict) else None
        if not isinstance(err, dict):
            raise Fail("the 429 carried no error object: %r" % (got,))
        wait = err.get("retry_after_s")
        if not isinstance(wait, int) or isinstance(wait, bool):
            raise Fail("the 429's retry_after_s was %r, not an integer, so a "
                       "client cannot learn when to come back" % (wait,))
        if wait < 1:
            raise Fail("the 429 said retry_after_s=%d; a refusal that tells a "
                       "caller to come back in no time has said nothing" % wait)
        if wait > after["min_interval_s"]:
            raise Fail("the 429 said retry_after_s=%d, longer than the %d s "
                       "interval it is measured against"
                       % (wait, after["min_interval_s"]))

        throttled = profile_of(control(api_port))
        if throttled != profile_of(after):
            raise Fail("a throttled re-target moved the profile: %r -> %r"
                       % (profile_of(after), throttled))
        still_mining("retarget", miner, miner_log)
    finally:
        stop([miner, pool_a, pool_b], [miner_log, log_a, log_b])

    print("  retarget     one change spent one epoch; the next was throttled "
          "and moved nothing")


def case_park(opts):
    """The same switch under the tightest park the miner will accept.

    The floor is 250 ms and the option parser enforces it, on the stated ground
    that anything shorter would roll every change back before a worker could
    reach the top of its loop. So a park timeout cannot be injected from out
    here at all, and the rollback-on-timeout path stays control_test.cpp's to
    prove. What this case can still say is that at the tightest legal timing the
    profile is wholly moved or wholly not, and the miner mines either way."""
    first, second, api_port = free_port(), free_port(), free_port()
    pool_a, log_a = start_pool(first)
    pool_b, log_b = start_pool(second)
    miner, miner_log = start_miner(
        opts, first, api_port,
        ["--api-control", "--api-control-park-timeout", "250"])
    try:
        wait_for_api(api_port, miner, miner_log)
        wait_for_pool(api_port, miner)
        before = control(api_port)

        url_b = "stratum+tcp://127.0.0.1:%d" % second
        status, _ = api(api_port, "/control/profile",
                        {"pool": {"url": url_b, "user": "second", "pass": "x"}},
                        timeout=90)

        time.sleep(2.0)
        after = control(api_port)
        moved = [after["pool"]["url"] == url_b,
                 after["pool"]["user"] == "second"]

        if any(moved) and not all(moved):
            raise Fail("half a pool landed under a park timeout: url %r, "
                       "user %r" % (after["pool"]["url"], after["pool"]["user"]))
        if after["algo"] != before["algo"]:
            raise Fail("a pool change moved the algorithm: %r -> %r"
                       % (before["algo"], after["algo"]))
        still_mining("park", miner, miner_log)
    finally:
        stop([miner, pool_a, pool_b], [miner_log, log_a, log_b])

    landed = "landed" if all(moved) else "rolled back"
    print("  park         a 250 ms park timeout %s whole, answered %d"
          % (landed, status))


def case_disabled(opts):
    """Without --api-control the control routes are switched off, not absent.

    Both halves of that are promises a manager depends on. The capability stays
    in the index, so "control exists and is off" can be told from "this build
    does not route control at all" -- one is a flag to turn on, the other is a
    miner to stop asking. And the refusal carries the control API's own wording
    rather than the privilege one, so a missing control flag can be told from a
    missing write flag. This miner is a privileged source, which is what leaves
    the flag as the only thing able to refuse it.

    Reading the state is a read by the privilege table and still refused here,
    and that is not an inconsistency: the privilege level says no write is
    needed, the flag says whether this miner may be driven at all."""
    pool_port, api_port = free_port(), free_port()
    pool, pool_log = start_pool(pool_port)
    miner, miner_log = start_miner(opts, pool_port, api_port)
    try:
        index = wait_for_api(api_port, miner, miner_log)

        caps = index["index"]["capabilities"]
        for want in ("control.state", "control.profile"):
            if want not in caps:
                raise Fail("%r is absent from the capability list, which says "
                           "this build does not route it at all -- with the "
                           "flag off it is supposed to be listed and refused"
                           % want)

        for path in ("/control/state", "/control/profile"):
            body = None
            if path.endswith("profile"):
                body = {"pool": {"url": "stratum+tcp://127.0.0.1:%d"
                                        % free_port()}}
            status, got = api(api_port, path, body)
            if status != 403:
                raise Fail("%s without --api-control answered %d, not 403"
                           % (path, status))
            if "--api-control" not in message(got):
                raise Fail("%s was refused with %r, which is the other 403: "
                           "that wording means the write flag is missing, and "
                           "a client told it cannot tell which flag to set"
                           % (path, message(got)))

        still_mining("disabled", miner, miner_log)
    finally:
        stop([miner, pool], [miner_log, pool_log])

    print("  disabled     both routes listed and both 403 'control API "
          "disabled'")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--miner", default="./vkminer")
    p.add_argument("--backend", default="null",
                   help="null needs no GPU: nothing here is about hashes")
    p.add_argument("--devices", default="",
                   help="passed through to --devices; a box that enumerates a "
                        "software rasterizer alongside its GPU wants 0")
    p.add_argument("--case", default="all",
                   choices=["all", "bodies", "refused", "retarget", "park",
                            "disabled"])
    opts = p.parse_args()

    if not os.path.exists(opts.miner):
        print("SKIP no miner at %s" % opts.miner)
        return 77
    if not os.path.exists(SERVER):
        print("SKIP no fake pool at %s" % SERVER)
        return 77

    cases = {"bodies": case_bodies, "refused": case_refused,
             "retarget": case_retarget, "park": case_park,
             "disabled": case_disabled}
    todo = cases if opts.case == "all" else {opts.case: cases[opts.case]}

    print("control: %d case(s) on the %s backend" % (len(todo), opts.backend))
    try:
        for fn in todo.values():
            fn(opts)
    except Fail as e:
        print("FAIL %s" % e)
        return 1
    except subprocess.TimeoutExpired:
        print("FAIL a process had to be killed -- it never reached its own "
              "time limit")
        return 1

    print("ok   control")
    return 0


if __name__ == "__main__":
    sys.exit(main())
