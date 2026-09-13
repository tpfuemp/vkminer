#!/usr/bin/env python3
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
"""A first job whose dataset does not fit, driven two ways.

The switch arm: a miner mining one algorithm is re-targeted over the control API
at a pool serving another, whose first job states a block height far past
anything the fork declares. The switch itself succeeds -- the pre-check asks at
the fork's *declared* worst-case epoch, which the device passes -- so the failure
lands later, when the job's own epoch asks for a dataset larger than the device.
What is asserted is that the miner is still running afterwards, back on the
profile it came from, with last_error saying what happened.

The startup arm: the same pool and height, but the miner is launched on that
algorithm directly. There is no previous profile to go back to, so the
recoverable path is closed and the process must exit non-zero.

Neither arm submits a share or needs credentials. The switch arm costs an
allocation attempt rather than a dataset build: the buffers are created before
anything is generated.
"""

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


# Epoch 1400 of a 7500-block fork. The dataset for it is about 12224 MiB, larger
# than the entire device-local heap of the cards this runs on, so the refusal
# does not depend on how much of the card the miner is willing to ask for.
# Deliberately not an absurd height: the host light cache grows with the epoch
# too, and a number chosen for drama would make cache generation the slow part
# rather than the allocation under test.
FAR_HEIGHT = 10500000


class Fail(Exception):
    pass


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def api(port, path, body=None, timeout=30):
    """Returns (status, parsed body). A refusal is a result here, not an
    exception."""
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
            raw = r.read().decode()
            try:
                return r.status, json.loads(raw)
            except ValueError:
                return r.status, None
    except urllib.error.HTTPError as ex:
        raw = ex.read().decode()
        try:
            return ex.code, json.loads(raw)
        except ValueError:
            return ex.code, None
    except Exception:
        return 0, None


def control(port):
    status, body = api(port, "/control/state")
    if status != 200 or not isinstance(body, dict):
        raise Fail("control/state answered %d" % status)
    return body["control"]


def profile_of(c):
    return (c["state"], c["algo"], c["pool"]["url"], c["pool"]["user"])


def tail(path, lines=25):
    try:
        with open(path, "r", errors="replace") as fh:
            got = fh.read().splitlines()
    except OSError:
        return "(no log)"
    return "\n    ".join(got[-lines:])


def start_pool(script, port, log_path, extra=()):
    log = open(log_path, "w")
    cmd = [sys.executable, script, "--port", str(port)] + list(extra)
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
    # The pool binds before it prints anything, so connect rather than poll a
    # log line: a pool that failed to bind is the one failure that would
    # otherwise show up as the miner's retry loop instead.
    for _ in range(100):
        if proc.poll() is not None:
            raise Fail("the pool on %d exited %d -- %s"
                       % (port, proc.returncode, tail(log_path)))
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            s.close()
            return proc, log
        except OSError:
            time.sleep(0.1)
    raise Fail("the pool on %d never accepted a connection" % port)


def start_miner(opts, args, log_path):
    log = open(log_path, "w")
    env = dict(os.environ)
    # So a run never rewrites this machine's real tuning.
    env["APPDATA"] = opts.scratch
    env["XDG_CONFIG_HOME"] = opts.scratch
    proc = subprocess.Popen([opts.miner] + args, stdout=log,
                            stderr=subprocess.STDOUT, env=env)
    return proc, log


def wait_for_api(port, proc, log_path, seconds=90):
    end = time.time() + seconds
    while time.time() < end:
        if proc.poll() is not None:
            raise Fail("the miner exited %d before its API answered --\n    %s"
                       % (proc.returncode, tail(log_path)))
        status, _ = api(port, "/", timeout=5)
        if status == 200:
            return
        time.sleep(0.5)
    raise Fail("the miner's API never answered --\n    %s" % tail(log_path))


def stop(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


# ---------------------------------------------------------------- the arms

def arm_switch(opts):
    """Re-targeted onto a far-future job: alive, rolled back, and says why."""
    home_port = free_port()
    far_port = free_port()
    api_port = free_port()

    home_log = os.path.join(opts.out, "switch-pool-home.log")
    far_log = os.path.join(opts.out, "switch-pool-far.log")
    miner_log = os.path.join(opts.out, "switch-miner.log")

    home = far = miner = None
    try:
        home, _ = start_pool(opts.stratum, home_port, home_log)
        far, _ = start_pool(opts.stratum, far_port, far_log,
                            ["--dialect", "progpow",
                             "--base-height", str(FAR_HEIGHT)])

        miner, _ = start_miner(opts, [
            "-a", opts.home_algo, "--backend", "vulkan",
            "--devices", str(opts.device),
            "-o", "stratum+tcp://127.0.0.1:%d" % home_port,
            "-u", "tester", "-p", "x",
            "--retry-pause", "2", "--time-limit", str(opts.seconds),
            "--no-tune",
            "-b", "127.0.0.1:%d" % api_port,
            "--api-remote", "--api-control",
            "--api-control-min-interval", "0",
        ], miner_log)

        wait_for_api(api_port, miner, miner_log)

        before = control(api_port)
        print("    starts on   %s" % (profile_of(before),))
        if before["algo"] != opts.home_algo:
            raise Fail("started on '%s', not '%s'"
                       % (before["algo"], opts.home_algo))

        status, body = api(api_port, "/control/profile", {
            "algo": opts.far_algo,
            "pool": {"url": "stratum+tcp://127.0.0.1:%d" % far_port,
                     "user": "tester", "pass": "x"},
        }, timeout=120)
        print("    switch to '%s' answered %d" % (opts.far_algo, status))
        if status not in (200, 202):
            raise Fail("the switch was refused %d before the job could be "
                       "served: %s" % (status, json.dumps(body)))

        # The switch was accepted, so the miner is now on the far pool and its
        # first job is the one that cannot be held. What comes back is a
        # restore, posted by the worker that failed to build -- so this waits
        # for last_error to appear rather than for any particular state.
        end = time.time() + opts.wait
        seen = None
        while time.time() < end:
            if miner.poll() is not None:
                raise Fail("the miner exited %d -- a far-future job must not "
                           "end a run that had somewhere to go back to:\n    %s"
                           % (miner.returncode, tail(miner_log)))
            c = control(api_port)
            if c.get("last_error"):
                seen = c
                break
            time.sleep(0.5)

        if seen is None:
            raise Fail("no last_error after %d s; state is %s\n    %s"
                       % (opts.wait, json.dumps(control(api_port)),
                          tail(miner_log)))

        print("    last_error: %s" % seen["last_error"])

        # Still running is half of what is claimed here; back on the profile it
        # came from is the other half.
        # Read after last_error appeared, and once more a moment later, because
        # the restore lands as a park and the state it lands in is the one that
        # has to hold.
        time.sleep(3)
        if miner.poll() is not None:
            raise Fail("the miner exited %d after reporting the failure:\n    %s"
                       % (miner.returncode, tail(miner_log)))
        after = control(api_port)
        print("    ends on     %s" % (profile_of(after),))

        if after["algo"] != opts.home_algo:
            raise Fail("left on '%s'; the previous profile was '%s'"
                       % (after["algo"], opts.home_algo))
        if str(home_port) not in after["pool"]["url"]:
            raise Fail("left pointing at %s, not the pool it came from"
                       % after["pool"]["url"])
        if opts.far_algo not in (after["last_error"] or ""):
            raise Fail("last_error does not name '%s': %s"
                       % (opts.far_algo, after["last_error"]))

        # Whatever the device actually said, quoted from the log rather than
        # asserted on: last_error carries the worker's summary, and the sizes
        # are one layer below it.
        with open(miner_log, "r", errors="replace") as fh:
            for line in fh:
                if "shared state" in line or "would want" in line:
                    print("    log:        %s" % line.strip())
        return True
    finally:
        stop(miner)
        stop(far)
        stop(home)


def arm_startup(opts):
    """The same job with nothing to fall back to: the run must end."""
    far_port = free_port()
    far_log = os.path.join(opts.out, "startup-pool.log")
    miner_log = os.path.join(opts.out, "startup-miner.log")

    far = miner = None
    try:
        far, _ = start_pool(opts.stratum, far_port, far_log,
                            ["--dialect", "progpow",
                             "--base-height", str(FAR_HEIGHT)])

        miner, _ = start_miner(opts, [
            "-a", opts.far_algo, "--backend", "vulkan",
            "--devices", str(opts.device),
            "-o", "stratum+tcp://127.0.0.1:%d" % far_port,
            "-u", "tester", "-p", "x",
            "--retry-pause", "2", "--time-limit", str(opts.seconds),
            "--no-tune",
        ], miner_log)

        end = time.time() + opts.wait
        while time.time() < end:
            if miner.poll() is not None:
                break
            time.sleep(0.5)

        if miner.poll() is None:
            raise Fail("still running after %d s; a dataset that does not fit "
                       "at startup has nowhere to go back to and must end the "
                       "run:\n    %s" % (opts.wait, tail(miner_log)))
        if miner.returncode == 0:
            raise Fail("exited 0; the run failed and must say so")

        print("    exited %d" % miner.returncode)
        with open(miner_log, "r", errors="replace") as fh:
            for line in fh:
                if ("shared state" in line or "no kernel for" in line
                        or "would want" in line):
                    print("    log:        %s" % line.strip())
        return True
    finally:
        stop(miner)
        stop(far)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--miner", required=True)
    p.add_argument("--stratum",
                   default=os.path.join(HERE, "stratum_server.py"))
    # What the miner is told to use for its tuning cache. Never the real one:
    # a test run would otherwise rewrite the machine's tuning.
    p.add_argument("--scratch", default="")
    # Where the pool and miner logs are left for reading afterwards.
    p.add_argument("--out", default="")
    p.add_argument("--device", type=int, default=0)
    p.add_argument("--home-algo", default="sha256d")
    p.add_argument("--far-algo", default="kawpow")
    p.add_argument("--seconds", type=int, default=300)
    p.add_argument("--wait", type=int, default=150)
    p.add_argument("--only", default="")
    opts = p.parse_args()

    tmp = tempfile.mkdtemp(prefix="oversize-dataset-")
    opts.scratch = opts.scratch or os.path.join(tmp, "config")
    opts.out = opts.out or tmp
    os.makedirs(opts.scratch, exist_ok=True)
    os.makedirs(opts.out, exist_ok=True)
    print("   logs in %s" % opts.out)

    arms = [("switch", arm_switch), ("startup", arm_startup)]
    if opts.only:
        arms = [a for a in arms if a[0] == opts.only]

    bad = 0
    for name, fn in arms:
        print("== %s" % name)
        started = time.time()
        try:
            fn(opts)
            print("   ok   %s (%.0f s)" % (name, time.time() - started))
        except Fail as ex:
            bad += 1
            print("   FAIL %s: %s" % (name, ex))
        except Exception as ex:                    # noqa: BLE001
            bad += 1
            print("   FAIL %s: unexpected %r" % (name, ex))
    print("\n%d arm(s) failed" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
