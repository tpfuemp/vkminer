#!/usr/bin/env python3
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
"""Is a wrong shader caught by the switch, or by the pool?

A miner that changes algorithm at run time has the same exposure the startup
path was given a self-test for: the kernels being switched *to* have never run
on this device this session, and a build whose shader hashes wrongly costs the
pool's trust. The switch hook therefore self-tests before it commits, and the
claim under test is that the refusal happens there, with nothing submitted
anywhere.

The wrong shader is real and is not in the source tree. This test copies
sha256d.comp, changes its 640-bit length padding by one (0x280 -> 0x281),
compiles the copy with the build's own glslc flags into a temporary directory,
and hands that to the miner through --algo-dir. Neither the tree nor the build
directory is written to, so no arm can pick up a patched blob from a rebuild.

Two arms:

  switch  -- mine blake2s, then ask the API for sha256d. The refusal has to
             carry the self-test's own sentence, the miner has to still be
             mining blake2s afterwards, and the sha256d pool has to have been
             never even connected to -- the profile is refused before the pool
             is swapped.
  startup -- start on sha256d with the same blob. Non-zero exit, and again a
             pool that was never connected to.

The load-bearing assertion in both is the `Using sha256d from <path>` line:
--algo-dir answers a directory with no usable module by warning and carrying on
with the built-in one, so a run that never loaded the bad blob would pass both
arms for the wrong reason.

Needs a device: the switch hook skips its self-test on the null backend.
lavapipe is enough -- nothing here is a rate.

Exit 0 pass, 1 fail, 77 skip (which ctest reads as a skip). It skips where glslc
is absent: without it the good shader would pass every assertion for the wrong
reason.
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


# What the switch hook says when the self-test refuses it (src/main.cpp).
REFUSAL = ("'sha256d' fails its self-test on this build, "
           "so its shares would be rejected")


class Fail(Exception):
    pass


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def api(port, path, body=None, timeout=30):
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


def shares(port):
    status, body = api(port, "/summary")
    if status != 200 or not isinstance(body, dict):
        raise Fail("/summary answered %d" % status)
    s = (body.get("summary") or {}).get("shares") or {}
    return s.get("accepted", 0) or 0, s.get("rejected", 0) or 0


def read(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def tail(path, lines=25):
    got = read(path).splitlines()
    if not got:
        return "(no log)"
    return "\n    ".join(got[-lines:])


def start_pool(script, port, log_path, diff="0.001"):
    """Well-behaved on purpose: this pool drops its first session and throttles
    a fast client by default, and both look exactly like the failure under
    test."""
    log = open(log_path, "w")
    cmd = [sys.executable, script, "--port", str(port), "--drops", "0",
           "--diff", str(diff), "--job-interval", "4"]
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(100):
        if proc.poll() is not None:
            raise Fail("the pool on %d exited %d -- %s"
                       % (port, proc.returncode, tail(log_path)))
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            s.close()
            return proc
        except OSError:
            time.sleep(0.1)
    raise Fail("the pool on %d never accepted a connection" % port)


def start_miner(opts, args, log_path):
    log = open(log_path, "w")
    env = dict(os.environ)
    # A test run must not rewrite the machine's tuning.
    env["APPDATA"] = opts.scratch
    env["XDG_CONFIG_HOME"] = opts.scratch
    return subprocess.Popen([opts.miner] + args, stdout=log,
                            stderr=subprocess.STDOUT, env=env)


def wait_for_api(port, proc, log_path, seconds=180):
    end = time.time() + seconds
    while time.time() < end:
        if proc.poll() is not None:
            raise Fail("the miner exited %d before its API answered --\n    %s"
                       % (proc.returncode, tail(log_path)))
        if api(port, "/", timeout=5)[0] == 200:
            return
        time.sleep(0.5)
    raise Fail("the miner's API never answered --\n    %s" % tail(log_path))


def wait_for_shares(port, baseline, miner, log_path, seconds):
    end = time.time() + seconds
    while time.time() < end:
        if miner.poll() is not None:
            raise Fail("the miner exited %d while mining:\n    %s"
                       % (miner.returncode, tail(log_path)))
        acc, _ = shares(port)
        if acc > baseline:
            return acc
        time.sleep(0.5)
    raise Fail("no share after %d s, so this arm never established that the "
               "miner was mining at all\n    %s" % (seconds, tail(log_path)))


def stop(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


def assert_loaded_bad_blob(miner_log, algo_dir):
    """--algo-dir falls back to the built-in blob with a warning, so without
    this every assertion below would hold for a miner running the good one."""
    # Separators are normalised on both sides before comparing. os.path.join
    # gives a backslash under Windows Python while the miner echoes the path it
    # was handed, so the two disagree on a run where everything else is right --
    # which is exactly how this failed both arms on the 3060 while the log said
    # the bad blob had loaded.
    def flat(p):
        return p.replace("\\", "/")

    want = "Using sha256d from " + flat(algo_dir).rstrip("/") + "/sha256d.spv"
    log = flat(read(miner_log))
    if want not in log:
        if "has no usable sha256d" in log:
            raise Fail("the miner fell back to the built-in sha256d, so the "
                       "wrong shader was never under test")
        raise Fail("the miner never logged loading sha256d from %s, so what it "
                   "ran is unknown\n    %s" % (algo_dir, tail(miner_log)))


def untouched(pool_log, which):
    """Neither "no shares" nor "no connections".

    The pool is swapped only after the hook agrees, so a refused switch should
    leave the second pool with nothing on it -- but counting connections is not
    how to say so. start_pool's own readiness probe is a TCP connection, and it
    makes the pool log a connect, a `gone before authorize` and a zero-share
    session: exactly the four lines a refused switch leaves behind. Standing a
    pool up and probing it with no miner running at all reproduces them, which
    is how this was caught failing both arms on the harness's own footprint.

    What a bare probe cannot produce is a stratum session. An authorize means a
    miner got as far as the pool; a share means it mined onto it."""
    log = read(pool_log)
    sessions = log.count("SERVER authorize")
    submitted = log.count("SERVER share #")
    if sessions or submitted:
        raise Fail("the %s pool saw %d stratum session(s) and %d share(s); the "
                   "switch got further than the self-test\n    %s"
                   % (which, sessions, submitted, tail(pool_log)))
    return log.count("SERVER connect #")


# ---------------------------------------------------------------- the arms

def arm_switch(opts):
    """Mining blake2s, asked for a sha256d whose shader is wrong."""
    b2_port, sha_port, api_port = free_port(), free_port(), free_port()
    b2_log = os.path.join(opts.out, "switch-pool-blake2s.log")
    sha_log = os.path.join(opts.out, "switch-pool-sha256d.log")
    miner_log = os.path.join(opts.out, "switch-miner.log")

    b2 = sha = miner = None
    try:
        # The difficulty is the caller's: one share is all this arm needs to
        # establish that the miner is mining, and a real card at the lavapipe
        # default submits hundreds a second -- the flood that provokes the
        # stratum defects, which would fail this arm for the wrong reason.
        b2 = start_pool(opts.stratum, b2_port, b2_log, diff=opts.diff)
        sha = start_pool(opts.stratum, sha_port, sha_log, diff=opts.diff)

        miner = start_miner(opts, [
            "-a", "blake2s", "--backend", "vulkan",
            "--devices", str(opts.device), "--algo-dir", opts.algo_dir,
            "-o", "stratum+tcp://127.0.0.1:%d" % b2_port,
            "-u", "tester", "-p", "x",
            "--retry-pause", "2", "--time-limit", str(opts.seconds),
            "-b", "127.0.0.1:%d" % api_port,
            "--api-remote", "--api-control", "--api-control-min-interval", "0",
        ], miner_log)

        wait_for_api(api_port, miner, miner_log)
        wait_for_shares(api_port, 0, miner, miner_log, opts.wait)
        before = control(api_port)
        print("    mining '%s', state %s" % (before["algo"], before["state"]))

        status, body = api(api_port, "/control/profile", {
            "algo": "sha256d",
            "pool": {"url": "stratum+tcp://127.0.0.1:%d" % sha_port,
                     "user": "tester", "pass": "x"},
        }, timeout=240)
        said = json.dumps(body) if body is not None else "(no body)"
        print("    the switch answered %d: %s" % (status, said))

        if status in (200, 202):
            raise Fail("the switch to a knowingly wrong sha256d was accepted "
                       "(%d)" % status)
        if status == 0:
            raise Fail("the switch got no answer at all -- %s"
                       % tail(miner_log))

        # The refusal has to be the self-test's, not a busy barrier or a
        # throttle that would have refused a perfectly good shader too.
        state = control(api_port)
        where = []
        if REFUSAL in said:
            where.append("the response")
        if REFUSAL in json.dumps(state):
            where.append("last_error")
        if not where:
            raise Fail("refused, but not by the self-test: response %s, "
                       "state %s" % (said, json.dumps(state)))
        print("    refused by the self-test, carried in %s" % " and ".join(where))

        assert_loaded_bad_blob(miner_log, opts.algo_dir)

        if state["algo"] != "blake2s":
            raise Fail("left the miner on '%s', not the blake2s it was mining"
                       % state["algo"])
        if state["state"] != "running":
            raise Fail("left the miner %s, not running" % state["state"])
        if miner.poll() is not None:
            raise Fail("the miner exited %d over a refused switch"
                       % miner.returncode)

        untouched(sha_log, "sha256d")
        acc, rej = shares(api_port)
        print("    still mining blake2s; sha256d pool never connected to; "
              "%d accepted, %d rejected overall" % (acc, rej))
        return True
    finally:
        stop(miner)
        stop(sha)
        stop(b2)


def arm_startup(opts):
    """The same blob, as the algorithm the miner is started on."""
    sha_port = free_port()
    sha_log = os.path.join(opts.out, "startup-pool-sha256d.log")
    miner_log = os.path.join(opts.out, "startup-miner.log")

    sha = None
    try:
        sha = start_pool(opts.stratum, sha_port, sha_log, diff=opts.diff)
        log = open(miner_log, "w")
        env = dict(os.environ)
        env["APPDATA"] = opts.scratch
        env["XDG_CONFIG_HOME"] = opts.scratch
        rc = subprocess.call([
            opts.miner, "-a", "sha256d", "--backend", "vulkan",
            "--devices", str(opts.device), "--algo-dir", opts.algo_dir,
            "-o", "stratum+tcp://127.0.0.1:%d" % sha_port,
            "-u", "tester", "-p", "x",
            "--retry-pause", "2", "--time-limit", str(opts.wait),
        ], stdout=log, stderr=subprocess.STDOUT, env=env)
        log.close()
        print("    the miner exited %d" % rc)

        assert_loaded_bad_blob(miner_log, opts.algo_dir)
        if rc == 0:
            raise Fail("started and exited cleanly on a shader that hashes "
                       "wrongly\n    %s" % tail(miner_log))
        if "Self-test failed" not in read(miner_log):
            raise Fail("exited %d, but not over the self-test\n    %s"
                       % (rc, tail(miner_log)))

        untouched(sha_log, "sha256d")
        print("    refused at startup, pool never connected to")
        return True
    finally:
        stop(sha)


class Skip(Exception):
    pass


def build_bad_blob(out_dir):
    """Compiles a deliberately wrong sha256d into out_dir, and returns it.

    The change is one digit of the length padding. A SHA-256 message block
    states the message length in bits, and 0x280 is the 80-byte header; 0x281
    makes every digest wrong and leaves nothing else about the kernel unusual,
    so what the self-test catches is a bad hash rather than a blob that will
    not load."""
    glslc = shutil.which("glslc")
    if not glslc:
        raise Skip("glslc is not installed, so the wrong shader cannot be "
                   "built")

    src = os.path.join(ROOT, "algorithms", "sha256d", "sha256d.comp")
    try:
        with open(src, "r") as fh:
            text = fh.read()
    except OSError as ex:
        raise Skip("cannot read %s: %s" % (src, ex))

    # One occurrence, or the substitution is not the one this test describes:
    # the second compression block states a length of its own.
    if text.count("0x280u") != 1:
        raise Skip("sha256d.comp no longer states its length padding as a "
                   "single 0x280u, so exactly one thing cannot be corrupted")

    os.makedirs(out_dir, exist_ok=True)
    patched = os.path.join(out_dir, "sha256d.comp")
    with open(patched, "w") as fh:
        fh.write(text.replace("0x280u", "0x281u"))

    # The build's own flags, from cmake/CompileShaders.cmake: an #include names
    # its path from the root of the tree, and 1.1 is the baseline.
    spv = os.path.join(out_dir, "sha256d.spv")
    proc = subprocess.run(
        [glslc, "--target-env=vulkan1.1", "-O", "-I", ROOT, "-o", spv,
         patched],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        raise Skip("glslc could not compile the patched shader:\n    %s"
                   % proc.stdout.strip())
    return out_dir


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--miner", required=True)
    p.add_argument("--stratum",
                   default=os.path.join(HERE, "stratum_server.py"))
    # A directory holding a sha256d.spv that hashes wrongly. Built from the
    # shipped shader when it is not given, which is how ctest runs this.
    p.add_argument("--algo-dir", default="")
    # What the miner is told to use for its tuning cache. Never the real one:
    # a test run would otherwise rewrite the machine's tuning.
    p.add_argument("--scratch", default="")
    # Where the pool and miner logs are left for reading afterwards.
    p.add_argument("--out", default="")
    p.add_argument("--device", type=int, default=0)
    p.add_argument("--diff", default="0.001")
    p.add_argument("--seconds", type=int, default=300)
    p.add_argument("--wait", type=int, default=120)
    p.add_argument("--only", default="")
    opts = p.parse_args()

    tmp = tempfile.mkdtemp(prefix="switch-selftest-")
    opts.scratch = opts.scratch or os.path.join(tmp, "config")
    opts.out = opts.out or tmp
    os.makedirs(opts.scratch, exist_ok=True)
    os.makedirs(opts.out, exist_ok=True)
    if not opts.algo_dir:
        try:
            opts.algo_dir = build_bad_blob(os.path.join(tmp, "algo"))
        except Skip as ex:
            print("SKIP %s" % ex)
            return 77
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
