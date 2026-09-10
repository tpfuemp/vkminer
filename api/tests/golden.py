#!/usr/bin/env python3
"""Golden-output capture for the REST API.

Asks a running miner for every route it serves and records the exact shape it
replies with. Used as a regression gate: capture before a change, capture after,
diff. The API is a compatibility surface, so any diff that is not explicitly
intended is a defect.

    vkminer --api-bind 127.0.0.1:4048 -a <algo> --benchmark
    python api/tests/golden.py capture before.txt
    ...change something, rebuild...
    python api/tests/golden.py capture after.txt
    python api/tests/golden.py diff before.txt after.txt

Replies are recorded verbatim except for the values listed in VOLATILE, which
change between two runs of the *same* binary -- uptime, rates, temperatures --
and would otherwise drown the signal. The key stays; only the value is masked,
so a field that appears or disappears is still a diff.

Only scalars are ever masked. A field name that carries a number in one response
and an object in another is common here -- `difficulty` is a number on a pool and
an object on the summary -- and replacing the object with a placeholder would
hide every field inside it, which is the whole point of the capture. Names that
collide on scalars too are written `parent.name`.

The capture is also where the contract's examples come from: a documented
response nobody generated from a running miner is a response nobody has checked.
"""

import json
import socket
import sys
import urllib.error
import urllib.request

HOST, PORT = "127.0.0.1", 4048
BASE = "http://%s:%d" % (HOST, PORT)

# Every route the miner may serve, plus the error cases the transport has to
# handle. A route answering 501 is captured as a 501: switching one on is a
# deliberate change and belongs in the diff.
ROUTES = [
    "/api/v1",
    "/api/v1/summary",
    "/api/v1/threads",
    "/api/v1/threads?id=0",
    "/api/v1/threads?id=99",
    "/api/v1/devices",
    "/api/v1/devices/0",
    "/api/v1/system",
    "/api/v1/pools",
    "/api/v1/pools/0",
    "/api/v1/health",
    "/api/v1/config",
    "/api/v1/algos",
    "/api/v1/history",
    "/api/v1/scanlog",
    "/api/v1/meminfo",
    "/api/v1/control/state",
    "/metrics",
    # Error cases. An index out of range is a 404 and not an empty object; a
    # path that no row matches is a 404 with the same envelope.
    "/api/v1/devices/99",
    "/api/v1/pools/99",
    "/api/v1/nosuchroute",
]

# Values that legitimately differ between two runs of the SAME binary. Verified
# by capturing twice without rebuilding: anything that moves and is not here is
# protocol, not runtime state.
VOLATILE = {
    "uptime_s", "timestamp", "hashrate_hs", "hashrate_avg_hs",
    "hashrate_per_watt_khs", "accepted", "rejected", "stale", "solved",
    "accepted_per_min", "best_share", "difficulty",
    "temp_c", "fan_pct", "fan_rpm", "clock_mhz", "mem_clock_mhz",
    "power_mw", "power_limit_mw", "cpu_temp_c", "cpu_clock_mhz",
    "cpu_fan_pct", "ping_ms", "disconnects", "wait_time_s", "session_s",
    "last_share_age_s", "batches_total", "batches_late",
    "height", "extranonce2", "extranonce2_size",
    "mining", "pool_connected", "tuned", "workgroup",
    "queue_depth", "kernel",
    # Qualified because the bare name is protocol somewhere else: the two
    # difficulties the summary reports are numbers while a device's or a
    # thread's `id` is its index, and `status` on an error envelope is the code
    # the route always answers with.
    "difficulty.pool", "difficulty.network", "job.id",
    "health.status", "pool.status", "pools.status",
}

# Values that differ between two *machines* rather than two runs, so a capture
# taken on one box can still be diffed against a capture taken on another.
HOST_SPECIFIC = {
    "driver", "os", "cpus", "mem_bytes", "vendor_id", "device_id",
    "devices_ok", "backend", "int64", "devices", "threads",
    "bus_id", "serial", "bios", "sm", "pstate", "nvml_id", "nvapi_id",
    "base_clock_mhz", "base_mem_clock_mhz",
    # `name` is the card here and the miner in the envelope; `api_version` is
    # the driver's Vulkan level here and the contract's version there. Neither
    # of the envelope's two may be masked -- they are the only fields every
    # response carries.
    "device.name", "devices.name", "vulkan.api_version",
}


def mask(node, keys, parent=""):
    """Replace the value of every listed key, at any depth, with a placeholder.

    The key survives, so a field that is added or removed is still a diff -- it
    is only the number that is silenced. A listed key whose value is an object
    or an array is recursed into instead: masking a container would silence
    every field under it, and those fields are what is being captured.
    """
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            hit = k in keys or (parent + "." + k) in keys
            out[k] = ("<v>" if hit and not isinstance(v, (dict, list))
                      else mask(v, keys, k))
        return out
    if isinstance(node, list):
        return [mask(v, keys, parent) for v in node]
    return node


def ask(path, token=None, timeout=8.0):
    """One request, one connection: every response is Connection: close."""
    req = urllib.request.Request(BASE + path)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        # A 404, a 501 and a degraded /health's 503 all carry a body, and the
        # body is the thing being captured.
        return e.code, e.read().decode("utf-8", "replace")


def render(path, status, text, keys):
    try:
        body = json.loads(text)
    except ValueError:
        # /metrics is not JSON. Its exposition format has its own gate; here it
        # is enough to record that it answered and with how many lines.
        lines = [ln for ln in text.splitlines() if ln.strip()]
        return "%d non-json, %d lines\n" % (status, len(lines))
    body = mask(body, keys)
    return "%d\n%s\n" % (status, json.dumps(body, indent=2, sort_keys=True))


def capture(path_out, token, keys):
    out = []
    unreachable = 0
    for route in ROUTES:
        try:
            status, text = ask(route, token)
        except (OSError, socket.timeout) as e:      # report, do not raise
            out.append("=== %s ===\nTRANSPORT-ERROR: %s\n" % (route, e))
            unreachable += 1
            continue
        out.append("=== %s ===\n%s" % (route, render(route, status, text, keys)))
    body = "".join(out)
    with open(path_out, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    print("wrote %s  (%d routes, %d unreachable)"
          % (path_out, len(ROUTES), unreachable))
    return 1 if unreachable else 0


def diff(a, b):
    la = open(a, encoding="utf-8").read().splitlines()
    lb = open(b, encoding="utf-8").read().splitlines()
    import difflib
    d = list(difflib.unified_diff(la, lb, a, b, lineterm="", n=1))
    if not d:
        print("IDENTICAL: %s == %s" % (a, b))
        return 0
    print("\n".join(d))
    print("\n%d diff lines -- every one must be an intended change." % len(d))
    return 1


if __name__ == "__main__":
    argv = sys.argv[1:]
    tok = None
    if "--token" in argv:
        i = argv.index("--token")
        tok = argv[i + 1]
        del argv[i:i + 2]
    # Two captures from two different machines are only comparable with this;
    # two captures from one machine are stricter without it.
    mask_keys = VOLATILE | HOST_SPECIFIC if "--any-host" in argv else VOLATILE
    argv = [a for a in argv if a != "--any-host"]

    if len(argv) >= 2 and argv[0] == "capture":
        sys.exit(capture(argv[1], tok, mask_keys))
    if len(argv) >= 3 and argv[0] == "diff":
        sys.exit(diff(argv[1], argv[2]))
    print(__doc__)
    sys.exit(2)
