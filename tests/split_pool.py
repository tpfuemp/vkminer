#!/usr/bin/env python3
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The fake pool, with one reply written in two pieces and a gap between them.
#
# Nothing here invents a reply. stratum_server.py is imported and its
# Client.send is wrapped, so the bytes on the wire are the ones an ordinary run
# would send and the only difference is where they are cut. That matters: a
# hand-written server that gets a field wrong proves something about the field
# instead of about the split.
#
# Usage: split_pool.py <gap seconds> <nth message> [stratum_server.py args]

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import stratum_server                                          # noqa: E402

GAP = float(sys.argv[1])
NTH = int(sys.argv[2])
REST = sys.argv[3:]

original_send = stratum_server.Client.send
count = {"n": 0}


def send(self, obj):
    count["n"] += 1
    if count["n"] != NTH:
        return original_send(self, obj)

    raw = (json.dumps(obj) + "\n").encode()
    cut = len(raw) // 2
    # The cut is deliberately not at the newline: what is modelled is a line
    # whose tail is still in flight, which is what TCP does to a busy
    # connection, and not a pool that went quiet between two whole messages.
    self.conn.sendall(raw[:cut])
    stratum_server.log("split", "message %d cut at %d of %d bytes, %gs before "
                                "the rest" % (NTH, cut, len(raw), GAP))
    time.sleep(GAP)
    self.conn.sendall(raw[cut:])
    stratum_server.log("split", "message %d completed" % NTH)


stratum_server.Client.send = send
sys.argv = ["stratum_server.py"] + REST
sys.exit(stratum_server.main())
