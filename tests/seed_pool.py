#!/usr/bin/env python3
# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The fake pool with exactly one field changed: the seed hash it serves.
#
# Nothing here invents a reply. stratum_server.py is imported and one module
# global is replaced, so the two arms differ in the seed and in nothing else --
# same height, same job cadence, same everything on the wire. A hand-written
# server that got a neighbouring field wrong would prove something about that
# field instead of about the seed.
#
# Usage: seed_pool.py <64 hex chars | default> [stratum_server.py args]

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import stratum_server                                          # noqa: E402

SEED = sys.argv[1]
REST = sys.argv[2:]

if SEED != "default":
    stratum_server.PROGPOW_SEED = SEED

sys.argv = ["stratum_server.py"] + REST
sys.exit(stratum_server.main())
