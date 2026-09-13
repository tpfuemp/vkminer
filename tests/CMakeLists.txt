# vkminer -- a Vulkan compute cryptocurrency miner.
# SPDX-License-Identifier: GPL-3.0-or-later

# The run-state barrier: three threads' worth of agreement, and nothing else.
# Fast, so no timeout beyond ctest's own -- the parks it waits for are a
# millisecond apart and the ones it waits out are the timeout it sets itself.
#
# Built from the source rather than linked from vkminer_control, which now
# comes with the option parser and the stratum thread attached. This test
# defines the handful of globals it reads for itself, and the point of it is
# that they are the only ones there are.
add_executable(control_test control_test.cpp
    "${CMAKE_SOURCE_DIR}/src/api/api_control.cpp")
target_link_libraries(control_test PRIVATE
    vkminer_jansson vkminer_curl vkminer_warnings Threads::Threads)
target_include_directories(control_test PRIVATE
    "${CMAKE_SOURCE_DIR}" "${CMAKE_SOURCE_DIR}/src" "${CMAKE_SOURCE_DIR}/compat"
    "${CMAKE_BINARY_DIR}/generated")
add_test(NAME control_test COMMAND control_test)

# The snapshot layer: what the API reports, before there is an API to report it
# through. Same arrangement as the test above -- the sources are compiled in
# rather than linked, and the miner state the collectors read is defined in the
# test, so the list of globals they touch is asserted by the link.
add_executable(api_model_test api_model_test.cpp
    "${CMAKE_SOURCE_DIR}/src/api/api_model.cpp"
    "${CMAKE_SOURCE_DIR}/src/api/api_control.cpp"
    "${CMAKE_SOURCE_DIR}/backends/backend.cpp")
target_link_libraries(api_model_test PRIVATE
    vkminer_jansson vkminer_curl vkminer_warnings Threads::Threads)
target_include_directories(api_model_test PRIVATE
    "${CMAKE_SOURCE_DIR}" "${CMAKE_SOURCE_DIR}/src" "${CMAKE_SOURCE_DIR}/compat"
    "${CMAKE_BINARY_DIR}/generated")
add_test(NAME api_model_test COMMAND api_model_test)

# The HTTP transport's parser and router, with no socket and no miner: the
# fixtures are buffers, which is what api_http_parse() was written as a pure
# function for. Shared with the sibling miners, so a failure here is a failure
# of the copy, not of anything vkminer wrote.
add_executable(api_http_test api_http_test.c
    "${CMAKE_SOURCE_DIR}/src/api/api_http.c")
# Not linked against vkminer_warnings, for the same reason vkminer_api_shared
# is not: the test is a copy kept in step with the miners this transport is
# shared with, and -Werror here would mean editing a file whose whole value is
# that it is the same file.
target_link_libraries(api_http_test PRIVATE vkminer_jansson)
target_include_directories(api_http_test PRIVATE
    "${CMAKE_SOURCE_DIR}/src/api" "${CMAKE_SOURCE_DIR}/compat")
# The fixtures are buffers, but api_http.c still writes its responses with
# send(), so the winsock import library is needed even though this test never
# opens a socket. The miner gets it from vkminer_inherited; nothing else here
# links that, so it is named directly.
if(WIN32)
    target_link_libraries(api_http_test PRIVATE ws2_32)
endif()
add_test(NAME api_http_test COMMAND api_http_test)

# First-party, so the project's warning flags apply here too.
add_executable(sha256_kat sha256_kat.c)
target_link_libraries(sha256_kat PRIVATE vkminer_sha256 vkminer_warnings)
add_test(NAME sha256_kat COMMAND sha256_kat)

# The same question one level up: not whether SHA-256 is right, but whether the
# algorithm object turns struct work's words into the header that gets hashed.
add_executable(sha256d_kat sha256d_kat.cpp)
target_link_libraries(sha256d_kat PRIVATE
    vkminer_algorithms vkminer_warnings Threads::Threads)
add_test(NAME sha256d_kat COMMAND sha256d_kat)

# The same question for the second algorithm. Its vectors are anchored
# differently, on the headers' own difficulty; the test explains why.
add_executable(blake2s_kat blake2s_kat.cpp)
target_link_libraries(blake2s_kat PRIVATE
    vkminer_algorithms vkminer_warnings Threads::Threads)
add_test(NAME blake2s_kat COMMAND blake2s_kat)

# And for the third, which is the first with an anchor in a standards document:
# RFC 7914 publishes vectors for scrypt itself, so the reference is checked
# against the RFC as well as against mined headers.
add_executable(scrypt_kat scrypt_kat.cpp)
target_link_libraries(scrypt_kat PRIVATE
    vkminer_algorithms vkminer_warnings Threads::Threads)
add_test(NAME scrypt_kat COMMAND scrypt_kat)

# And for the fourth, anchored on published block hashes: BitcoinIII makes
# sha3t its block hash, not only its proof of work.
add_executable(sha3t_kat sha3t_kat.cpp)
target_link_libraries(sha3t_kat PRIVATE
    vkminer_algorithms vkminer_warnings Threads::Threads)
add_test(NAME sha3t_kat COMMAND sha3t_kat)

# The ProgPoW host reference, which is not an algorithm here yet and is checked
# anyway: it is the reference a future kernel would be judged against, the
# vendored code is only worth what this test says it is, and none of it needs a
# device. It builds five light caches -- three seconds on the dev host, more on
# the aarch64 box, and much the most work of any test here that runs on the CPU
# alone, which is what the timeout is sized for.
add_executable(progpow_kat progpow_kat.cpp)
target_link_libraries(progpow_kat PRIVATE ethash vkminer_warnings)
add_test(NAME progpow_kat COMMAND progpow_kat)
set_tests_properties(progpow_kat PROPERTIES TIMEOUT 300)

# The same thirteen vectors again, from the other side: KawPoW's inner loop
# rewritten as a program that is generated once per period and then interpreted,
# which is the only form sixteen invocations in lockstep can run. The test above
# says the vendored reference is right; this one says the restructuring the
# kernel needs does not change the answer -- on the host, where a disagreement
# has one new implementation in it rather than two. Same five light caches, so
# the same timeout.
add_executable(kawpow_program_kat kawpow_program_kat.cpp)
target_link_libraries(kawpow_program_kat PRIVATE
    vkminer_algorithms ethash vkminer_warnings Threads::Threads)
add_test(NAME kawpow_program_kat COMMAND kawpow_program_kat)
set_tests_properties(kawpow_program_kat PROPERTIES TIMEOUT 300)

# The same interpreter again, for the forks of it: against the only vectors any
# of them published, and against shares a pool accepted where there are none. No
# vendored second opinion exists here -- see the file -- so this is what stands
# between a fork's row of constants and a live pool. Light caches by the dozen,
# the largest at epoch 1092 and 152 MiB, so twice the timeout above.
add_executable(progpow_variants_kat progpow_variants_kat.cpp)
target_link_libraries(progpow_variants_kat PRIVATE
    vkminer_algorithms vkminer_warnings Threads::Threads)
add_test(NAME progpow_variants_kat COMMAND progpow_variants_kat)
set_tests_properties(progpow_variants_kat PROPERTIES TIMEOUT 600)

# One level up again: not whether a header hashes correctly, but whether a
# mining.notify turns into the right header in the first place.
add_executable(stratum_header_kat stratum_header_kat.cpp)
target_link_libraries(stratum_header_kat PRIVATE
    vkminer_algorithms vkminer_warnings Threads::Threads)
add_test(NAME stratum_header_kat COMMAND stratum_header_kat)

# The same level, for the dialect where there is no header to assemble: the
# pool's own hash of one, a block height, a nonce prefix and a mix hash going
# back. Needs no device -- everything a KawPoW pool can be misunderstood about
# happens before the first dispatch.
add_executable(stratum_kawpow_kat stratum_kawpow_kat.cpp)
target_link_libraries(stratum_kawpow_kat PRIVATE
    vkminer_algorithms vkminer_warnings Threads::Threads)
add_test(NAME stratum_kawpow_kat COMMAND stratum_kawpow_kat)
set_tests_properties(stratum_kawpow_kat PROPERTIES TIMEOUT 300)

# The tuning file: whether an entry comes back only for the device, driver,
# algorithm and shader it was measured on. Needs no GPU, because what is being
# checked is the bookkeeping around a measurement rather than the measurement.
add_executable(tune_cache_test tune_cache_test.cpp)
target_link_libraries(tune_cache_test PRIVATE
    vkminer_tune_cache vkminer_warnings Threads::Threads)
add_test(NAME tune_cache COMMAND tune_cache_test)

# The first test of the assembled binary rather than of something linked out of
# it. It exists because --time-limit shipped parsed-but-never-read: accepted,
# documented in --help, and doing nothing. It asserts only that the miner stops
# by itself and stops with 0 -- CTest's TIMEOUT catches the regression, because
# the bug guarded against looks exactly like a miner that runs forever.
#
# The null backend keeps it honest on a machine with no GPU: no device, no
# shaders, no skip, so this runs everywhere the project builds.
add_test(NAME time_limit
    COMMAND vkminer --backend null -a sha256d --benchmark --time-limit 3)
set_tests_properties(time_limit PROPERTIES TIMEOUT 20)

# Reconnect, against a Stratum server written to misbehave. The three ways a
# pool connection ends -- the socket breaking, the pool going quiet, and the
# pool sending client.reconnect -- each reach the recovery path by a different
# route, and none of them can be provoked on cue from a real pool.
#
# On the null backend, so it needs no GPU -- which leaves shares uncovered;
# point it at --backend vulkan by hand for those. Three of its four assertions
# are about something not happening for a while, which makes it much the
# slowest test here, so it is labelled for ctest -LE slow.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME reconnect COMMAND ${Python3_EXECUTABLE}
        "${CMAKE_CURRENT_SOURCE_DIR}/reconnect_test.py"
        --miner "$<TARGET_FILE:vkminer>" --backend null)
    set_tests_properties(reconnect
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300 LABELS slow)

    # The other stratum, against the same pool taught to serve it. A KawPoW
    # pool sends the hash of a header rather than a coinbase, pushes a 256-bit
    # target with a method of its own, and reads a five-field submit -- and the
    # arrival of that method must not change how a job is parsed, in either
    # dialect. stratum_kawpow_kat proves the parsing without a socket; this
    # proves the miner gets there with one.
    #
    # Runs on the null backend, so it needs no GPU and finds no shares; add
    # --backend vulkan --require-shares by hand for the submit path. Kept out of
    # the slow label because a dialect regression should show up in the fast
    # suite, at the cost of half a minute.
    add_test(NAME dialect COMMAND ${Python3_EXECUTABLE}
        "${CMAKE_CURRENT_SOURCE_DIR}/dialect_test.py"
        --miner "$<TARGET_FILE:vkminer>" --backend null --seconds 10)
    set_tests_properties(dialect PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300)

    # A pool reply split across two writes, with a gap longer than the one
    # second stratum_recv_line gives the tail. The connection has to survive it:
    # a redial refuses every share found before the drop, since the new session
    # never issued their job ids.
    #
    # Needs no device; the read path is what is under test.
    add_test(NAME splitline COMMAND ${Python3_EXECUTABLE}
        "${CMAKE_CURRENT_SOURCE_DIR}/splitline_test.py"
        --miner "$<TARGET_FILE:vkminer>" --backend null)
    set_tests_properties(splitline PROPERTIES TIMEOUT 300)

    # A ProgPoW pool whose seed hash is not the epoch its own height says,
    # reported once and deduped over later jobs. The zero arm is the trap: all
    # zeros is epoch 0's real seed hash *and* what an unfilled field looks like,
    # so a dedupe whose sentinel is a zeroed buffer goes silent on the likeliest
    # real pool bug.
    #
    # Needs no device: the check runs as a notify is parsed.
    add_test(NAME seed_mismatch COMMAND ${Python3_EXECUTABLE}
        "${CMAKE_CURRENT_SOURCE_DIR}/seed_mismatch_test.py"
        --miner "$<TARGET_FILE:vkminer>" --backend null)
    set_tests_properties(seed_mismatch PROPERTIES TIMEOUT 300)

    # The control API over HTTP: the bodies a route refuses, its privilege and
    # flag gates, and the profile it declines to half-apply. Nothing else in the
    # suite reaches those -- control_test calls the request functions directly,
    # behind the route.
    #
    # Needs no GPU and no credentials. Five miners start and stop in sequence,
    # which is where the half-minute goes rather than any one assertion.
    add_test(NAME control_api COMMAND ${Python3_EXECUTABLE}
        "${CMAKE_CURRENT_SOURCE_DIR}/control_test.py"
        --miner "$<TARGET_FILE:vkminer>" --backend null)
    set_tests_properties(control_api
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300)

    # A job id is not unique. Pools that switch between coins re-send one, and
    # the miner has to come back to it with a coinbase it has not used before or
    # it re-submits nonces it already sent. This pool re-sends a job on purpose
    # and fails on any repeated submission.
    #
    # Runs wherever shares are produced. The difficulty is an opening bid and
    # vardiff tightens it, so the CPU backend submits hundreds inside a phase
    # and a fast card is held to a rate rather than flooding -- it is registered
    # on the device because that is the configuration worth asserting on, not
    # because it is the only one that works. The null backend still produces
    # nothing. SKIPs where nothing connects, and where too few shares arrive to
    # conclude.
    if(TARGET vkminer_shaders)
        add_test(NAME duplicate_test COMMAND ${Python3_EXECUTABLE}
            "${CMAKE_CURRENT_SOURCE_DIR}/duplicate_test.py"
            --miner "$<TARGET_FILE:vkminer>" --backend vulkan --devices 0)
        set_tests_properties(duplicate_test
            PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300 LABELS slow)

        # A reply says which share it answers only through the id it echoes.
        # With the queue kept full several shares are in flight at once and a
        # pool may answer the newest first, so a miner matching replies by
        # arrival order prints one share's job and difficulty beside another
        # share's verdict. This pool answers out of order on purpose.
        #
        # Needs a device for the same reason as above, and measures the device's
        # share rate before it starts: the miner remembers only the last eight
        # submissions, so the experiment has to be slower than that window.
        add_test(NAME submit_id_test COMMAND ${Python3_EXECUTABLE}
            "${CMAKE_CURRENT_SOURCE_DIR}/submit_id_test.py"
            --miner "$<TARGET_FILE:vkminer>" --backend vulkan --devices 0)
        set_tests_properties(submit_id_test
            PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300 LABELS slow)

        # A kernel that hashes wrongly has to be refused by the self-test the
        # switch runs, with nothing submitted anywhere -- not discovered later
        # as a reject rate on a pool. The bad shader is built by the test from
        # the shipped one, with its length padding changed by a digit, and
        # reaches the miner through --algo-dir; neither the tree nor the build
        # directory is written to.
        #
        # Needs a device: that self-test is skipped on the null backend, which
        # is the whole of what this proves. SKIPs where glslc is not installed,
        # because then the wrong shader cannot be built and the good one would
        # pass every assertion for the wrong reason.
        add_test(NAME switch_selftest COMMAND ${Python3_EXECUTABLE}
            "${CMAKE_CURRENT_SOURCE_DIR}/switch_selftest_test.py"
            --miner "$<TARGET_FILE:vkminer>")
        set_tests_properties(switch_selftest
            PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900 LABELS slow)

        # A job whose dataset does not fit the device, arriving the two ways it
        # can: at a switch, where there is a profile to fall back to and the
        # miner has to end up running on it with last_error saying why, and at
        # startup, where there is none and the process has to exit non-zero.
        # Costs an allocation attempt rather than a dataset build.
        add_test(NAME oversize_dataset COMMAND ${Python3_EXECUTABLE}
            "${CMAKE_CURRENT_SOURCE_DIR}/oversize_dataset_test.py"
            --miner "$<TARGET_FILE:vkminer>")
        set_tests_properties(oversize_dataset
            PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900 LABELS slow)
    endif()
endif()

# Only exists where shaders were compiled, because there is nothing to embed
# otherwise. No device needed: this is about which bytes get loaded, not about
# running them.
if(TARGET vkminer_shaders)
    add_executable(shader_source_test shader_source_test.cpp)
    target_link_libraries(shader_source_test PRIVATE
        vkminer_shaders vkminer_warnings Threads::Threads)
    add_test(NAME shader_source COMMAND shader_source_test)
    set_tests_properties(shader_source PROPERTIES SKIP_RETURN_CODE 77)
endif()

# Needs a device, so it is not built where there are no shaders to run on one.
# It reports SKIP rather than failing when the machine has no Vulkan: a build
# machine without a GPU is a normal thing, a wrong result is not.
if(VKMINER_VK_SMOKE_SPV)
    add_executable(vk_smoke vk_smoke.cpp)
    target_link_libraries(vk_smoke PRIVATE
        vkminer_backends vkminer_warnings Threads::Threads)
    target_compile_definitions(vk_smoke PRIVATE
        VK_SMOKE_SPV="${VKMINER_VK_SMOKE_SPV}")
    add_dependencies(vk_smoke vkminer_shader_vk_smoke)

    # Beside the binary, so that the test can be copied to the machine with the
    # GPU -- which for the cross builds is never the machine that compiled it.
    add_custom_command(TARGET vk_smoke POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${VKMINER_VK_SMOKE_SPV}" "$<TARGET_FILE_DIR:vk_smoke>")

    add_test(NAME vk_smoke COMMAND vk_smoke)
    set_tests_properties(vk_smoke PROPERTIES SKIP_RETURN_CODE 77)
endif()

# Shared device state, through the backend's real kernel path with an algorithm
# written for the purpose. Same conditions as vk_smoke: a device, or a SKIP.
if(VKMINER_SHARED_STATE_SPV)
    add_executable(shared_state_test shared_state_test.cpp)
    target_link_libraries(shared_state_test PRIVATE
        vkminer_backends vkminer_warnings Threads::Threads)
    target_compile_definitions(shared_state_test PRIVATE
        SHARED_STATE_SPV="${VKMINER_SHARED_STATE_SPV}")
    add_dependencies(shared_state_test vkminer_shader_shared_state)

    add_custom_command(TARGET shared_state_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${VKMINER_SHARED_STATE_SPV}"
                "$<TARGET_FILE_DIR:shared_state_test>")

    add_test(NAME shared_state COMMAND shared_state_test)
    set_tests_properties(shared_state PROPERTIES SKIP_RETURN_CODE 77
                                                 TIMEOUT 600)

    # The DAG generation kernel against the host reference. Two shaders: the
    # one under test, which writes the shared buffer before any dispatch, and
    # the shared-state probe above, which is reused unchanged to read it back
    # -- a window of DAG is a table of digest-shaped words like any other.
    #
    # Not labelled slow, though it builds a light cache on the host, generates
    # eight thousand items on the device and recomputes every one of them on
    # the CPU to compare: it is seconds on a software rasterizer, and it is the
    # only thing that says the DAG kernel is right. The generous timeout is for
    # the aarch64 box, where the light cache alone is most of it.
    if(VKMINER_DAG_SPV)
        add_executable(dag_test dag_test.cpp)
        target_link_libraries(dag_test PRIVATE
            vkminer_backends vkminer_warnings Threads::Threads)
        target_compile_definitions(dag_test PRIVATE
            DAG_SPV="${VKMINER_DAG_SPV}"
            SHARED_STATE_SPV="${VKMINER_SHARED_STATE_SPV}")
        add_dependencies(dag_test
            vkminer_shader_kernels vkminer_shader_shared_state)

        add_custom_command(TARGET dag_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${VKMINER_DAG_SPV}" "${VKMINER_SHARED_STATE_SPV}"
                    "$<TARGET_FILE_DIR:dag_test>")

        add_test(NAME dag_test COMMAND dag_test)
        set_tests_properties(dag_test PROPERTIES SKIP_RETURN_CODE 77
                                                 TIMEOUT 900)
    endif()

    # Whether a device has room, asked before anything is built on it. Reuses
    # the shader above because nothing here dispatches: what is being tested is
    # the decision, and the decision is made from a spec and a device's limits.
    #
    # Cheap for a device test -- two small tables and a handful of pipelines --
    # so it is not labelled slow. Half of it needs no device at all: the
    # declared worst-case epochs are checked before the backend is opened, so a
    # machine that SKIPs the rest still fails on a fork that declares nothing.
    add_executable(would_fit_test would_fit_test.cpp)
    target_link_libraries(would_fit_test PRIVATE
        vkminer_backends vkminer_warnings Threads::Threads)
    target_compile_definitions(would_fit_test PRIVATE
        SHARED_STATE_SPV="${VKMINER_SHARED_STATE_SPV}")
    add_dependencies(would_fit_test vkminer_shader_shared_state)

    add_custom_command(TARGET would_fit_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${VKMINER_SHARED_STATE_SPV}"
                "$<TARGET_FILE_DIR:would_fit_test>")

    add_test(NAME would_fit_test COMMAND would_fit_test)
    set_tests_properties(would_fit_test PROPERTIES SKIP_RETURN_CODE 77
                                                   TIMEOUT 300)
endif()

# The shader against the scalar reference, over a nonce range. Needs the
# embedded SPIR-V, so it exists only where the shaders were compiled; it finds
# its own device and SKIPs when there is none. The generous timeout is for the
# software rasterizer, which is the only device some build machines have.
if(TARGET vkminer_shaders)
    add_executable(diff_test diff_test.cpp)
    target_link_libraries(diff_test PRIVATE
        vkminer_backends vkminer_warnings Threads::Threads)
    add_test(NAME diff_test COMMAND diff_test sha256d 100000)
    set_tests_properties(diff_test PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900)

    # The same for blake2s, and the only place its byte order -- the mirror
    # image of sha256d's -- meets something that computes it independently.
    add_test(NAME diff_test_blake2s COMMAND diff_test blake2s 100000)
    set_tests_properties(diff_test_blake2s
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900)

    # And for the third, over a fifth of the range. Both halves of this
    # comparison compute four thousand Salsa20 cores per nonce, and the host's
    # half is a deliberately unoptimized reference: 20,011 nonces is 11 seconds
    # on the dev host's software rasterizer where the two above are a fifth of
    # one, and the aarch64 box is several times slower again. Hence the shorter
    # range and the label. What it buys is candidates, and twenty of them
    # exercise the same paths a hundred would.
    add_test(NAME diff_test_scrypt COMMAND diff_test scrypt 20011)
    set_tests_properties(diff_test_scrypt
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900 LABELS slow)

    # The first algorithm with two kernels: 64-bit Keccak lanes where the device
    # has shaderInt64, a 2x32 module where it does not. This arm gets whichever
    # the machine has.
    add_test(NAME diff_test_sha3t COMMAND diff_test sha3t 100000)
    set_tests_properties(diff_test_sha3t
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900)

    # And the other one, which a device with the feature would otherwise only
    # compile and never run. --no-int64 withholds the feature at device creation
    # too, so a run that took the 64-bit module anyway fails validation.
    add_test(NAME diff_test_sha3t32 COMMAND diff_test sha3t 100000 --no-int64)
    set_tests_properties(diff_test_sha3t32
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900)

    # The fifth algorithm, which does not go through diff_test: KawPoW hashes
    # against a gigabyte of DAG, and a differential run that generated one would
    # be measuring the setup pass as much as the kernel. This test uploads a
    # small host-built table instead, so the only thing it can disagree about is
    # the hash -- and it is the first test of a kernel where sixteen invocations
    # cooperate on one nonce.
    #
    # Not labelled slow: the host's half is 256 DAG items per nonce recomputed
    # from a light cache, which is a few minutes' worth only if the range is
    # made much larger than the default. The timeout is for the aarch64 box,
    # where building epoch 0's light cache is most of the run.
    add_executable(progpow_test progpow_test.cpp)
    target_link_libraries(progpow_test PRIVATE
        vkminer_backends vkminer_warnings Threads::Threads)
    add_test(NAME progpow_test COMMAND progpow_test 256)
    set_tests_properties(progpow_test PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900)

    # And the other KawPoW kernel: the one whose program is compiled into the
    # pipeline rather than read out of a buffer. It hashes the same nonces both
    # ways and against the host, then crosses a period boundary -- which is the
    # only place a kernel that is rebuilt per period can go wrong invisibly,
    # because a stale pipeline keeps returning perfectly well-formed digests.
    #
    # A smaller range than progpow_test's: every nonce is hashed on the host
    # twice, once per period, and that is the slow half.
    add_executable(progpow_spec_test progpow_spec_test.cpp)
    target_link_libraries(progpow_spec_test PRIVATE
        vkminer_backends vkminer_warnings Threads::Threads)
    add_test(NAME progpow_spec_test COMMAND progpow_spec_test 64)
    set_tests_properties(progpow_spec_test
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900)

    # Both of those again over another fork's row of constants. Only two of the
    # forks have published hashes to be checked against, and the shader gets its
    # constants through specialization -- so for the rest this pair is the whole
    # check that what the device computes is what the host says it should,
    # before a pool is asked. Cheap: the fork changes numbers, not sizes.
    #
    # meowpow and meraki earn the loop: they move the numbers the shader is
    # specialized on -- sixteen registers instead of thirty-two, half the
    # rounds, more cache reads than arithmetic -- so they are where a
    # specialization constant that reached the pipeline but not the array it
    # sizes would show up. meraki is also the only fork that uses the twelfth
    # cache read, the widest the program layout goes.
    # firopow earns it for a different reason: its keccak seal is the vanilla
    # padding rather than a seed-word injection, which is a pair of arrays no
    # other row here puts on a device.
    foreach(fork evrprogpow meowpow meraki firopow)
        add_test(NAME progpow_test_${fork}
            COMMAND progpow_test 256 --fork ${fork})
        set_tests_properties(progpow_test_${fork}
            PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900)

        add_test(NAME progpow_spec_test_${fork}
            COMMAND progpow_spec_test 64 --fork ${fork})
        set_tests_properties(progpow_spec_test_${fork}
            PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900)
    endforeach()

    # The same kernels over a range the other arm cannot reach. Its host oracle
    # walks a DAG per nonce, which is what holds it to 64; two kernels compared
    # against each other are both the device, so the range costs dispatches
    # rather than minutes of CPU. A few dozen nonces select a few dozen paths
    # through a 134-word program, and this is the arm that says the rest of them
    # agree too -- which is what makes it the gate for changing the shader.
    #
    # Weaker per nonce than the arm above, because two kernels sharing a body
    # can share a mistake in it. It runs beside that arm, never instead of it.
    add_test(NAME progpow_wide_diff COMMAND progpow_spec_test 8 --wide 100000)
    set_tests_properties(progpow_wide_diff
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 1800 LABELS slow)

    # The same range with the queue held to one dispatch -- the path
    # --queue-depth 1 selects, and the baseline the pipelining is measured
    # against. It catches a kernel that only works with something queued behind
    # it, and costs one more run of a shader and reference it already has.
    add_test(NAME diff_test_depth1 COMMAND diff_test sha256d 100000 1)
    set_tests_properties(diff_test_depth1
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900)

    # The same dispatch repeatedly, at the size the miner would run it, with the
    # queue full. Where diff_test asks whether the answers are right, this asks
    # whether they are the same answers twice -- which is the only cheap way to
    # see a race, and it needs a full-occupancy dispatch to see one, so it is
    # much the more expensive of the two on a software rasterizer.
    add_executable(race_test race_test.cpp)
    target_link_libraries(race_test PRIVATE
        vkminer_backends vkminer_warnings Threads::Threads)
    add_test(NAME race_test COMMAND race_test sha256d 8)
    set_tests_properties(race_test
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900 LABELS slow)

    # And for the algorithm with the most to race about: sixteen invocations
    # cooperate on one KawPoW nonce and exchange registers twice per round,
    # through a workgroup array on one kernel and subgroup shuffles on another,
    # so a missing barrier there is a wrong digest rather than a slow one.
    # Nothing else here runs that at full occupancy.
    #
    # Against a short host-built table, because the machines this suite has to
    # run on include two software rasterizers. That keeps the whole table in
    # cache, so it cannot open a window that needs the latency of a real DRAM
    # read: --device-dag is that run, by hand, on a card that can build one.
    #
    # It also carries this algorithm's differential test. The host reference
    # walks the table once per hash, which puts a hundred thousand nonces of it
    # out of reach -- but the three kernels can be compared against each other
    # over that many, and a shader edit touches one of them.
    add_test(NAME race_test_kawpow COMMAND race_test kawpow 8)
    set_tests_properties(race_test_kawpow
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 1800 LABELS slow)

    # The negative half of the known-answer test, perturbing the device rather
    # than the host reference. Cheap -- a couple of dozen single-nonce dispatches
    # -- so it is not labelled slow and runs on a software rasterizer too.
    add_executable(negative_kat negative_kat.cpp)
    target_link_libraries(negative_kat PRIVATE
        vkminer_backends vkminer_warnings Threads::Threads)
    add_test(NAME negative_kat COMMAND negative_kat sha256d)
    set_tests_properties(negative_kat PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300)

    add_test(NAME negative_kat_blake2s COMMAND negative_kat blake2s)
    set_tests_properties(negative_kat_blake2s
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300)

    add_test(NAME negative_kat_scrypt COMMAND negative_kat scrypt)
    set_tests_properties(negative_kat_scrypt
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300)

    # Both of sha3t's kernels, for the reason the differential test runs twice,
    # and worth doing per kernel: a lane type that drops the top half of a word
    # is only visible as a perturbed bit in the half being dropped.
    add_test(NAME negative_kat_sha3t COMMAND negative_kat sha3t)
    set_tests_properties(negative_kat_sha3t
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300)

    add_test(NAME negative_kat_sha3t32 COMMAND negative_kat sha3t --no-int64)
    set_tests_properties(negative_kat_sha3t32
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 300)

    # And for the fifth, where the question is sharper than elsewhere. Eight of
    # its nine header words are a hash the pool already computed, so nothing on
    # this side would notice one of them going unread; the ninth is a block
    # height that reaches the digest only through the program it selects, and a
    # kernel that built the program from a stale height would keep returning
    # well-formed answers. Both are single-bit perturbations here.
    #
    # Against the interpreter, which is what kernel() offers -- the specialized
    # kernels are held to it digest for digest by progpow_wide_diff, so the two
    # together say what running this per kernel would.
    add_test(NAME negative_kat_kawpow COMMAND negative_kat kawpow)
    set_tests_properties(negative_kat_kawpow
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900)

    # The calibration for --vk-probe-best, which is the only instrument that
    # says anything about the nonces a kernel did *not* find. It is checked
    # against the scalar reference at a size the host can hash, against itself
    # at the size the device really runs, and -- because a single reading is a
    # minimum and so a random quantity -- against its expectation over a few
    # hundred dispatches that share neither header nor nonce range.
    add_executable(probe_test probe_test.cpp)
    target_link_libraries(probe_test PRIVATE
        vkminer_backends vkminer_warnings Threads::Threads)
    add_test(NAME probe_test COMMAND probe_test sha256d 4)
    set_tests_properties(probe_test
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900 LABELS slow)

    # Per algorithm, because which word a kernel hands to probe_best is the
    # kernel's decision: a shader that screens on the right word and reports the
    # wrong one mines correctly and lies about it.
    add_test(NAME probe_test_blake2s COMMAND probe_test blake2s 4)
    set_tests_properties(probe_test_blake2s
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900 LABELS slow)

    add_test(NAME probe_test_scrypt COMMAND probe_test scrypt 4)
    set_tests_properties(probe_test_scrypt
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900 LABELS slow)

    # Once for sha3t, not twice: which word reaches probe_best is written in the
    # kernel body both modules include, so they cannot disagree about it.
    add_test(NAME probe_test_sha3t COMMAND probe_test sha3t 4)
    set_tests_properties(probe_test_sha3t
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 900 LABELS slow)

    # And for the fifth, whose kernel hands the probe a word computed by
    # sixteen invocations between them rather than by the one that reports it.
    # Its header is nine words, so this is also the arm that runs with a header
    # shorter than the block the file carries -- and the arm whose exact check
    # is bounded by the host rather than by the device, since its reference
    # walks a DAG per nonce.
    #
    # Once, not three times, unlike the race arm above: which word reaches the
    # probe is written in the body all three kernels are built from, so they
    # cannot disagree about it.
    add_test(NAME probe_test_kawpow COMMAND probe_test kawpow 4)
    set_tests_properties(probe_test_kawpow
        PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 1800 LABELS slow)
endif()
