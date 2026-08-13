# vkminer

A cryptocurrency miner that does its hashing on the GPU through **Vulkan compute**.

Where `ccminer` needs CUDA and an NVIDIA card, and an OpenCL miner needs a vendor runtime,
vkminer targets the one GPU API that every current desktop and mobile driver implements. One
set of shaders is meant to run on NVIDIA, AMD, Intel, the Mesa drivers and, eventually,
mobile GPUs — without a vendor SDK anywhere in the build.

> ### Status: it mines, but it is young
>
> Four algorithms work — **SHA-256d, Blake2s, Scrypt (N=1024) and SHA3-256t** — and each has
> had shares accepted by a real pool. There is no tagged release and no binary to download:
> build it yourself, and expect the command-line surface to keep moving.
>
> It has been run on NVIDIA cards (Pascal and Ampere, proprietary driver) and on Mesa's
> `lavapipe` software rasterizer, on x86-64 and on aarch64. **No AMD or Intel GPU has been
> tested yet.** The shaders are written to run there and nobody has confirmed that they do.

## Why Vulkan

- **One code path.** SPIR-V is the same binary format on every driver. There is no
  per-vendor kernel source, and no separate CUDA/HIP/OpenCL build.
- **No SDK at build time.** The Vulkan loader is resolved at runtime, so the binary links no
  GPU library and runs on a machine that has only a driver installed.
- **Reaches past the desktop.** Vulkan 1.1 is the baseline, which keeps mobile and embedded
  GPUs in scope rather than ruling them out by accident.

## Algorithms

| Algorithm | Status |
| :--- | :--- |
| `sha256d` | Working. Pool shares accepted |
| `blake2s` | Working. Pool shares accepted. Blakecoin is a *different* algorithm — BLAKE-256, eight rounds — and is not this one |
| `scrypt` | Working, N=1024, r=1, p=1. Pool shares accepted. The one memory-bound kernel: 128 KiB of scratchpad per invocation, so how many hashes fit is a property of the card |
| `sha3t` | Working. Three SHA3-256 passes over the 80-byte header, with SHA3 padding rather than Keccak's — `sha3d` is something else. Pool shares accepted from both of its kernels |
| `kawpow` | Planned — needs the DAG machinery, so it comes late |

## Requirements

- A **Vulkan 1.1** driver. `vulkaninfo --summary` should list your GPU.
- CMake 3.20 or newer, and Ninja
- A C++17 compiler
- libcurl and OpenSSL
- jansson, or none: a bundled fallback is used when the system library is missing
- `glslangValidator` or `glslc`, to compile the shaders

On Debian and Ubuntu:

```sh
sudo apt install build-essential cmake ninja-build pkg-config \
                 libcurl4-openssl-dev libjansson-dev libssl-dev zlib1g-dev \
                 glslang-tools vulkan-tools mesa-vulkan-drivers
```

`mesa-vulkan-drivers` provides the driver for Intel and AMD GPUs. NVIDIA cards use the
proprietary driver, which ships its own Vulkan support.

## Building

```sh
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

For a Windows binary, cross-compile with mingw-w64:

```sh
cmake -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake
cmake --build build-win
```

Two scripts wrap those, for the flags that are tedious to retype:

```sh
./build-linux.sh -t      # configure if needed, build, run the tests
./build-win.sh           # the cross build, and check what the .exe imports
./build-linux.sh -h      # -c to start clean, -d for a debug build, -j N
```

On 64-bit ARM, build natively on the target. No cross-compilation is involved and no extra
flags are needed.

## Running

List the GPUs vkminer can see, and check that the one you want is not a software
implementation:

```sh
./build/vkminer --device-list
```

If that prints `llvmpipe`, `lavapipe`, or a device type of `CPU`, you are looking at a
software rasterizer and no GPU is being used. Install or fix your driver first.

Then point it at a pool:

```sh
./build/vkminer -a sha256d \
                -o stratum+tcp://pool.example.com:3333 \
                -u YOUR_WALLET_ADDRESS.worker1 \
                -p x
```

Or use a configuration file, which accepts any long option:

```sh
cp config-template.json config.json     # then edit config.json
./build/vkminer -c config.json
```

`config.json` is git-ignored, so your credentials cannot be committed by accident.

### Options

| Option | Meaning |
| :--- | :--- |
| `-a, --algo NAME` | Algorithm to mine |
| `-o, --url URL` | Pool URL, `stratum+tcp://host:port` |
| `-u, --user USER` | Wallet address or pool username, usually `ADDRESS.WORKER` |
| `-p, --pass PASS` | Pool password, often just `x` |
| `-c, --config FILE` | Read options from a JSON file |
| `--device-list` | List the Vulkan devices found, with their indices, and exit |
| `--devices LIST` | GPUs to use, by index: `--devices 0,2`. Default is all |
| `--backend NAME` | `vulkan` (default), or `cpu` to run each algorithm's reference implementation — the control the GPU is checked against |
| `--benchmark` | Measure hashrate without connecting to a pool. Never submits |
| `--self-test` | Run the built-in known-answer tests and exit |
| `--hash-meter` | Log each worker's rate, not just the total |
| `--vk-validate` | Enable Vulkan validation layers. Much slower; for debugging |
| `--no-int64` | Report every device as lacking `shaderInt64`, so an algorithm carrying both a 64-bit and a 32-bit kernel takes the 32-bit one |
| `--queue-depth N` | Dispatches to keep queued on each GPU at once. Leave it alone to mine; set it to compare throughput at one depth against another |
| `--workgroup N` | Invocations per workgroup. The other half of the same idea: leave it alone to mine, set it to compare two runs at two widths |
| `--retune` | Measure the workgroup size and queue depth again, even though they are already known |
| `--no-tune` | Do not measure and do not use a measurement. Two runs of one binary are then comparable |
| `--time-limit N` | Stop cleanly after N seconds of mining, counted from the first job so a slow pool does not eat into it. With `--benchmark`, prints the rate for the whole run on the way out |
| `--api-bind ADDR` | Bind the local status API, e.g. `127.0.0.1:4048` |
| `-q, --quiet` | Reduce logging |
| `-D, --debug` | Increase logging |
| `-V, --version` | Print version and exit |

Option names follow cpuminer where the meaning is the same, so existing scripts and habits
carry over.

### Tuning

The workgroup size a shader runs fastest at differs between vendors, between two cards of one
vendor, and across a driver update, so it is measured rather than compiled in. The first run
on a given card sweeps for a few seconds against the algorithm's own test vector — never
against pool work — and every candidate has to reproduce the published hashes before it is
allowed to win. The answer goes in `%APPDATA%\vkminer\tune.json` or
`~/.config/vkminer/tune.json`, keyed by device, driver build, algorithm and shader, so a new
driver or an edited shader is measured again by itself. A card that will not tune mines at
the built-in defaults.

Where an algorithm has more than one kernel, which one to run is measured the same way rather
than chosen from a feature bit. `sha3t` ships a 64-bit and a 2×32-bit shader, and the faster
of the two is not the one the hardware's advertised support predicts on every card.

Two numbers a reader should not over-read. The rate printed by the sweep is a ranking, not a
benchmark: it is taken in the first seconds of load, which on a thermally capped card are its
best. And a candidate only displaces the default if it beats it by more than the sweep's own
rounds disagreed with each other, so on a noisy device the tuner will decline to move at all.

## Performance

One card, one driver, so read them as an order of magnitude rather than a table to buy
hardware from. Measured on an RTX 3060 under sustained load, not from the tuner's own line:

| Algorithm | Rate |
| :--- | :--- |
| `blake2s` | ~4.6 GH/s |
| `sha256d` | ~750 MH/s |
| `sha3t` | ~240 MH/s |
| `scrypt` | ~300 kH/s |

Scrypt is the one with a fair comparison available: ccminer manages about 408 kH/s on the
same card, so vkminer is at roughly three quarters of a mature CUDA implementation on the
algorithm that stresses memory hardest. Closing that gap is open work.

## How results are verified

A GPU cannot be trusted to have hashed correctly. An overclock, a driver bug or an off-by-one
in a shader all produce plausible-looking garbage, and a miner that submits it earns nothing
while looking busy. So:

1. Every algorithm **self-tests against known answers at startup**, before the first pool
   connection. A broken shader fails immediately and loudly.
2. The shader only *nominates* candidate nonces. Every candidate is **re-hashed on the CPU**
   and checked against the full target before it is submitted. Nothing reaches the pool
   unverified.
3. The test suite compares GPU output against the CPU implementation over large nonce ranges
   and requires them to be identical, on each driver.

If you see a high rejection rate, that is a bug worth reporting — the design intent is that
it cannot happen.

## Reporting problems

Please include:

- the output of `vkminer --device-list` and of `vulkaninfo --summary`
- your GPU, driver version, and operating system
- the algorithm and the pool, and the exact command line with credentials removed

## License

GPLv3 or later. See [COPYING](COPYING) for the license text and [AUTHORS](AUTHORS) for the
lineage — vkminer's pool and option-handling code comes from cpuminer-opt, which offers it
under GPLv2-or-later, and the miner would not exist without that work.
