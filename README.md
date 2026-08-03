# vkminer

A cryptocurrency miner that does its hashing on the GPU through **Vulkan compute**.

Where `ccminer` needs CUDA and an NVIDIA card, and an OpenCL miner needs a vendor runtime,
vkminer targets the one GPU API that every current desktop and mobile driver implements. One
set of shaders is meant to run on NVIDIA, AMD, Intel, the Mesa drivers and, eventually,
mobile GPUs — without a vendor SDK anywhere in the build.

> ### Status: early development
>
> **There is nothing to mine with yet.** The pool-side plumbing is being ported and the first
> compute kernel is not finished. No algorithm is usable, no release has been made, and the
> command lines below describe the intended interface rather than a working program.
>
> Watch the repository if you are interested; there is no point trying to build it for
> production use today.

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
| SHA-256d | planned — first target |
| Blake2s / Blakecoin | planned |
| Scrypt (N=1024) | planned |
| KawPoW | planned — needs the DAG machinery, so it comes late |

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

On 64-bit ARM, build natively on the target. No cross-compilation is involved and no extra
flags are needed.

## Running

List the GPUs vkminer can see, and check that the one you want is not a software
implementation:

```sh
./build/vkminer --devices
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
| `--devices LIST` | GPUs to use, by index: `--devices 0,2`. Default is all |
| `--benchmark` | Measure hashrate without connecting to a pool. Never submits |
| `--self-test` | Run the built-in known-answer tests and exit |
| `--vk-validate` | Enable Vulkan validation layers. Much slower; for debugging |
| `--api-bind ADDR` | Bind the local status API, e.g. `127.0.0.1:4048` |
| `-q, --quiet` | Reduce logging |
| `-D, --debug` | Increase logging |
| `-V, --version` | Print version and exit |

Option names follow cpuminer where the meaning is the same, so existing scripts and habits
carry over.

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

- the output of `vkminer --devices` and of `vulkaninfo --summary`
- your GPU, driver version, and operating system
- the algorithm and the pool, and the exact command line with credentials removed

## License

GPLv3 or later. See [COPYING](COPYING) for the license text and [AUTHORS](AUTHORS) for the
lineage — vkminer's pool and option-handling code comes from cpuminer-opt, which offers it
under GPLv2-or-later, and the miner would not exist without that work.
