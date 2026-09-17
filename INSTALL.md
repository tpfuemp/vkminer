# Installing vkminer

This covers getting a built vkminer onto a machine and running. For what it is and how to
build it, see [README.md](README.md); for the options, see the table there.

vkminer is a single executable. The shaders are compiled to SPIR-V at build time and
**embedded in the binary**, so there is no data directory to install alongside it and nothing
to set up before the first run. Copying the one file is a complete installation.

> There is no published release yet, so there is nothing to download. Until there is, the
> archive described below is one you build yourself with `./package.sh`, which is also what a
> release would be made with.

## 1. Install a driver first

This is the step that actually fails. vkminer links no GPU library -- it resolves the Vulkan
loader at run time -- so it builds and starts on a machine with no working driver and then
finds no device.

Check before anything else:

```sh
vulkaninfo --summary
```

Your GPU should be listed. If the command is missing, install it: `vulkan-tools` on Debian
and Ubuntu, `vulkan-tools` or `vulkan-utils` elsewhere.

| Hardware | What provides Vulkan |
| :--- | :--- |
| NVIDIA | The proprietary driver. It ships its own Vulkan support; nothing else is needed |
| AMD | Mesa's RADV, in `mesa-vulkan-drivers`. AMD's own `amdvlk` also works |
| Intel | Mesa's ANV, in the same package |
| Windows | The vendor's normal desktop driver. Vulkan is part of it |

If `vulkaninfo` lists only `llvmpipe` or `lavapipe`, that is Mesa's software rasterizer: it
is a CPU pretending to be a GPU. vkminer will run on it and will be far slower than mining on
the CPU directly. Fix the driver rather than mining on it.

## 2. Install the binary

### From an archive

The archive unpacks to a single directory holding the executable and these documents:

```sh
tar xf vkminer-0.1.0-dev-linux-x86_64.tar.gz
cd vkminer-0.1.0-dev-linux-x86_64
./vkminer --version
```

To put it on your `PATH`, copy the one file:

```sh
mkdir -p ~/.local/bin
cp vkminer ~/.local/bin/
```

**A Linux build is not portable between distributions.** It links libcurl, jansson,
OpenSSL and libstdc++ from the machine it was built on, and an archive built on a newer
distribution will fail on an older one with a `GLIBC_` or `libcurl.so` error. Build on the
machine you intend to run on, or on one no newer than it. `package.sh` prints the libraries
the binary needs so you can check.

The Windows `.exe` has no such problem: it is linked statically and imports only DLLs that
ship with Windows, which `build-win.sh` verifies every time it builds. Copy it anywhere and
run it.

### From source

Build as [README.md](README.md) describes, then either run it out of the build directory or
let CMake install it:

```sh
cmake --install build --prefix ~/.local
```

That writes `bin/vkminer` under the prefix and nothing else. With no `--prefix` it installs to
the system default, which needs `sudo`.

## 3. Configure it

Copy the template and edit the copy:

```sh
cp config-template.json config.json
vkminer -c config.json
```

`config.json` is ignored by git, so credentials in it cannot be committed by accident. Keys
beginning with `_` are comments and are ignored. Any long option works as a key, and anything
given on the command line overrides the file.

## 4. Check the installation

```sh
vkminer --device-list     # the GPUs it can see, with the indices --devices takes
vkminer --self-test       # hash the built-in known answers and exit
```

`--self-test` is the one that matters: it runs every algorithm's kernel against published
test vectors and fails loudly if the GPU is not hashing correctly. A card that passes
`--device-list` and fails this should not be mined on.

## 5. Where vkminer writes

It never writes to its own directory, so the executable can live somewhere read-only.

| File | Linux | Windows |
| :--- | :--- | :--- |
| `tune.json` -- measured workgroup and queue depth per device | `$XDG_CONFIG_HOME/vkminer/` or `~/.config/vkminer/` | `%APPDATA%\vkminer\` |
| `failed-candidates.log` -- written only when a device disagrees with the CPU re-check | the same directory | the same directory |
| the Vulkan pipeline cache -- compiled shaders, so later runs start faster | `$XDG_CACHE_HOME/vkminer/` or `~/.cache/vkminer/` | `%LOCALAPPDATA%\vkminer\` |

All three are caches in the sense that deleting them costs time and nothing else: the tuning
is measured again on the next run, and the pipeline cache is rebuilt.

**`failed-candidates.log` is not a cache.** It exists because the device reported a share the
CPU then refused, which is the one symptom that means a kernel, a driver or an overclock is
wrong. If it appears, read it -- `--replay` re-runs its contents through the same shader.

## 6. Upgrading

Replace the executable. Nothing else is versioned on disk, and `tune.json` is keyed by device,
driver build, algorithm *and* a hash of the shader, so a new build measures itself again
instead of trusting an old answer. There is no migration step and no need to clear anything.

## 7. Uninstalling

```sh
rm ~/.local/bin/vkminer                  # or wherever it was copied
rm -r ~/.config/vkminer ~/.cache/vkminer # the tuning and the pipeline cache
```

On Windows, delete the `.exe` and the `vkminer` folders under `%APPDATA%` and `%LOCALAPPDATA%`.

## 8. When it will not start

| Symptom | Cause |
| :--- | :--- |
| `no Vulkan devices found` | No driver, or a driver the loader cannot see. `vulkaninfo --summary` will fail the same way; fix that first |
| It lists `llvmpipe` or `lavapipe` only | Software rasterizer -- see step 1 |
| `error while loading shared libraries` | A Linux binary built on another machine. Build it here |
| `unknown algorithm` | Check the spelling against the table in [README.md](README.md). Unknown names are refused at startup rather than mined wrongly |
| A self-test failure | Report it. Include the output of `--device-list` and `vulkaninfo --summary`, your driver version, and the algorithm |
| It starts, connects, and every share is rejected | Wrong algorithm for that pool's port, or the wrong address format. Nothing reaches a pool unverified, so a rejection is about the job rather than the hashing |

## License

GPLv3 or later -- see [COPYING](COPYING) and [AUTHORS](AUTHORS).
