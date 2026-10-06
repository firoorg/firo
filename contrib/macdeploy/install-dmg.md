
# Building and Installing `dmg` from libdmg-hfsplus

## Prerequisites

- CMake (version 2.6 or newer)
- GNU Make
- C/C++ compiler (e.g., gcc/g++)
- zlib development package

### On Debian/Ubuntu, install prerequisites:
```bash
sudo apt-get update
sudo apt-get install build-essential cmake zlib1g-dev
```

## Build Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/theuni/libdmg-hfsplus.git
   cd libdmg-hfsplus
   ```

2. **Configure the build:**
   ```bash
   cmake -S . -B build
   ```

3. **Build only the `dmg` tool:**
   ```bash
   cmake --build build --target dmg
   ```
   *or, equivalently:*
   ```bash
   make -C build dmg
   ```

4. **Install the `dmg` binaries:**
   ```bash
   sudo make -C build install
   ```

## Uninstall

To uninstall, simply remove the binaries:
```bash
sudo rm /usr/local/dmg /usr/local/hdutil /usr/local/hfsplus
```
