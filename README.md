# Tor cell dissector plugin for Wireshark

## Compilation

Compiling the dissector requires a C compiler, Make, and Wireshark development files, as well as Python3 for some code generation.

Those requirements can be installed on Debian or Ubuntu with the following command:
```
apt-get install build-essential make libwireshark-dev libwiretap-dev python3 wireshark-dev
```

Once you have installed the requirements, the dissector can be build with `make`:
```
make
```

To use the dissector, you need copy the resulting library `cell.so` to your local Wireshark directory (on Linux, `~/.local/lib/wireshark/plugins/x.y/epan` where `x.y` is the version of Wireshark).


## Usage

To analyse the cells, Wireshark requires the encryption keys used by tor.
They can be retrieved by loading the symbols from `sslkeylog` (provided in its own subdirectory) when running the Tor daemon.

```
SSLKEYLOGFILE=premaster.txt LD_PRELOAD=./libsslkeylog.so /usr/bin/tor [...]
```
