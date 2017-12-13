# Compiling the cell dissector

Tested on Debian jessie and stretch only.

1. Prepare

        sudo apt-get build-dep wireshark
        sudo apt-get install libwireshark-dev
        sudo apt-get install libwiretap-dev

1. Compile

        make

1. Install: 

	Copy `cell.so`  to `~/.config/wireshark/plugins`

# Getting the premaster.txt

Compile sslkeylog (provided in a subdirectory), then start the tor daemon using

    SSLKEYLOGFILE=premaster.txt LD_PRELOAD=./libsslkeylog.so /usr/bin/tor ...
