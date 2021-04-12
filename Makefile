ifneq (,$(wildcard /usr/share/pyshared/make-plugin-reg.py))
MAKE_DIS_REG := /usr/share/pyshared/make-plugin-reg.py
else
echo "Install wireshark developpement files (apt-get install wireshark-dev)"
exit
endif

PLUGIN_VERSION='"0.0.2"'

CFLAGS=-fPIC -O2 -Wall -Wextra -DPLUGIN_VERSION=$(PLUGIN_VERSION)
INCLUDES=`pkg-config --cflags wireshark`
LDFLAGS=`pkg-config --libs wireshark` -lm


.PHONY: all clean


all: cell.so


cell.so: packet-cell.c.o plugin.c.o
	$(CC) ${CFLAGS} ${INCLUDES} -Wl,--as-needed -pie -shared -Wl,-soname,$@ -o $@ $^ ${LDFLAGS}


plugin.c: packet-cell.c
	python3 $(MAKE_DIS_REG) . plugin packet-cell.c


packet-cell.c.o: packet-cell.c
	$(CC) -DG_DISABLE_DEPRECATED -DG_DISABLE_SINGLE_INCLUDES ${CFLAGS} ${INCLUDES} -o $@ -c $^


plugin.c.o: plugin.c
	$(CC) -DG_DISABLE_DEPRECATED -DG_DISABLE_SINGLE_INCLUDES ${CFLAGS} ${INCLUDES} -o $@ -c $^


clean:
	rm -f plugin.c.o packet-cell.c.o plugin.c cell.so
