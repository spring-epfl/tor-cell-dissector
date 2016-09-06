ifneq (,$(wildcard /usr/share/pyshared/make-dissector-reg.py))
MAKE_DIS_REG := /usr/share/pyshared/make-dissector-reg.py
else
MAKE_DIS_REG := tools/make-dissector-reg.py
endif

.PHONY: all clean

all: cell.so

cell.so: packet-cell.c.o plugin.c.o
	gcc -fPIC -Wall -W -Wextra -Wendif-labels -Wpointer-arith -Warray-bounds -Wformat-security -fwrapv -fno-strict-overflow -fno-delete-null-pointer-checks -Wvla -Waddress -Wattributes -Wdiv-by-zero -Wignored-qualifiers -Wpragmas -Wno-overlength-strings -Wwrite-strings -Wno-long-long -fexcess-precision=fast -Wc++-compat -Wdeclaration-after-statement -Wshadow -Wno-pointer-sign -Wold-style-definition -Wstrict-prototypes -Wlogical-op -Wjump-misses-init -fvisibility=hidden -O2 -g -DNDEBUG -Wl,--as-needed -pie -shared -Wl,-soname,cell.so -o cell.so plugin.c.o packet-cell.c.o -lwireshark -lwiretap -lz -lwsutil -ldl -lgmodule-2.0 -lglib-2.0 -lglib-2.0 -lpcap -lcares -lkrb5 -lk5crypto -lcom_err -lGeoIP -lgcrypt -lgpg-error -lgnutls -lsmi -lm -llua5.2

plugin.c: packet-cell.c
	python $(MAKE_DIS_REG) . plugin packet-cell.c

packet-cell.c.o: packet-cell.c
	gcc -DG_DISABLE_DEPRECATED -DG_DISABLE_SINGLE_INCLUDES -Dcell_EXPORTS -Wall -W -Wextra -Wendif-labels -Wpointer-arith -Warray-bounds -Wformat-security -fwrapv -fno-strict-overflow -fno-delete-null-pointer-checks -Wvla -Waddress -Wattributes -Wdiv-by-zero -Wignored-qualifiers -Wpragmas -Wno-overlength-strings -Wwrite-strings -Wno-long-long -fexcess-precision=fast -Wc++-compat -Wdeclaration-after-statement -Wshadow -Wno-pointer-sign -Wold-style-definition -Wstrict-prototypes -Wlogical-op -Wjump-misses-init -fvisibility=hidden -I/usr/include/wireshark -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -O2 -g -DNDEBUG -fPIC -o packet-cell.c.o -c packet-cell.c

plugin.c.o: plugin.c
	gcc -DG_DISABLE_DEPRECATED -DG_DISABLE_SINGLE_INCLUDES -Dcell_EXPORTS -Wall -W -Wextra -Wendif-labels -Wpointer-arith -Warray-bounds -Wformat-security -fwrapv -fno-strict-overflow -fno-delete-null-pointer-checks -Wvla -Waddress -Wattributes -Wdiv-by-zero -Wignored-qualifiers -Wpragmas -Wno-overlength-strings -Wwrite-strings -Wno-long-long -fexcess-precision=fast -Wc++-compat -Wdeclaration-after-statement -Wshadow -Wno-pointer-sign -Wold-style-definition -Wstrict-prototypes -Wlogical-op -Wjump-misses-init -fvisibility=hidden -O2 -g -DNDEBUG -fPIC -I/usr/include/wireshark -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -o plugin.c.o -c plugin.c

clean:
	rm -f plugin.c.o packet-cell.c.o plugin.c cell.so
