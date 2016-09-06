SOURCE := sslkeylog.c
TARGET := libsslkeylog.so

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCE)
	gcc $< -shared -o $@ -fPIC -ldl

clean:
	rm -f $(TARGET)
