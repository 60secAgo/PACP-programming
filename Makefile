CC=gcc
CFLAGS=-Wall -Wextra
TARGET=sniff_improved
LIBS=-lpcap

all: $(TARGET)

$(TARGET): sniff_improved.c myheader.h
	$(CC) $(CFLAGS) sniff_improved.c -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)
