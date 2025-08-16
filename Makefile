CC=gcc
BIN=vuln
CFLAGS=-marm -fno-stack-protector -z execstack -no-pie -g -static

all: $(BIN)

$(BIN): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm $(BIN)
