CC=gcc
BIN=vuln
CFLAGS=-marm -fno-stack-protector -z execstack -no-pie

all: $(BIN)

$(BIN): %: %.c
	$(CC) -o $@ $<

clean:
	rm $(BIN)
