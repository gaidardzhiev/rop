CC=gcc
BIN=ropfinder
CFLAGS=-I/usr/include/capstone -lcapstone

all: $(BIN)

$(BIN): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm $(BIN)
