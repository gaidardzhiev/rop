CC=gcc
BIN=stack_overflow
CFLAGS=-z execstack

all: $(BIN)

$(BIN): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm $(BIN)
