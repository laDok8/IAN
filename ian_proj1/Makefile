CC=gcc
CFLAGS=-Wall -std=c11 -pedantic  -fsanitize=address -lelf
all: ian-proj1
ian-proj1: ian-proj1.o
	$(CC) $^ -o $@ $(CFLAGS)
%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm ian-proj1 ian-proj1.o
