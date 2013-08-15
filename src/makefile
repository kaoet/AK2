CFLAGS=-Wall -Werror -std=gnu99
LIBS=-lm -lrt

main: main.o executor.o log.o hash.o
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
.PHONY: clean indent
clean:
	rm *.o main *.c~
indent:
	indent -linux *.c
