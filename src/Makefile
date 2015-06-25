CFLAGS=-Wall -std=gnu99
LIBS=-lm -lrt -lpthread

.PHONY: clean indent release debug

debug: CFLAGS += -DDEBUG -g
debug: ak2

release: CFLAGS += -O3
release: ak2

ak2: main.o executor.o log.o vector.o
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

executor.o: executor.h log.h
main.o: executor.h log.h vector.h
log.o: log.h
vector.o: vector.h

clean:
	-rm *.o ak2 *.c~
indent:
	indent -linux *.c
