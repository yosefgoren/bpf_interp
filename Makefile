all: main

CFLAGS += -g -I./libpcap -L. -Wl,-rpath=/root/projects/shm -Wall
LIBRARIES += ./libpcap.so.1

data.h: datagen.py packets.json filters.json
	./$< > $@

main: main.c data.h interp.h
	$(CC) $(CFLAGS) $< $(LIBRARIES) -o $@ 

clean:
	rm -f main data.h