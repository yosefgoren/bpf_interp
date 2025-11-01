all: main

CFLAGS += -g -I./libpcap -L. -Wl,-rpath=/root/projects/shm -Wall -Wno-unused-function
LIBRARIES += ./libpcap.so.1

OBJS = main.o yogo_interp.o
HEADERS = data.h interp.h

data.h: datagen.py packets.json filters.json
	./$< > $@

%.o: %.c $(HEADERS)
	$(CC) -c $(CFLAGS) $< -o $@

main: $(OBJS)
	$(CC) $(CFLAGS) $^ $(LIBRARIES) -o $@ 

clean:
	rm -f main $(OBJS) data.h