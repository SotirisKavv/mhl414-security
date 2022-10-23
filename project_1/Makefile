OBJS = demoprogram.o simple_crypto.o
SOURCE = demoprogram.c simple_crypto.c
HEADER = simple_crypto.h
OUT = demoprogram
CC = gcc
FLAGS = -g -c

$(OUT): $(OBJS)
	$(CC) -g $(OBJS) -o $@

demoprogram.o: demoprogram.c
	$(CC) $(FLAGS) demoprogram.c

simple_crypto.o: simple_crypto.c
	$(CC) $(FLAGS) simple_crypto.c

clean:
	rm -f $(OBJS) $(OUT)