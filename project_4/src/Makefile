OBJS = main.o rsa.o utils.o
SOURCE = main.c rsa.c utils.c
HEADER = rsa.h utils.h
OUT = assign_3
CC = gcc
FLAGS = -O2 -Wall -g -c

$(OUT): $(OBJS)
	$(CC) -g $(OBJS) -o $@ -lm

main.o: main.c
	$(CC) $(FLAGS) main.c

rsa.o: rsa.c
	$(CC) $(FLAGS) rsa.c

utils.o: utils.c
	$(CC) $(FLAGS) utils.c

clean:
	rm -f $(OBJS) $(OUT)