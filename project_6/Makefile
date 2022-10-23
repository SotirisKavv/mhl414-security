CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
TARGET = assign_6

all: $(TARGET)

$(TARGET): monitor.c
	$(CC) $(CCFLAGS) $(DBUG) monitor.c -o $(TARGET) -lpcap

clean:
	rm -f $(TARGET) *.o
