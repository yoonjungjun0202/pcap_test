CC = gcc
TARGET = pcap_test
OBJECTS = pcap_test.c
LIBS = -lpcap

all : $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LIBS)

clean:
	rm $(TARGET)
