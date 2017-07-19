CC = gcc
TARGET = pcap_test
OBJECTS = pcap_test.c my_pcap.c
LIBS = -lpcap

all : $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LIBS)

clean:
	rm $(TARGET)
