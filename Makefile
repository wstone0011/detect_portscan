all: sniffer.cpp
	g++ sniffer.cpp -lpcap -o sniffer

clean:
	rm -f *.o sniffer

