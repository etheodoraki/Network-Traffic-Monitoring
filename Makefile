all: monitor

monitor: monitor.c 
	gcc monitor.c -o monitor -lpcap

clean:
	rm -rf monitor
