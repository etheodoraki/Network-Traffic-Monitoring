# Network-Traffic-Monitoring
Network traffic monitoring using the Packet Capture library
 Theodoraki Emmanouela
AM: 2014030238

### [ACE414] - Assignment 6

to build: >make all ( gcc monitor.c -o monitor -lpcap )
to clean: >make clean (	rm -rf monitor )

# Usage Options:
	> sudo 	./monitor -i <interface name> :Network interface name (e.g. any, wlp8s0)
	> ./monitor -r <pcap filename>        :Packet capture filename (e.g. test.pcap)
	> ./monitor -h                        :Help message

If the Network interface entered doesn't exist, a list of all available devices will be printed 
in order to select a valid one on the next try.

### (i) On the first option -i
    the packet capture is implemented using pcap_open_live for the chosen device

### (ii) On the first option -r
    the packet capture is implemented using pcap_open_offline for the chosen file

### in each case info for each TCP or UDP packet is printed on termninal
    -> source IP 
    -> destination IP
    -> source Port
    -> destination Port
    -> protocol (TCP/UDP)
    -> (TCP/UDP) Header length 
    -> (TCP/UDP) Payload length
    -> IP version (IPv4 or IPv6)

# In case (ii), when packet capturing of file ends, the program prints the following statistics
    a. Total number of network flows captured​.
    b. Number of TCP network flows captured.
    c. Number of UDP network flows captured.
    d. Total number of packets received (include the packets you skipped, that weren’t TCP or UDP packets.).
    e. Total number of TCP packets received.
    f. Total number of UDP packets received.
    g. Total bytes of TCP packets received.
    h. Total bytes of UDP packets received.
In case(i) this can not happen because the capturing stops by pressing ctrl+c on terminal
(maybe using time.h could work)
