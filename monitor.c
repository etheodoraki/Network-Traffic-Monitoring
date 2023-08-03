#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include<arpa/inet.h> 
#include<net/ethernet.h>
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header

#define IPv4_TYPE 2048
#define IPv6_TYPE 34525

typedef struct netflow netflow;
struct netflow{
	char sourceIP[INET_ADDRSTRLEN];
	char destIP[INET_ADDRSTRLEN];
	u_int sourcePort ;
	u_int destPort ;
	char * protocol;
};
// list of flows
typedef struct Node Node;
struct Node{
	struct netflow *flow;
	struct Node* next;
};

Node* headFlow = NULL;
int snaplen = BUFSIZ;		//the snapshot length to be set on the handle. 
int promisc = 1;			//If promisc is non-zero, promiscuous mode will be set to the interface
int to_ms = 1000;			//the packet buffer timeout, as a non-negative value, in milliseconds
int totalP = 0;				// num of total packets
int otherP = 0;				// num of packets that aren't TCP nor UDP
int TCPs = 0;				// num of TCP packets
int UDPs = 0;				// num of UDP packets
int TCPs_B = 0;				// bytes of TCP packets
int UDPs_B = 0;				// bytes of UDP packets
int netFlows = 0;			// netflows captured
int netFlows_TCP = 0;		// TCP netflows captured
int netFlows_UDP = 0;		// UDP netflows captured
struct sockaddr_in source,destination;

void availableDevices();
void packetHandler(u_char *,const struct pcap_pkthdr *,const u_char *);
void decodeTCP(const u_char *, int);
void decodeUDP(const u_char *, int);
void addNewFlow(netflow *, Node **);
int compareFlows(netflow *);
void statsOnExit();

void usage(void){
	printf(
		"\n"
		"Usage Options:\n"
		"sudo 	./monitor -i <interface name> :Network interface name (e.g. any, wlp8s0) \n"
		"\t./monitor -r <pcap filename>  :Packet capture filename (e.g. test_pcap_5mins.pcap)\n"
		"\t./monitor -h :Help message\n"
		);
	exit(0);
}

int main(int argc, char *argv[])
{
	int ch, offline;
	char errbuf[PCAP_ERRBUF_SIZE];		// Error buffer for pcap functions
	char *device;
	char *fname;
	pcap_t *handle;

	if(argc < 2) {usage();}
	while ((ch = getopt(argc, argv, "hi:r:")) != -1) {
		switch (ch){		
		case 'i':
			device = optarg;
			break;
		case 'r':
			offline = 1;
			fname = optarg;
			//offline_monitor(optarg,errbuf);
			break;
		case 'h':
			printf("Please select a valid option.\n");
			usage();
		default:
			usage();
		}
	}
	// case of pcap file capturing
	if (offline == 1){
		printf("Opening pcap file '%s' ... ", fname);
		handle = pcap_open_offline(fname,errbuf);
		if (handle == NULL){
			fprintf(stderr, "\npcap_open_offline() failed. %s\n", errbuf);
			exit(1);
		}
		printf("Done.\n");

	 	//running the pcap_loop 
		if (pcap_loop(handle, -1, packetHandler,NULL) <0) {
			fprintf(stderr, "\npcap_loop() failed to process packets: %s\n", pcap_geterr(handle));
			exit(1);
		}
	}
	// case of available network interface monitoring
	else{	
		handle = pcap_open_live(device,snaplen,promisc,to_ms,errbuf);
		if (handle == NULL){
			fprintf(stderr, "\npcap_open_live() failed. %s\n", errbuf);
			availableDevices();
			exit(1);
		}
		printf("Opening device %s ... Done.\n" , device);
		
		//running the pcap_loop 
		if (pcap_loop(handle, -1, packetHandler,NULL) <0) {
			fprintf(stderr, "\npcap_loop() failed to process packets: %s\n", pcap_geterr(handle));
			exit(1);
		}
	}
	printf("\n");
	statsOnExit();
	argc -= optind;
	argv += optind;	
	return 0;
}

/*
	3. Decode each received packet (i.e., is it a TCP or UDP packet?)​.
	4. Skip any packet that is not TCP or UDP.
	5. Print the packet’s source and destination IP addresses.
	6. Print the packet’s source and destination port numbers.
	7. Print the packet’s protocol.
	8. Print the packet’s TCP/UDP header length and TCP/UDP payload length in bytes.
*/
void packetHandler(u_char *args,const struct pcap_pkthdr *packet_header,const u_char *packet_body){
	struct iphdr *ipH = (struct iphdr *) (packet_body +sizeof(struct ethhdr));
	struct ethhdr *eth = (struct ethhdr *)packet_body ;
	int len;
	len = packet_header->len - (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr));
	++totalP;
	switch (ipH->protocol)
	{
	// TCP Protocol
	case IPPROTO_TCP:	 
		decodeTCP(packet_body,len);
		++TCPs;
		break;
	// UDP Protocol
	case IPPROTO_UDP:
		decodeUDP(packet_body,len);
		++UDPs;
		break;
	// Other Protocols
	default:
		++otherP;
		break;
	}
	//printf("TCP: %d UDP: %d Others: %d Total: %d\r", TCPs, UDPs, otherP, totalP);
}

void availableDevices(){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs , *dev;
	if(pcap_findalldevs(&alldevs, errbuf))	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	//Print the available devices
	int count = 1;
	char devs [50] [50];
	printf("\nAvailable Devices are :\n");
	for(dev=alldevs; dev != NULL ; dev=dev->next){
		printf("%d. %s - %s\n" , count , dev->name , dev->description);
		if(dev->name != NULL)
			strcpy(devs[count] , dev->name);

		count++;
	}
}

void decodeTCP(const u_char *packet, int len)
{
	netflow *flow = (netflow *)malloc(sizeof(netflow));
	struct iphdr *ipH = (struct iphdr *) (packet +sizeof(struct ethhdr));
	struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));
	struct ethhdr *eth = (struct ethhdr *)packet ;
    const struct tcphdr* tcpHeader = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
	int rt = 0;
 // for IP source and destination
 	char srcIP[INET_ADDRSTRLEN];
	memset(&source,0,sizeof(source));
	source.sin_addr.s_addr = ipH->saddr;
	strcpy(srcIP,inet_ntoa(source.sin_addr));
	char dstIP[INET_ADDRSTRLEN];
	memset(&destination,0,sizeof(destination));
	destination.sin_addr.s_addr = ipH->daddr;
	strcpy(dstIP,inet_ntoa(destination.sin_addr));
 // for Port source and destination
	u_int srcPort = ntohs(tcpHeader->th_sport);
	u_int dstPort = ntohs(tcpHeader->th_dport);
 // for Protocol
	char *ipv;
	if (ntohs(eth->h_proto) == IPv4_TYPE) {ipv = "IPv4";}
	else if (ntohs(eth->h_proto) == IPv6_TYPE) {ipv = "IPv6";}
 // for Header length
	int headerLen = (unsigned int)(tcpHeader->doff)*4;
	// int headerLen = (ipH->ihl*4) + (tcpHeader->doff)*4 +sizeof(struct ethhdr)
 // for Payload length
 //	int payload = len - headerLen;
	int payload = ntohs(ip->ip_len) - (ip->ip_hl)*4 - headerLen;	// !!
 	//int payload = siz;
 // for retransmitted packet
	char * reTrans;
 	if (rt == 1){ reTrans = "Yes";}
	else {reTrans = "No";}

	memcpy(flow->sourceIP, srcIP, INET_ADDRSTRLEN);
	memcpy(flow->destIP, dstIP, INET_ADDRSTRLEN);
	flow->sourcePort = srcPort;
	flow->destPort;
 	flow->protocol = "TCP";
 // check if flow already exists - compare flow and node
	int flowexists = compareFlows(flow);
	if (!flowexists){
		addNewFlow(flow, &headFlow);
		netFlows++;
		netFlows_TCP++;
	}else{free(flow);}

	TCPs_B += payload;
	printf("_________________________________ TCP Packet _________________________________\n");
	printf("\tSource IP     :\t%s", srcIP);
	printf("\tDestination IP   : %s\n", dstIP);
	printf("\tSource Port   :\t%u", srcPort);
	printf("\t\tDestination Port : %u\n", dstPort);
	printf("\tProtocol      :\tTCP\n");
	printf("\tHeader length :\t%d Bytes\n", headerLen);
	printf("\tPayload       :\t%d Bytes\n", payload);
	printf("\tIP version    :\t%s\n", ipv);
	printf("\tRetransmitted : %s\n", reTrans);

}

void decodeUDP(const u_char *packet, int len)
{
	netflow * flow = (netflow *)malloc(sizeof(netflow));
	struct iphdr *ipH = (struct iphdr *) (packet +sizeof(struct ethhdr));
	struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));
	struct ethhdr *eth = (struct ethhdr *)packet ;
	struct udphdr *udpHeader = (struct udphdr *)(packet + (ipH->ihl*4) + sizeof(udpHeader));
	int rt = 0;
 // for IP source and destination
 	char srcIP[INET_ADDRSTRLEN];
	memset(&source,0,sizeof(source));
	source.sin_addr.s_addr = ipH->saddr;
	strcpy(srcIP,inet_ntoa(source.sin_addr));
	char dstIP[INET_ADDRSTRLEN];
	memset(&destination,0,sizeof(destination));
	destination.sin_addr.s_addr = ipH->daddr;
	strcpy(dstIP,inet_ntoa(destination.sin_addr));
 // for Port source and destination
	u_int srcPort = ntohs(udpHeader->source);
	u_int dstPort = ntohs(udpHeader->dest);
 // for Protocol
 	char *ipv;
	if (ntohs(eth->h_proto) == IPv4_TYPE) {ipv = "IPv4";}
	else if (ntohs(eth->h_proto) == IPv6_TYPE) {ipv = "IPv6";}
 // for Header length
 //	int headerLen = ((unsigned int)(ipH->ihl))*4;		// !  ip header length
	int headerLen = 8; //(fixed)
 // for Payload length
//	int payload = ntohs(ip->ip_len) - (ip->ip_hl)*4 - 8;
	int payload = ntohs(udpHeader->len) - 8;
	//int payload = siz - sizeof(struct ethhdr)- (ip->ip_hl)*4 - 8;
 // for retransmitted packet
	char * reTrans;
 	if (rt == 1){ reTrans = "Yes";}
	else {reTrans = "No";}
	
	memcpy(flow->sourceIP, srcIP, INET_ADDRSTRLEN);
	memcpy(flow->destIP, dstIP, INET_ADDRSTRLEN);
	flow->sourcePort = srcPort;
	flow->destPort;
 	flow->protocol = "UDP";
 // check if flow already exists - compare flow and node
	int flowexists = compareFlows(flow);
	if (!flowexists){
		addNewFlow(flow, &headFlow);
		netFlows++;
		netFlows_UDP++;
	}else{free(flow);}

	UDPs_B += payload;
	printf("_________________________________ UDP Packet _________________________________\n");
	printf("\tSource IP     : %s", srcIP);
	printf("\tDestination IP   : %s\n", dstIP);
	printf("\tSource Port   : %u", srcPort);
	printf("\t\tDestination Port : %u\n", dstPort);
	printf("\tProtocol      : UDP\n");
	printf("\tHeader length : %d Bytes\n", headerLen);
	printf("\tPayload       : %d Bytes\n", payload);
	printf("\tIP version    : %s\n", ipv);
	printf("\tRetransmitted : %s\n", reTrans);
}

void addNewFlow(netflow *flow, Node **headFlow)
{
	Node *newN = (Node *)malloc(sizeof(Node));
	newN->flow = flow;
	newN->next = (*headFlow);
	(*headFlow) = newN;
}

int compareFlows(netflow *flow)
{
	Node* tmpNode = headFlow;
	while (tmpNode != NULL) {
		if (!strcmp(flow->sourceIP,     tmpNode->flow->sourceIP) 
		 && !strcmp(flow->destIP,       tmpNode->flow->destIP) 
		 &&        (flow->sourcePort == tmpNode->flow->sourcePort) 
		 && 	   (flow->destPort   == tmpNode->flow->destPort) 
		 && !strcmp(flow->protocol,     tmpNode->flow->protocol))
		{
			return 1;
		}	
		tmpNode = tmpNode->next;	
	}
	return 0;
}

/*
	a. Total number of network flows captured​ 2​.
	b. Number of TCP network flows captured.
	c. Number of UDP network flows captured.
	d. Total number of packets received (include the packets you skipped).
    e. Total number of TCP packets received.
    f. Total number of UDP packets received.
    g. Total bytes of TCP packets received.
    h. Total bytes of UDP packets received.
*/
void statsOnExit()
{
	printf("Total number of network flows captured: %d\n", netFlows);		//a.
	printf("Number of TCP network flows captured  : %d\n", netFlows_TCP);	//b.
	printf("Number of UDP network flows captured  : %d\n", netFlows_UDP);	//c.
	printf("Total number of packets received      : %d\n", totalP);			//d.
	printf("Total number of TCP packets received  : %d\n", TCPs);			//e.
	printf("Total number of UDP packets received  : %d\n", UDPs);			//f.
	printf("Total bytes of TCP packets received   : %d\n", TCPs_B);			//g.
	printf("Total bytes of UDP packets received   : %d\n", UDPs_B);			//h.
}