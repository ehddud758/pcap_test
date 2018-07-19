#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

void usage() ;

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800

struct sniff_ethernet 
{
	u_char ether_dhost[ETHER_ADDR_LEN];	// Destination MAC Address
	u_char ether_shost[ETHER_ADDR_LEN];	// Source MAC Address
	u_short ether_type;
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

struct sniff_ip 
{
	u_char ip_vhl;
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
	#define IP_RF 0x8000
	#define IP_DF 0x4000
	#define IP_MF 0x2000
	#define IP_OFFMASK 0x1fff
	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	struct in_addr ip_src;	// Source IP Address
	struct in_addr ip_dst;	// Destination IP Address
};

typedef u_int tcp_seq;

struct sniff_tcp
{
	u_short th_sport;	// Source Port
	u_short th_dport;	// Destination Port
	tcp_seq th_seq;
	tcp_seq th_ack;
	u_char th_offx2;
	#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};


int main(int argc, char* argv[]) 
{
  	char* dev = argv[1];
  	char errbuf[PCAP_ERRBUF_SIZE];
  	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	struct sniff_ethernet *ethernet;	// Ethernet header
	struct sniff_ip *iph;		// IP header
	struct sniff_tcp *tcph;		// TCP header
	char *payload;		// payload

	u_int size_ip;
	u_int size_tcp;
	unsigned short ether_type;

	int i, payload_len;

	printf("[bob7]pcap_test[김동영]\n");
	printf("===========================================================\n\n");

	// Argument Check
	if (argc != 2) 
	{
    		usage();
    		return -1;
	}

	// Error Check
  	if (handle == NULL) 
	{
    		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    		return -1;
  	}

  	while (1) 
	{
   		struct pcap_pkthdr* header;
	    	const u_char* packet;
	    	int res = pcap_next_ex(handle, &header, &packet);
    		
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		ethernet = (struct sniff_ethernet *)(packet);

		printf("Source MAC Address : ");
		for (i=0; i<ETHER_ADDR_LEN; i++)
		{
			printf("%02x ", ethernet->ether_shost[i]);
		}
		printf("\nDestination MAC Address : ");
		for (i=0; i<ETHER_ADDR_LEN; i++)
		{
			printf("%02x ", ethernet->ether_dhost[i]);
		}
		printf("\n\n");

		ether_type = ntohs(ethernet->ether_type);

		// IP Packet Check
		if (ether_type == ETHERTYPE_IP)
		{

			iph = (struct sniff_ip *)(packet + SIZE_ETHERNET);
			size_ip = IP_HL(iph) * 4;
			printf("Source IP Address : %s\n", inet_ntoa(iph->ip_src));
			printf("Destination IP Address : %s\n\n", inet_ntoa(iph->ip_dst));

			// TCP Segments Check
			if (iph->ip_p == IPPROTO_TCP)
			{
				tcph = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = TH_OFF(tcph)*4;

				printf("Source Port : %d\n", ntohs(tcph->th_sport));
				printf("Destination Port : %d\n\n", ntohs(tcph->th_dport));
				
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
				payload_len = ntohs(iph->ip_len)-(size_ip + size_tcp);
				if (payload_len == 0)
					printf("No Payload Data\n\n");
				else
				{
					printf("Payload Data : ");
					for (int i=1; i< payload_len; i++)
					{
						printf("%02x ", payload[i-1]);
						if (i%16 == 0)  break;
					}
					printf("\n\n");
				}
			}
			else
			{
				printf("None TCP Segment \n\n");
			}

		}
		else
		{
			printf("None IP Packet \n\n");
		}
		printf("===========================================================\n\n");
	}
  	pcap_close(handle);
  	return 0;

}

void usage() 
{
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0 \n");
}
