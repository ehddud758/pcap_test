#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

void usage() 
{
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0 \n");
}



int main(int argc, char* argv[]) 
{

	printf("[bob7]pcap_test[김동영]\n");
	printf("===========================================================\n\n");

	// Argument Check
	if (argc != 2) 
	{
    		usage();
    		return -1;
  	}

  	char* dev = argv[1];
  	char errbuf[PCAP_ERRBUF_SIZE];
  	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	struct ip *iph;
	struct tcphdr *tcph;
	struct ether_header *ep;
	unsigned short ether_type;

	int i;

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

		ep = (struct ether_header *)packet;
		// 호스트 바이트 순서를 네트워크 바이트 순서로 변경
		ether_type = ntohs(ep->ether_type);
		
		// Print Source, Destination MAC Address 
		printf("Source MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n", ep->ether_shost[0], ep->ether_shost[1], ep->ether_shost[2], ep->ether_shost[3], ep->ether_shost[4], ep->ether_shost[5]);	
		printf("Destination MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n\n", ep->ether_dhost[0], ep->ether_dhost[1], ep->ether_dhost[2], ep->ether_dhost[3], ep->ether_dhost[4], ep->ether_dhost[5]);	
		
		// Ethernet 헤더 크기만큼 offset을 더함
		packet += sizeof(struct ether_header);

		// IP Packet Check
		if (ether_type == ETHERTYPE_IP)
		{	
			iph = (struct ip *)packet;
			// Print Source, Destination IP
			// 네트워크 바이트 순서의 값을 보기 쉬운 IP 주소 값으로 변환

			printf("Source IP Address : %s \n",inet_ntoa(iph->ip_src));
			printf("Destination IP Address : %s \n\n",inet_ntoa(iph->ip_dst));
			// TCP Segments Check
			if (iph->ip_p == IPPROTO_TCP)
			{
				tcph = (struct tcp*)(packet + iph->ip_hl*4);
				// Print Source, Destination TCP Port
				// short 네트워크 바이트 순서를 호스트 바이트 순서로 변환
				printf("Source Port : %d\n", ntohs(tcph->source));
				printf("Destination Port : %d\n", ntohs(tcph->dest));
				printf("TCP Data : ");
				tcph = (struct tcp*)packet;
				for (i=0; i<16; i++)
				{
					printf("%02x ", tcph++->th_off);
				}
				printf("\n\n");

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
