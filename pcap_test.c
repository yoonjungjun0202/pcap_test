#include <stdio.h>
#include "my_pcap.h"

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char filter_exp[] = "port 80";	/* The filter expression */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	int re, offset;
	ethernet_t eth;
	ip_t ip;
	tcp_t tcp;
	data_t data;



	if(argc < 2)
	{
		printf("Please, input the network interface\n");
		return 0;
	}


	init_pcap(&handle, filter_exp, argv[1]);
	while( 0 <= (re = pcap_next_ex(handle, &header, &packet)) )
	{
		if( 0 == re )
			continue;

		int lev = packet_parsing(eth, ip, tcp, data, packet);
		print_packet_info(eth, ip, tcp, data, lev);
		if(lev == 4)
			free(data->data);
		printf("\n\n");
	}
	pcap_close(handle);


	return(0);
}
