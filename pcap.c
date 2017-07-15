#include <pcap.h>
#include <stdio.h>


int print_to_eth(const u_char *_packet, int _offset)
{
	int i;
	const u_char *eth = _packet + _offset;


	printf("dmac: ");
	for(i=5; i>0; i--)
		printf("%02X:", eth[i]);
	printf("%02X\n", eth[i]);

	printf("smac: ");
	for(i=11; i>6; i--)
		printf("%02X:", eth[i]);
	printf("%02X\n", eth[i]);


	return 14;
}

int print_to_ip(const u_char *_packet, int _offset)
{
	int i;
	const u_char *ip = _packet + _offset;


	printf("sip: ");
	for(i=12; i<15; i++)
		printf("%d:", ip[i]);
	printf("%d\n", ip[i]);

	printf("dip: ");
	for(i=16; i<19; i++)
		printf("%d:", ip[i]);
	printf("%d\n", ip[i]);


	return (int)(ip[0] & 0x0f) * 4;
}

int print_to_port(const u_char *_packet, int _offset)
{
	const u_char *port = _packet + _offset;


	printf("sport: %d\n", (((int)port[0] << 8) | (int)port[1]));
	printf("dport: %d\n", (((int)port[2] << 8) | (int)port[3]));


	return (int)((port[12] & 0xf0) >> 4) * 4;
}

int print_to_data(const u_char *_packet, int _offset, int _len)
{
	int i;
	const u_char *data = _packet + _offset;


	printf("## data\n");
	for(i=0; i<_len; i++)
		printf("%02X ", data[i]);
	printf("\n");
	for(i=0; i<_len; i++)
		printf("%c ", data[i]);
	printf("\n");


	return 0;
}

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	
	int re, offset;


	/* Define the device */
	// dev = wlan0
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("device is %s\n", dev);
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	// file open about wlan0
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}



	/* Grab a packet */
	while( 0 <= (re = pcap_next_ex(handle, &header, &packet)) )
	{
		if( 0 == re )
			continue;

		printf("## info\n");
		offset = 0;
		offset += print_to_eth(packet, offset);
		offset += print_to_ip(packet, offset);
		offset += print_to_port(packet, offset);
		offset += print_to_data(packet, offset, 12);

		printf("\n\n");
		/* And close the session */
	}


	pcap_close(handle);
	return(0);
}
