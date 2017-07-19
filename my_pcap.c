#include "my_pcap.h"


int set_ethernet(ethernet_t _eth, const u_char *_packet)
{
	memcpy(_eth, _packet, sizeof(struct ethernet_s));
	return sizeof(_eth[0]);
}

int set_ip(ip_t _ip, const u_char *_packet, int _offset)
{
	memcpy(_ip, _packet + _offset, sizeof(struct ip_s));
	return IP_LENGTH(_ip->vhl);
}

int set_tcp(tcp_t _tcp, const u_char *_packet, int _offset)
{
	memcpy(_tcp, _packet + _offset, sizeof(struct tcp_s));
	return TCP_OFFSET(_tcp->off_res);
}

int set_data(data_t _data, const u_char *_packet, int _offset, int _data_length)
{
	if(0 == _data_length)
		return 0;

	_data->length = _data_length+1;
	_data->data = (u_char *) calloc (_data->length * sizeof(u_char), sizeof(u_char));
	memcpy(_data->data, _packet + _offset, _data_length);
	return _data_length;
}


int packet_parsing(ethernet_t _eth, ip_t _ip, tcp_t _tcp, data_t _data, const u_char *_packet)
{
	int data_length = 0;
	int offset = 0;

	offset += set_ethernet(_eth, _packet);
	if(ETHERTYPE_IP != ntohs(_eth->type))
		return 1;

	offset += set_ip(_ip, _packet, offset);
	if(IPPROTO_TCP != _ip->proto)
		return 2;

	offset += set_tcp(_tcp, _packet, offset);
	data_length = _ip->len - TCP_OFFSET(_tcp->off_res);
	if(0 == data_length)
		return 3;

	set_data(_data, _packet, offset, data_length);

	return 4;
}


void print_eth_info(ethernet_t _eth)
{
	printf("##### Ethernet Info #####\n");
	printf(">> dst mac : %s\n", ether_ntoa((struct ether_addr *)_eth->dst_mac));
	printf(">> src mac : %s\n", ether_ntoa((struct ether_addr *)_eth->src_mac));
}


void print_ip_info(ip_t _ip)
{
	char buf[20] = {'\0', };
	printf("##### IP Info #####\n");
	inet_ntop(AF_INET, &(_ip->src_ip), buf, sizeof(buf));
	printf(">> src IP : %s\n", buf);
	inet_ntop(AF_INET, &(_ip->dst_ip), buf, sizeof(buf));
	printf(">> dst IP : %s\n", buf);
}

void print_tcp_info(tcp_t _tcp)
{
	printf("##### TCP Info #####\n");
	printf(">> src TCP port: %d\n", ntohs(_tcp->src_port));
	printf(">> src TCP port: %d\n", ntohs(_tcp->dst_port));
}

void print_data_info(data_t _data)
{
	printf("##### data Info #####\n");
	printf("%s\n", _data->data);
}

void print_packet_info(ethernet_t _eth, ip_t _ip, tcp_t _tcp, data_t _data, int _lev)
{
	if(0 >= _lev--)
		return;
	print_eth_info(_eth);

	if(0 >= _lev--)
		return;
	print_ip_info(_ip);

	if(0 >= _lev--)
		return;
	print_tcp_info(_tcp);

	if(0 >= _lev--)
		return;
	print_data_info(_data);
}


void init_pcap(pcap_t **handle, char *_filter_exp, char *_dev)
{
	char *dev = _dev;           /* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
	struct bpf_program fp;      /* The compiled filter */
	bpf_u_int32 mask;       /* Our netmask */
	bpf_u_int32 net;        /* Our IP */

	/*
	// Define the device
	// dev = wlan0
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
	fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
	return(2);
	}
	printf("device is %s\n", dev);
	// Find the properties for the device
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
	fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
	net = 0;
	mask = 0;
	}
	 */
	/* Open the session in promiscuous mode */
	// file open about wlan0
	*handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
//	*handle = pcap_open_live("awdl0", BUFSIZ, 1, 1000, errbuf); // dump
	if (*handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(*handle, &fp, _filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", _filter_exp, pcap_geterr(*handle));
		exit(2);
	}
	if (pcap_setfilter(*handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", _filter_exp, pcap_geterr(*handle));
		exit(2);
	}
}
