#ifndef __MY_PCAP_H__	// start of my_pcap.h
#define __MY_PCAP_H__

#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>


#define MAC_SIZE 6

#define IP_VERSION(x) ((x & 0xf0) >> 4) // (ip->vhl & 0xf0) >> 4
#define IP_LENGTH(x) ((x & 0x0f) << 2)  // (ip->vhl & 0x0f) << 2
#define TCP_OFFSET(x) ((x & 0xf0) >> 2) // ((tcp->off_res & 0xf0) >> 4) << 2)
#define TCP_RESERVED(x) (x & 0x0f)      // tcp->off_res & 0x0f

/* define struct */
struct ethernet_s
{   
	uint8_t dst_mac[MAC_SIZE];
	uint8_t src_mac[MAC_SIZE];
	uint16_t type;
};

struct ip_s
{   
	uint8_t vhl;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t flag;
	uint8_t ttl;
	uint8_t proto;
	uint16_t checksum;
	struct in_addr src_ip;
	struct in_addr dst_ip;
};

struct tcp_s
{   
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t off_res;
	uint8_t flag;
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_point;
};

struct data_s
{   
	int length;
	u_char *data;
};

typedef struct ethernet_s ethernet_t[1];
typedef struct ip_s ip_t[1];
typedef struct tcp_s tcp_t[1];
typedef struct data_s data_t[1];


// memory copy.
int set_ethernet(ethernet_t _eth, const u_char *_packet);
int set_ip(ip_t _ip, const u_char *_packet, int _offset);
int set_tcp(tcp_t _tcp, const u_char *_packet, int _offset);
int set_data(data_t _data, const u_char *_packet, int _offset, int _data_length);

// parse packet.
int packet_parsing(ethernet_t _eth, ip_t _ip, tcp_t _tcp, data_t _data, const u_char *_packet);

// print packet info.
void print_eth_info(ethernet_t _eth);
void print_ip_info(ip_t _ip);
void print_tcp_info(tcp_t _tcp);
void print_data_info(data_t _data);
void print_packet_info(ethernet_t _eth, ip_t _ip, tcp_t _tcp, data_t _data, int _lev);

// initialize pcap.
void init_pcap(pcap_t **handle, char *_filter_exp, char *_dev);

#endif	// end of my_pcap.h
