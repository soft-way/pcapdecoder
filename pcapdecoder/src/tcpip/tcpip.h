#ifndef __TCPIP_H__
#define __TCPIP_H__

#define VLAN_801_1Q   0x8100
#define IPV4_PROTOCOL 0x0800
#define IPV6_PROTOCOL 0x86dd
#define TCP_PROTOCOL  0x06
#define UDP_PROTOCOL  0x11
#define ICMP_PROTOCOL 0x01

typedef enum {
    PDU_AMQP,
    PDU_HTTP
} PDUType;

unsigned char src_ip[64];
unsigned char dest_ip[64];
unsigned int src_port;
unsigned int dest_port;

void init_tcp_data();
int add_tcp_data(unsigned char* data, int size);
unsigned char* get_tcp_data(int* size);

int del_tcp_data();

int parseEthernetII(unsigned char* data, int len, int in_wrap);

int parseIPv4(unsigned char* d, int l);
int parseIPv6(unsigned char* d, int l);
int parseTCP(unsigned char* d, int l);
int parseUDP(unsigned char* d, int l);

void create_ipv4_str(unsigned char* buf, unsigned char* ip);
void create_ipv6_str(unsigned char* buf, unsigned char* ip);

PDUType pdu_type(unsigned char* p);

#endif // __TCPIP_H__
