#include "log.h"
#include "utils.h"
#include "myhash.h"
#include "tcpip.h"
#include "amqp.h"
#include "http.h"

extern UINT32 trace_level;
extern UINT32 net_byte_swap;

UINT32 eth_num = 0;

hashtable_t* tcp_data_map = 0;

void init_tcp_data() {
    if (tcp_data_map == NULL) {
        tcp_data_map = ht_create(65536);
    }
}

int add_tcp_data(unsigned char* data, int size) {
    init_tcp_data();

    char key[128];
    sprintf(key, "%s:%d->%s:%d", src_ip, src_port, dest_ip, dest_port);

    ht_set(tcp_data_map, key, data, size);

    return 0;
}

unsigned char* get_tcp_data(int* size) {
    if (tcp_data_map == 0) {
        return 0;
    }

    char key[128];
    sprintf(key, "%s:%d->%s:%d", src_ip, src_port, dest_ip, dest_port);

    return ht_get(tcp_data_map, key, size);
}

int del_tcp_data() {
    if (tcp_data_map == 0) {
        return 0;
    }

    char key[128];
    sprintf(key, "%s:%d->%s:%d", src_ip, src_port, dest_ip, dest_port);

    return ht_del(tcp_data_map, key);
}

int parseEthernetII(unsigned char* data, int len, int in_wrap) {
    if (!in_wrap) eth_num++;
    INFO("\nEthernet package: %d\n", eth_num);

    // get ip protocol data
    int type = get_int16(data + 12, net_byte_swap);
    int ret = 0;
    int eth_hdr_len = 14;
    int vlan_hdr_len = 4;
    if (type == VLAN_801_1Q) {
        type = get_int16(data + 16, net_byte_swap);
        if (type == IPV4_PROTOCOL) {
            ret = parseIPv4(data + eth_hdr_len + vlan_hdr_len,
                            len - eth_hdr_len - vlan_hdr_len);
        } else if (type == IPV6_PROTOCOL) {
            ret = parseIPv6(data + eth_hdr_len + vlan_hdr_len,
                            len - eth_hdr_len - vlan_hdr_len);
        } else {
            INFO("Ethernet packet is not IPv4 or IPv6 package, type %d, skip\n", type);
        }
    } else if (type == IPV4_PROTOCOL) {
        ret = parseIPv4(data + eth_hdr_len, len - eth_hdr_len);
    } else if (type == IPV6_PROTOCOL) {
        ret = parseIPv6(data + eth_hdr_len, len - eth_hdr_len);
    } else {
        INFO("Ethernet packet is not IPv4 or IPv6 package, type %d, skip\n", type);
    }

    return ret;
}

int parseIPv4(unsigned char* data, int len) {
    int ret = 0;
    unsigned char* ip_data;
    int ip_len = len;

    ip_data = data;
    dump_hex((unsigned char*)ip_data, ip_len);

    int ip_version = ((*ip_data) & 0xF0) >> 4;
    ip_len = get_int16(ip_data + 2, net_byte_swap);
    create_ipv4_str(src_ip, ip_data + 12);
    create_ipv4_str(dest_ip, ip_data + 16);

    if (ip_version != 4) {
        ERR("Not IPv4 package\n");
        exit(32);
    }
    int protocol = *(ip_data + 9);
    int ip_header_len = ((*ip_data) & 0x0F) * 4;
    if (protocol == UDP_PROTOCOL) {
        int udp_len = ip_len - ip_header_len;
        unsigned char* udp_data = ip_data + ip_header_len;
        ret = parseUDP(udp_data, udp_len);

    } else if (protocol == TCP_PROTOCOL) {
        int tcp_len = ip_len - ip_header_len;
        unsigned char* tcp_data = ip_data + ip_header_len;
        dump_hex((unsigned char*)tcp_data, tcp_len);
        ret = parseTCP(tcp_data, tcp_len);
    } else if (protocol == ICMP_PROTOCOL) {
        INFO("PING from %s to %s\n", src_ip, dest_ip);
        ret = len;
    } else {
        LOG("IP package is not supported type %d\n", protocol);
        return 0;
    }

    return ret;
}

int parseIPv6(unsigned char* data, int data_len) {
    unsigned char* ipv6_data = data;
    int ipv6_len = data_len;

    DEBUG("IPv6 package data:\n");
    dump_hex((unsigned char*)ipv6_data, ipv6_len);

    int ipv6_version = ((*ipv6_data) & 0xF0) >> 4;
    int ipv6_payload_len = get_int16(ipv6_data + 4, net_byte_swap);
    if (ipv6_version != 6) {
        LOG("Only support IP version 6 in IPv6 package, now is %d, skipped\n",
            ipv6_version);
        return 0;
    }

    unsigned int next_header = *(ipv6_data + 6);
    if (next_header != 0x06) {
        INFO("Not TCP package data in IPv6:\n");
        dump_hex((unsigned char*)data, data_len);
        return 0;
    }

    int tcp_len = ipv6_payload_len;
    unsigned char* tcp_data = ipv6_data + 40;
    DEBUG("TCP package data:\n");
    dump_hex((unsigned char*)tcp_data, tcp_len);
    return (parseTCP(tcp_data, tcp_len));

    return 1;
}

int parseTCP(unsigned char* data, int data_len) {
    src_port = get_int16(data, net_byte_swap);
    dest_port = get_int16(data + 2, net_byte_swap);
    unsigned char tcp_flags = *(data + 13);
    int tcp_header_len = ((*(data + 12) >> 4) & 0x0F) * 4;
    int app_data_len = data_len - tcp_header_len;
    unsigned char* app_data = data + tcp_header_len;
    DEBUG("TCP package data\n");
    dump_hex((unsigned char*)app_data, app_data_len);

    if (app_data_len == 0) {
        INFO("TCP Data is empty\n");
        return 0;
    }

    int result = 0;
    int prev_len = 0;
    unsigned char* prev_data = get_tcp_data(&prev_len);
    unsigned char* new_data = NULL;
    if (prev_data != NULL) { // get PDU data in previous TCP package
        INFO("Part of PDU data in previous tcp package\n");
        new_data = malloc(prev_len + app_data_len);
        if (new_data == NULL) {
            LOG("Not enough memory\n");
            exit(33);
        }
        memcpy(new_data, prev_data, prev_len);
        memcpy(new_data + prev_len, app_data, app_data_len);


        app_data_len += prev_len;

        app_data = new_data;

        del_tcp_data();
    }
    switch (pdu_type(app_data)) {
    case PDU_AMQP:
        result = parseAMQP(app_data, app_data_len);
        break;
    case PDU_HTTP:
        result = parseHTTP(app_data, app_data_len);
        break;
    default:
        ERR("Unsupport PDU\n");
        exit(34);
    }

    // some data from previous tcp package
    if (new_data) {
        free(new_data);
    }

    return result;
}

int parseUDP(unsigned char* data, int len) {
    src_port = get_int16(data, net_byte_swap);
    dest_port = get_int16(data + 2, net_byte_swap);
    int udp_len = get_int16(data + 4, net_byte_swap);

    int ret = 0;

    if (src_port == 4789 || dest_port == 4789) { // vxlan
        unsigned char* vxlan = data + 8;
        int vni = get_int24(vxlan+4, net_byte_swap);
        INFO("VXLAN Network ID: %d\n", vni);
        ret = parseEthernetII(data + 16, len - 16, 1);
    } else {
        LOG("Not supported UDP");
    }

    return ret;
}

void create_ipv4_str(unsigned char* buf, unsigned char* ip) {
    sprintf(buf, "%03d.%03d.%03d.%03d", *ip, *(ip + 1), *(ip + 2), *(ip + 3));
}

PDUType pdu_type(unsigned char* p) {
    char buf[256];
    int i = 0;
    while (*p && *p != '\r' && i < 255) {
        buf[i++] = *p++;
    }
    buf[i] = '\0';
    if (strstr(buf, "HTTP/1.1")) {
        return PDU_HTTP;
    }

    return PDU_AMQP;
}
