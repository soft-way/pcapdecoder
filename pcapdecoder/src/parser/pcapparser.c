
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "log.h"
#include "utils.h"
#include "tcpip.h"
#include "pcapparser.h"

unsigned char if_tsresol = 6;

extern UINT32 trace_level;
extern UINT32 eth_num;
extern UINT32 http_num;
extern UINT32 amqp_num;

int byte_order_swap = 0;

// https://wiki.wireshark.org/Development/LibpcapFileFormat
int processPcap(FILE* f) {
    unsigned char pcap_hdr_s[64];

    // go to file header
    fseek(f, 0, SEEK_SET);

    // reset for each file
    eth_num = 0;
    http_num = 0;
    amqp_num = 0;

    int total_read = 0;
    int read_num = fread(pcap_hdr_s, 1, 24, f);
    if (read_num < 24) {
        ERR("Short read, should have read 24 bytes, only read %d\n", read_num);
        exit(19);
    }
    DEBUG("0x%08x: Global Header\n", total_read);
    total_read += read_num;

    int version_major = get_int16(pcap_hdr_s + 4, byte_order_swap);
    int version_minor = get_int16(pcap_hdr_s + 6, byte_order_swap);
    int thiszone = get_int32(pcap_hdr_s + 8, byte_order_swap);
    unsigned int sigfigs = get_int32(pcap_hdr_s + 12, byte_order_swap);
    unsigned int snaplen = get_int32(pcap_hdr_s + 16, byte_order_swap);
    unsigned int network = get_int32(pcap_hdr_s + 20, byte_order_swap);

    if (network != 1) {
        ERR("Only support IEEE 802.3 Ethernet, current network type %d\n", network);
        exit(20);
    }

    int record_number = 0;
    INFO("Tcpdump capture file version %d.%d\n", version_major, version_minor);
    while (!feof(f)) {
        unsigned char pcaprec_hdr_s[16];
        unsigned int read_num = fread(pcaprec_hdr_s, 1, 16, f);
        if (read_num < 16) {
            if (read_num == 0 && feof(f))
                break;

            ERR("Short read for record header, should have read 16 bytes, only read %d\n", read_num);
            exit(21);
        }
        DEBUG("\n0x%08x: Record Header for record: %d\n", total_read, record_number);
        total_read += read_num;

        unsigned int sec = get_int32(pcaprec_hdr_s, byte_order_swap);
        unsigned int micro_sec = get_int32(pcaprec_hdr_s + 4, byte_order_swap);
        unsigned int incl_len = get_int32(pcaprec_hdr_s + 8, byte_order_swap);
        unsigned int orig_len = get_int32(pcaprec_hdr_s + 12, byte_order_swap);

        create_time_str(sec, micro_sec);

        unsigned char pkg[8192];
        read_num = fread(pkg, 1, incl_len, f);
        if (read_num < incl_len) {
            ERR("Short read, should have read %d bytes, only read %d\n", read_num, incl_len);
            exit(22);
        }
        DEBUG("0x%08x: Record Content for record: %d\n", total_read, record_number);
        total_read += read_num;

        parseEthernetII(pkg, incl_len, 0);
        record_number++;
    }

    LOG("\nTotal ethernet package: %d, http: %d, aqmp: %d\n", eth_num, http_num, amqp_num);

    return total_read;
}

/*
http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#section_shb
*/
int processPcapNg(FILE* f) {
    // go to file header
    fseek(f, 0, SEEK_SET);

    // reset for each file
    eth_num = 0;
    http_num = 0;
    amqp_num = 0;

    int total_read = 0;

    UINT32 block_number = 0;

    while (!feof(f)) {
        unsigned char sec_header_block[8];
        UINT32 read_num = fread(sec_header_block, 1, 8, f);
        if (read_num < 8) {
            if (read_num == 0 && feof(f))
                break;

            ERR("Short read, should have read 8 bytes, only read %d\n", read_num);
            exit(23);
        }

        block_number++;

        // need to calculate block_type based on byte order magic
        UINT32 block_type = get_int32(sec_header_block, byte_order_swap);
        if (block_type == 0x0a0d0d0a) { /* Section Header Block */
            DEBUG("\n0x%08x: Block #%u, Type = Section Header Block (0x%08x)\n", total_read, block_number, block_type);
            // decide endian
            unsigned char sec_byte_order[4];
            UINT32 read_len = fread(sec_byte_order, 1, 4, f);
            if (read_len < 4) {
                ERR("Short read, should have read 4 bytes, only read %d\n", read_num);
                exit(23);
            }
            UINT32 byte_order_magic = get_int32(sec_byte_order, 0);
            if (byte_order_magic == ENDIAN_MAGIC) {
                byte_order_swap = 0;
            } else {
                byte_order_swap = 1;
            }
            read_num += read_len;
        }
        UINT32 block_length = get_int32(sec_header_block + 4, byte_order_swap);

        if (block_type == 0x0a0d0d0a) block_length -= 4; // already read 4 bytes byte order magic

        switch (block_type) {
        case 0x00000001: /* Interface Description Block */
            DEBUG("\n0x%08x: Block #%u, Type = Interface Description Block (0x%08x)\n", total_read, block_number, block_type);
            break;
        case 0x00000002: /* Packet Block */
            DEBUG("\n0x%08x: Block #%u, Type = Packet Block (0x%08x)\n", total_read, block_number, block_type);
            break;
        case 0x00000003: /* Simple Packet Block */
            DEBUG("\n0x%08x: Block #%u, Type = Simple Packet Block (0x%08x)\n", total_read, block_number, block_type);
            break;
        case 0x00000004: /* Name Resolution Block */
            DEBUG("\n0x%08x: Block #%u, Type = Name Resolution Block (0x%08x)\n", total_read, block_number, block_type);
            break;
        case 0x00000005: /* Interface Statistics Block */
            DEBUG("\n0x%08x: Block #%u, Type = Interface Statistics Block (0x%08x)\n", total_read, block_number, block_type);
            break;
        case 0x00000006: /* Enhanced Packet Block */
            DEBUG("\n0x%08x: Block #%u, Type = Enhanced Packet Block (0x%08x)\n", total_read, block_number, block_type);
            break;
        case 0x0a0d0d0a: /* Section Header Block */
            break;
        default:
            if (block_type == 0x0a0a0d0a
                    || (block_type >= 0x0a0d0a00 && block_type <= 0x0a0d0aff)
                    || (block_type >= 0x0d0d0a00 && block_type <= 0x0d0d0aff)) {
                ERR("0x%08x: Corrupted Section header. (0x%08x)\n", total_read, block_type);
                exit(24);
            } else {
                ERR("0x%08x: Unknown Block Type (0x%08x)\n", total_read, block_type);
                exit(25);
            }
        }
        total_read += read_num;

        UINT32 adjusted_block_length = block_length;
        if (block_length % 4 != 0) {
            adjusted_block_length += 4 - block_length % 4;
        }

        DEBUG("0x%08x: Reported Block Length %5u (0x%08x), Adjusted Block Length %5u (0x%08x), next block at offset (0x%08x)\n",
              total_read,
              block_length,
              block_length,
              adjusted_block_length,
              adjusted_block_length,
              total_read + (adjusted_block_length - 4));

        UINT32 next_read_length = adjusted_block_length - 8;
        DEBUG("0x%08x: Remainder of Block Data (0x%08x) bytes\n", next_read_length, next_read_length);

        unsigned char* read_buf = get_buffer(next_read_length);
        read_num = fread(read_buf, 1, next_read_length, f);
        if (read_num < next_read_length) {
            ERR("Short read, should have read %d bytes, only read %d.\n",
                next_read_length, read_num);
            exit(26);
        }
        total_read += read_num;

        if (block_type == 0x00000001) { /* Interface Description Block */
            UINT16 link_type = get_int16(read_buf, byte_order_swap);
            UINT16 reserved = get_int16(read_buf + 2, byte_order_swap);
            UINT32 snapLen = get_int32(read_buf + 4, byte_order_swap);
            processIntfDescBlkOpt(read_buf + 8);
        } else if (block_type == 0x00000006) { /* Enhanced Packet Block */
            UINT32 interface_id = get_int32(read_buf, byte_order_swap);
            UINT32 timestamp_high = get_int32(read_buf + 4, byte_order_swap);
            UINT32 timestamp_low = get_int32(read_buf + 8, byte_order_swap);
            UINT64 timestamp = ((UINT64)timestamp_high << 32) + timestamp_low;

            UINT32 sec = (UINT32)(timestamp / integer_pow(10, if_tsresol));
            UINT32 x_sec = (UINT32)(timestamp - sec * integer_pow(10, if_tsresol));
            UINT32 micro_sec = 0;
            if (if_tsresol >= 6) {
                micro_sec = x_sec / integer_pow(10, if_tsresol - 6);
            } else {
                micro_sec = x_sec * integer_pow(10, 6 - if_tsresol);
            }
            create_time_str(sec, micro_sec);

            UINT32 captured_len = get_int32(read_buf + 12, byte_order_swap);
            UINT32 original_len = get_int32(read_buf + 16, byte_order_swap);

            parseEthernetII(read_buf + 20, captured_len, 0);
        } else if (block_type == 0x0a0d0d0a) { /* Section Header Block */
            UINT16 major_version = get_int16(read_buf, byte_order_swap);
            UINT16 minor_version = get_int16(read_buf + 2, byte_order_swap);
            UINT64 section_length = get_int64(read_buf + 4, byte_order_swap);

            LOG("File format: pcap-ng capture file - version %d.%d\n", major_version, minor_version);
            if (read_num > 16) processSecHdrBlkOpt(read_buf + 12);
        }
    }

    LOG("\nTotal ethernet package: %d, http: %d, aqmp: %d\n", eth_num, http_num, amqp_num);

    return total_read;
}

void processSecHdrBlkOpt(unsigned char* p) {
    unsigned char val[512];

    unsigned char* q = p;
    while (1) {
        UINT32 code = get_int16(q, byte_order_swap);

        if (code == 0) {
            DEBUG("Option End\n");
            return;
        }

        q += 2;
        UINT32 len = get_int16(q, byte_order_swap);

        q += 2;
        memcpy(val, q, len);
        val[len] = 0;
        switch (code) {
        case 2:
            LOG("Hardware: %s\n", val);
            break;

        case 3:
            LOG("Operating system: %s\n", val);
            break;

        case 4:
            LOG("User application: %s\n", val);
            break;

        default:
            ERR("Unknown option code: %d\n", code);
            exit(11);
        }

        UINT32 adj_len = len;
        if (len % 4 != 0) adj_len += 4 - len % 4;

        q += adj_len;
    }
}

void processIntfDescBlkOpt(unsigned char* p) {
    unsigned char val[512];

    unsigned char* q = p;
    while (1) {
        int code = get_int16(q, byte_order_swap);

        if (code == 0) {
            DEBUG("Option End\n");
            return;
        }

        q += 2;
        int len = get_int16(q, byte_order_swap);

        q += 2;
        memcpy(val, q, len);
        val[len] = 0;

        unsigned char* r = val;
        switch (code) {
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
            // erase leading 0
            while (r - val < len) {
                if (*r != 0) break;
                r++;
            }
            LOG("%s: %s\n", opt_type_name(code), r);
            break;

        case 9:
            if_tsresol = val[0];
            LOG("%s: %d\n", opt_type_name(code), val[0]);
            break;

        default:
            ERR("Unknown option code: %d\n", code);
            exit(11);
        }

        UINT32 adj_len = len;
        if (len % 4 != 0) adj_len += 4 - len % 4;

        q += adj_len;
    }
}

/*
Interface Description Block Options
Name	Code	Length	Multiple allowed?
if_name	2	variable	no
if_description	3	variable	no
if_IPv4addr	4	8	yes
if_IPv6addr	5	17	yes
if_MACaddr	6	6	no
if_EUIaddr	7	8	no
if_speed	8	8	no
if_tsresol	9	1	no
if_tzone	10	4	no
if_filter	11	variable, minimum 1	no
if_os	12	variable	no
if_fcslen	13	1	no
if_tsoffset	14	8	no
if_hardware	15	variable	no
*/
unsigned char* opt_type_name(int t) {
    unsigned char* option_tbl[16] = {
        "",
        "",
        "if_name",
        "if_description",
        "if_IPv4addr",
        "if_IPv6addr", // 5
        "if_MACaddr",
        "if_EUIaddr",
        "if_speed",
        "if_tsresol",
        "if_tzone",    // 10
        "if_filter",
        "if_os",
        "if_fcslen",
        "if_tsoffset",
        "if_hardware",
    };

    if (t < 2 || t > 15) {
        ERR("unkown type name");
        exit(28);
    }

    return (option_tbl[t]);
}
