/*
    pdudecoder.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "log.h"
#include "utils.h"
#include "pcapparser.h"

UINT32 net_byte_swap = 0;

/*
 * main():
 */

int main(int argc, char* argv[]) {
    if (argc < 2) {
        ERR("\tUsage: %s <pcap1> [pcap2] [pcap3] ...\n\n", argv[0]);
        exit(29);
    }

    int arg_idx = 1;
    extern unsigned int trace_level;

    if (memcmp(argv[arg_idx], "-v", 2) == 0) {
        trace_level |= TRACE_INFO;

        if (strlen(argv[arg_idx]) >= 3) {
            trace_level |= TRACE_DEBUG;
        }
        arg_idx++;
    }

    UINT32 my_sys_endianness = get_sys_endianness();
    switch (my_sys_endianness) {
    case ENDIAN_BIG:
        printf("This machine is big-endian.\n\n");
        break;

    case ENDIAN_LITTLE:
        printf("This machine is little-endian.\n\n");
        break;

    case ENDIAN_UNKNOWN: {
        printf("Endianness for this machine could not be determined.\n\n");
        exit(99);
        break;

        default:
            printf("Unexpected endianness value %d (%0x).\n", my_sys_endianness, my_sys_endianness);
            exit(99);
            break;
        }
    }
    if (my_sys_endianness == NETWORK_ORDER) {
        net_byte_swap = 0;
    } else {
        net_byte_swap = 1;
    }

    char* pcap_filename;
    FILE* pcap_handler;

    /*
    pcap-ng capture file
    http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#section_shb
    */
    char pcap_ng_magic_number[4] = { 0x0A, 0x0D, 0x0D, 0x0A };

    // LibpcapFileFormat
    // https://wiki.wireshark.org/Development/LibpcapFileFormat
    char libpcap_magic_number[4] = { 0xD4, 0xC3, 0xB2, 0xA1 };

    UINT32 file_idx = 0;
    while (arg_idx < argc) {
        pcap_filename = argv[arg_idx];
        pcap_handler = fopen(pcap_filename, "rb");
        if (pcap_handler == NULL) {
            ERR("Could not open file %s, err(%d): %s\n", pcap_filename, errno, strerror(errno));
            exit(30);
        }

        LOG("%d. Working on file: %s\n", ++file_idx, pcap_filename);
        UINT32 total_read = 0;
        char* buf[16];
        while (!feof(pcap_handler)) {
            int read_num = fread(buf, 1, FILE_HEAD_PRE_READ, pcap_handler);
            if (read_num < FILE_HEAD_PRE_READ) {
                if (read_num == 0 && feof(pcap_handler))
                    break;

                ERR("Short read, should have read %d bytes, only read %d\n",
                    FILE_HEAD_PRE_READ, read_num);
                exit(31);
            }

            if (memcmp(buf, libpcap_magic_number, 4) == 0) {
                total_read = processPcap(pcap_handler);
            } else if (memcmp(buf, pcap_ng_magic_number, 4) == 0) {
                total_read = processPcapNg(pcap_handler);
            } else {
                LOG("Unsupported file format %s, skipped\n", pcap_filename);
            }
        }

        fclose(pcap_handler);
        LOG("Total read: %d\n", total_read);
        arg_idx++;
    }

    return 0;
}

