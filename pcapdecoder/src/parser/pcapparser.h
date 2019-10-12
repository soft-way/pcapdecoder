#ifndef __PCAP_PARSER_H__
#define __PCAP_PARSER_H__

#define ENDIAN_MAGIC    0x1A2B3C4D

int processPcap(FILE* f);
int processPcapNg(FILE* f);

void processSecHdrBlkOpt(unsigned char* p);
void processIntfDescBlkOpt(unsigned char* p);

unsigned char* opt_type_name(int t);

#endif // __PCAP_PARSER_H__
