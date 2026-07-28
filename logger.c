#include "logger.h"

const char* protocol_name(u8 protocol){

	switch(protocol){

		case IPPROTO_TCP:
			return "TCP";
		case IPPROTO_UDP:
			return "UDP";
		case IPPROTO_ICMP:
			return "ICMP";
		default:
			return "UNKNOWN";
	}
}

void logger(struct packet_info *pkt){

	pr_info("SRC-IP -> %pI4 DST-IP -> %pI4 SRC-PORT -> %u DST-PORT -> %u PROTO=%s LEN=%u\n", 
			&pkt->src_ip,
			&pkt->dst_ip,
			pkt->src_port,
			pkt->dst_port,
			protocol_name(pkt->protocol),
			pkt->packet_length);
}
