#include "packet_parser.h"


bool parse_packet(struct sk_buff *skb, struct packet_info *pkt){

	struct iphdr *iph;
	iph = ip_hdr(skb);

	if(!iph)
		return false;

	pkt->src_ip = iph->saddr;
	pkt->dst_ip = iph->daddr;
	pkt->protocol = iph->protocol;
	pkt->packet_length = ntohs(iph->tot_len);

	switch(iph->protocol){

		case IPPROTO_TCP:

			struct tcphdr *tcph;
			tcph = tcp_hdr(skb);

			pkt->src_port = ntohs(tcph->source);
			pkt->dst_port = ntohs(tcph->dest);

			pkt->tcp_flags = tcph->fin | 
					(tcph->syn << 1) |
					(tcph->rst << 2) |
					(tcph->psh << 3) |
					(tcph->ack << 4) |
					(tcph->urg << 5);
			return true;

		case IPPROTO_UDP:		

			struct udphdr *udph;
			udph = udp_hdr(skb);

			pkt->src_port = ntohs(udph->source);
			pkt->dst_port = ntohs(udph->dest);
			return true;

		case IPPROTO_ICMP:
		
			struct icmphdr *icmph;
			icmph = icmp_hdr(skb);

			pkt->icmp_type = icmph->type;
			pkt->icmp_code = icmph->code;
			return true;

		default:
			return true;
	}

}
