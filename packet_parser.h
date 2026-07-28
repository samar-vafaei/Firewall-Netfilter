
#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

struct packet_info {

       __be32 src_ip;
       __be32 dst_ip;

       u8 protocol;

       __be16 src_port;
       __be16 dst_port;

       u8 tcp_flags;

       u8 icmp_type;
       u8 icmp_code;

       u16 packet_length;
};

bool parse_packet(struct sk_buff *skb, struct packet_info *pkt);

#endif
